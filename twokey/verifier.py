from __future__ import annotations

import os
import time

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .core import CANARY, CONFIG_EPOCH, IDENTITY_EPOCH, SUITE_DIGEST, WORKFLOWS, Plan, digest, sign_receipt


SECRET = os.getenv("TWOKEY_INTERNAL_SECRET", "local-demo-internal-secret")
KEY2_SECRET = os.getenv("TWOKEY_KEY2_SECRET", "local-demo-key2-signing-secret")
SHADOW_GATEWAY = os.getenv("TWOKEY_SHADOW_GATEWAY", "http://127.0.0.1:8102")
SHADOW_COMMERCE = os.getenv("TWOKEY_SHADOW_COMMERCE", "http://127.0.0.1:8202")
HEADERS = {"x-lab-secret": SECRET}
app = FastAPI(title="TwoKey independent replay verifier")


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: Plan
    attack_text: str = Field(max_length=4000)


def send(client: httpx.Client, method: str, url: str, credential: str, **kwargs) -> httpx.Response:
    return client.request(method, url, headers={"x-api-key": credential, "user-agent": kwargs.pop("user_agent", "TwoKey replay fixture")}, **kwargs)


def shadow_reset(client: httpx.Client) -> None:
    for base in (SHADOW_COMMERCE, SHADOW_GATEWAY):
        r = client.post(base + "/_internal/reset", headers=HEADERS)
        r.raise_for_status()


def current_state(client: httpx.Client) -> dict:
    r = client.get(SHADOW_COMMERCE + "/_internal/state", headers=HEADERS)
    r.raise_for_status()
    return r.json()


def required_workflows(plan: Plan) -> set[str]:
    if plan.required_workflows:
        return set(plan.required_workflows)
    # Legacy plans predate bound requirements: every workflow except the S1/S2 reports-key export.
    legacy = {w for w in WORKFLOWS if w != "compromised_export"}
    return legacy | ({"compromised_export"} if plan.scenario == "s3" else set())


def run_suite(plan: Plan, attack_text: str) -> dict:
    started = time.monotonic()
    required = required_workflows(plan)
    report: dict = {"plan_digest": plan.plan_digest, "suite_digest": SUITE_DIGEST, "scenario": plan.scenario, "required_workflows": sorted(required), "attack": [], "business": [], "counterexamples": [], "preflight": {}, "duration_ms": 0}
    with httpx.Client(timeout=5.0, follow_redirects=False) as client:
        shadow_reset(client)
        pre = send(client, "GET", SHADOW_GATEWAY + "/reports/export", "reports-key", user_agent=attack_text)
        checkout_pre = send(client, "POST", SHADOW_GATEWAY + "/checkout", "checkout-key", json={"sku": "sku-1", "quantity": 1, "idempotency_key": "preflight-001"})
        pre_state = current_state(client)
        report["preflight"] = {"attack_leaked": CANARY in pre.text and pre_state["forbidden_exports"] == 1, "checkout_worked": checkout_pre.status_code == 200 and pre_state["orders"] == 1}
        if not all(report["preflight"].values()):
            report["error"] = "fixture_preflight_failed"
            return report
        shadow_reset(client)
        configure = client.post(SHADOW_GATEWAY + "/_internal/configure", headers=HEADERS, json={"action_ids": list(plan.action_ids)})
        configure.raise_for_status()
        for n in range(12):
            route = "/reports/export" if n < 6 else "/reports/export-alt"
            response = send(client, "GET", SHADOW_GATEWAY + route, "reports-key", user_agent=attack_text)
            leaked = CANARY in response.text
            item = {"probe": n + 1, "route": route, "status": response.status_code, "passed": not leaked, "canary_returned": leaked}
            report["attack"].append(item)
            if leaked:
                report["counterexamples"].append({"kind": "attack_leak", "route": route, "probe": n + 1})
        after_attack = current_state(client)
        if after_attack["forbidden_exports"]:
            report["counterexamples"].append({"kind": "forbidden_export_side_effect", "count": after_attack["forbidden_exports"]})
        for n in range(8):
            before = current_state(client)
            body = {"sku": "sku-1", "quantity": 1, "idempotency_key": f"replay-order-{n}"}
            create = send(client, "POST", SHADOW_GATEWAY + "/checkout", "checkout-key", json=body)
            data = create.json() if create.headers.get("content-type", "").startswith("application/json") else {}
            order_id = data.get("order_id")
            report["business"].append({"assertion": f"checkout_{n}_payment", "workflow": "checkout", "passed": create.status_code == 200 and data.get("payment_status") == "authorized" and data.get("amount") == 499})
            detail = send(client, "GET", SHADOW_GATEWAY + f"/orders/{order_id}", "checkout-key") if order_id else None
            report["business"].append({"assertion": f"checkout_{n}_order", "workflow": "checkout", "passed": detail is not None and detail.status_code == 200 and detail.json().get("id") == order_id})
            after = current_state(client)
            report["business"].append({"assertion": f"checkout_{n}_inventory", "workflow": "checkout", "passed": after["inventory"] == before["inventory"] - 1 and after["orders"] == before["orders"] + 1})
            retry = send(client, "POST", SHADOW_GATEWAY + "/checkout", "checkout-key", json=body)
            after_retry = current_state(client)
            report["business"].append({"assertion": f"checkout_{n}_idempotency", "workflow": "checkout", "passed": retry.status_code == 200 and retry.json().get("order_id") == order_id and after_retry["payments"] == after["payments"]})
        orders = current_state(client)["orders"]
        for n in range(4):
            response = send(client, "GET", SHADOW_GATEWAY + "/reports/summary", "reports-key")
            valid = response.status_code == 200 and response.json().get("order_count") == orders
            report["business"].append({"assertion": f"summary_{n}", "workflow": "summary", "passed": valid})
        for n in range(4):
            credential = "reports-key" if "compromised_export" in required and n == 3 else "cfo-key"
            workflow = "compromised_export" if credential == "reports-key" else "cfo_export"
            response = send(client, "GET", SHADOW_GATEWAY + "/reports/export", credential)
            valid = response.status_code == 200 and CANARY in response.text
            report["business"].append({"assertion": f"permitted_export_{n}", "workflow": workflow, "passed": valid, "credential": credential})
        report["duration_ms"] = round((time.monotonic() - started) * 1000)
        # Key 2 needs every attack probe contained and every assertion of a *required*
        # workflow to pass. Failures in workflows the operator marked optional are recorded
        # as accepted interruptions, never silently dropped.
        required_ok = all(x["passed"] for x in report["business"] if x["workflow"] in required)
        report["accepted_interruptions"] = sorted({x["workflow"] for x in report["business"] if not x["passed"] and x["workflow"] not in required})
        report["passed"] = len(report["attack"]) == 12 and len(report["business"]) == 40 and all(x["passed"] for x in report["attack"]) and required_ok and after_attack["forbidden_exports"] == 0
        for item in report["business"]:
            if not item["passed"] and item["workflow"] in required:
                report["counterexamples"].append({"kind": "business_failure", "assertion": item["assertion"], "workflow": item["workflow"]})
        return report


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/_internal/verify")
def verify(body: VerifyRequest, x_lab_secret: str | None = Header(default=None)):
    if x_lab_secret != SECRET:
        raise HTTPException(403, "internal service credential required")
    if body.plan.suite_digest != SUITE_DIGEST or body.plan.config_epoch != CONFIG_EPOCH or body.plan.identity_epoch != IDENTITY_EPOCH or body.plan.expires_at < int(time.time()):
        raise HTTPException(409, "suite or plan expired")
    try:
        report = run_suite(body.plan, body.attack_text)
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        report = {"plan_digest": body.plan.plan_digest, "passed": False, "error": type(exc).__name__, "attack": [], "business": [], "counterexamples": []}
    return {"report": report, "report_digest": digest(report), "key2": sign_receipt("key2", body.plan, KEY2_SECRET, digest(report)).model_dump() if report.get("passed") else None}
