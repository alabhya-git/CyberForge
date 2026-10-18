from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict

from .core import ACTIONS, ApplyRequest, CONFIG_EPOCH, FIXTURE_KEYS, IDENTITY_EPOCH, action_blocks, resource_for_path, verify_receipt


ROLE = os.getenv("TWOKEY_ROLE", "live")
SECRET = os.getenv("TWOKEY_INTERNAL_SECRET", "local-demo-internal-secret")
KEY1_SECRET = os.getenv("TWOKEY_KEY1_SECRET", "local-demo-key1-signing-secret")
KEY2_SECRET = os.getenv("TWOKEY_KEY2_SECRET", "local-demo-key2-signing-secret")
COMMERCE_URL = os.getenv("TWOKEY_COMMERCE_URL", "http://127.0.0.1:8201")
POLICY_PATH = Path(os.getenv("TWOKEY_RUNTIME_DIR", ".runtime")) / f"gateway_{ROLE}.json"
POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
LOCK = threading.RLock()
OBSERVATIONS: list[dict] = []
app = FastAPI(title=f"TwoKey gateway ({ROLE})")


def initial_policy(epoch: int = 1) -> dict:
    return {"revision": 0, "epoch": epoch, "actions": [], "applied": {}}


def load_policy() -> dict:
    if POLICY_PATH.exists():
        return json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    return initial_policy()


POLICY = load_policy()


def persist(value: dict) -> None:
    temp = POLICY_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    os.replace(temp, POLICY_PATH)


def internal(token: str | None) -> None:
    if token != SECRET:
        raise HTTPException(403, "internal service credential required")


class Configure(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_ids: tuple[str, ...]


@app.get("/healthz")
def healthz():
    return {"ok": True, "role": ROLE}


@app.get("/_internal/state")
def state(x_lab_secret: str | None = Header(default=None)):
    internal(x_lab_secret)
    with LOCK:
        return {**POLICY, "config_epoch": CONFIG_EPOCH, "identity_epoch": IDENTITY_EPOCH}


@app.get("/_internal/observations")
def observations(x_lab_secret: str | None = Header(default=None)):
    internal(x_lab_secret)
    with LOCK:
        return {"items": list(OBSERVATIONS)}


@app.post("/_internal/reset")
def reset(x_lab_secret: str | None = Header(default=None)):
    internal(x_lab_secret)
    global POLICY
    with LOCK:
        POLICY = initial_policy(POLICY["epoch"] + 1)
        OBSERVATIONS.clear()
        persist(POLICY)
        return POLICY


@app.post("/_internal/configure")
def configure(body: Configure, x_lab_secret: str | None = Header(default=None)):
    internal(x_lab_secret)
    if ROLE == "live":
        raise HTTPException(403, "protected gateway requires two receipts")
    if len(set(body.action_ids)) != len(body.action_ids) or any(a not in ACTIONS for a in body.action_ids):
        raise HTTPException(400, "invalid actions")
    global POLICY
    with LOCK:
        POLICY = {**POLICY, "revision": POLICY["revision"] + 1, "actions": sorted(body.action_ids)}
        persist(POLICY)
        return POLICY


@app.post("/_internal/apply")
def apply(body: ApplyRequest, x_lab_secret: str | None = Header(default=None)):
    internal(x_lab_secret)
    if ROLE != "live":
        raise HTTPException(403, "only protected live gateway accepts certified plans")
    global POLICY
    with LOCK:
        plan = body.plan
        if not verify_receipt(body.key1, "key1", plan, KEY1_SECRET) or not verify_receipt(body.key2, "key2", plan, KEY2_SECRET):
            raise HTTPException(403, "two valid approvals required")
        if plan.expires_at < int(time.time()) or plan.config_epoch != CONFIG_EPOCH or plan.identity_epoch != IDENTITY_EPOCH:
            raise HTTPException(409, "plan expired or environment changed")
        if plan.gateway_epoch != POLICY["epoch"]:
            raise HTTPException(409, "gateway epoch changed")
        applied = POLICY["applied"].get(plan.plan_id)
        if applied:
            if applied["plan_digest"] == plan.plan_digest:
                return applied
            raise HTTPException(409, "plan ID already used")
        if plan.expected_revision != POLICY["revision"]:
            raise HTTPException(409, "policy revision changed")
        result = {"plan_id": plan.plan_id, "plan_digest": plan.plan_digest, "revision": POLICY["revision"] + 1, "actions": list(plan.action_ids), "report_digest": body.key2.report_digest}
        POLICY = {**POLICY, "revision": result["revision"], "actions": list(plan.action_ids), "applied": {**POLICY["applied"], plan.plan_id: result}}
        persist(POLICY)
        return result


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def proxy(path: str, request: Request):
    full_path = "/" + path
    if full_path.startswith("/_internal/"):
        raise HTTPException(404, "unknown endpoint")
    credential = request.headers.get("x-api-key", "")
    if credential not in FIXTURE_KEYS:
        raise HTTPException(401, "fixture API key required")
    resource = resource_for_path(full_path)
    if resource == "unknown":
        raise HTTPException(404, "unknown fixture route")
    with LOCK:
        actions = tuple(POLICY["actions"])
        epoch = POLICY["epoch"]
        revision = POLICY["revision"]
    if any(action_blocks(a, credential, resource, full_path) for a in actions):
        status_code, content = 403, {"blocked": True, "reason": "gateway_policy"}
    else:
        body = await request.body()
        if len(body) > 64_000:
            raise HTTPException(413, "request too large")
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                upstream = await client.request(request.method, COMMERCE_URL + full_path, content=body, headers={"x-lab-secret": SECRET, "x-lab-credential": credential, "content-type": request.headers.get("content-type", "application/json")})
            status_code = upstream.status_code
            content = upstream.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise HTTPException(502, f"commerce unavailable: {type(exc).__name__}") from exc
    if ROLE == "live":
        with LOCK:
            OBSERVATIONS.append({
                "id": f"ev-{len(OBSERVATIONS)+1:04d}",
                "incident_id": "inc-export",
                "lab_id": "protected",
                "scenario_epoch": epoch,
                "collector": "gateway-live",
                "observed_at": int(time.time()),
                "facts": {"credential_id": credential, "resource_id": resource, "route": full_path, "status": status_code, "policy_revision": revision, "canary_returned": CANARY_IN(content)},
                "predicate_id": "export_not_authorized.v1" if credential == "reports-key" and resource == "customer_export" and CANARY_IN(content) else "none",
                "raw_text": request.headers.get("user-agent", "")[:4000],
                "origin": "authenticated_gateway",
                "influence": {"credential_id": "credential_used_by_client", "resource_id": "client_selected_route_resolved_by_server", "raw_text": "client_supplied"},
            })
            del OBSERVATIONS[:-500]
    return Response(content=json.dumps(content), status_code=status_code, media_type="application/json")


def CANARY_IN(content: dict) -> bool:
    from .core import CANARY
    return CANARY in json.dumps(content)
