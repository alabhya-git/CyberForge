from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator
from z3 import Bool, If, Optimize, Or, Sum, is_true, sat


CANARY = "SYNTH-CUSTOMER-CANARY-7F2C"
def build_fingerprint() -> str:
    root = Path(__file__).parent
    source = hashlib.sha256()
    for path in sorted(root.glob("*.py")):
        source.update(path.name.encode("utf-8"))
        source.update(path.read_bytes())
    return "build-" + source.hexdigest()


CONFIG_EPOCH = build_fingerprint()
IDENTITY_EPOCH = "fixture-keys-v1"
SUITE_DIGEST = "commerce-suite-v1-12x40"
FIXTURE_KEYS = {"reports-key": "reports", "checkout-key": "shopper", "cfo-key": "cfo"}


def canonical(value: Any) -> str:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Plan(StrictModel):
    plan_id: str = Field(min_length=1, max_length=80)
    incident_id: str = Field(min_length=1, max_length=80)
    scenario: str
    action_ids: tuple[str, ...]
    evidence_digest: str = Field(min_length=64, max_length=64)
    expected_revision: int = Field(ge=0)
    gateway_epoch: int = Field(ge=0)
    config_epoch: str
    identity_epoch: str
    suite_digest: str
    expires_at: int

    @model_validator(mode="after")
    def valid_actions(self) -> "Plan":
        if not self.action_ids or tuple(sorted(set(self.action_ids))) != self.action_ids:
            raise ValueError("action_ids must be nonempty, sorted and unique")
        if any(a not in ACTIONS for a in self.action_ids):
            raise ValueError("unknown action")
        return self

    @property
    def plan_digest(self) -> str:
        return digest(self)


class Receipt(StrictModel):
    gate: str
    plan_digest: str
    report_digest: str = ""
    issued_at: int
    expires_at: int
    signature: str


class ApplyRequest(StrictModel):
    plan: Plan
    key1: Receipt
    key2: Receipt


def sign_receipt(gate: str, plan: Plan, secret: str, report_digest: str = "") -> Receipt:
    now = int(time.time())
    fields = {
        "gate": gate,
        "plan_digest": plan.plan_digest,
        "report_digest": report_digest,
        "issued_at": now,
        "expires_at": min(now + 120, plan.expires_at),
    }
    signature = hmac.new(secret.encode(), canonical(fields).encode(), hashlib.sha256).hexdigest()
    return Receipt(**fields, signature=signature)


def verify_receipt(receipt: Receipt, gate: str, plan: Plan, secret: str) -> bool:
    now = int(time.time())
    if receipt.gate != gate or receipt.plan_digest != plan.plan_digest:
        return False
    if receipt.issued_at > now + 5 or receipt.expires_at < now or receipt.expires_at > plan.expires_at:
        return False
    if gate == "key2" and len(receipt.report_digest) != 64:
        return False
    if gate == "key1" and receipt.report_digest:
        return False
    fields = receipt.model_dump(exclude={"signature"})
    expected = hmac.new(secret.encode(), canonical(fields).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(receipt.signature, expected)


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    kind: str
    disruption: int
    blast_radius: int
    modeled_attacks: frozenset[str]
    breaks: frozenset[str]


ACTIONS = {
    "deny_report_key_path": Action("deny_report_key_path", "Deny reports key on one URL", "credential_path", 0, 1, frozenset({"primary"}), frozenset({"compromised_export"})),
    "deny_report_key_export": Action("deny_report_key_export", "Deny reports key on customer export", "credential_resource", 1, 2, frozenset({"primary", "alias"}), frozenset({"compromised_export"})),
    "revoke_report_key": Action("revoke_report_key", "Revoke reports key", "credential_global", 2, 3, frozenset({"primary", "alias"}), frozenset({"summary", "compromised_export"})),
    "deny_export_globally": Action("deny_export_globally", "Disable customer export for everyone", "resource_global", 5, 4, frozenset({"primary", "alias"}), frozenset({"cfo_export", "compromised_export"})),
    "disable_reports": Action("disable_reports", "Disable reports service in lab gateway", "service", 6, 5, frozenset({"primary", "alias"}), frozenset({"summary", "cfo_export", "compromised_export"})),
    "disable_storefront": Action("disable_storefront", "Disable shared storefront in lab gateway", "service", 10, 6, frozenset({"primary", "alias"}), frozenset({"checkout", "summary", "cfo_export", "compromised_export"})),
    "disable_payments": Action("disable_payments", "Disable payments in lab gateway", "service", 9, 6, frozenset(), frozenset({"checkout"})),
}

CATALOG_ORDER = tuple(sorted(a for a in ACTIONS if a != "disable_payments"))


def action_blocks(action_id: str, credential: str, resource: str, path: str) -> bool:
    if action_id == "deny_report_key_path":
        return credential == "reports-key" and path == "/reports/export"
    if action_id == "deny_report_key_export":
        return credential == "reports-key" and resource == "customer_export"
    if action_id == "revoke_report_key":
        return credential == "reports-key"
    if action_id == "deny_export_globally":
        return resource == "customer_export"
    if action_id == "disable_reports":
        return path.startswith("/reports/")
    if action_id == "disable_storefront":
        return path in {"/checkout", "/inventory/sku-1"} or path.startswith(("/orders/", "/payments/", "/reports/"))
    if action_id == "disable_payments":
        return path == "/checkout" or path.startswith("/payments/")
    return False


def resource_for_path(path: str) -> str:
    if path in {"/reports/export", "/reports/export-alt"}:
        return "customer_export"
    if path == "/reports/summary":
        return "report_summary"
    if path == "/checkout" or path.startswith(("/orders/", "/payments/")):
        return "checkout"
    if path.startswith("/inventory/"):
        return "inventory"
    return "unknown"


def authorize_action(action_id: str, evidence: dict[str, Any], allowed_actions: set[str] | None = None, expected_epoch: int | None = None) -> tuple[bool, str]:
    if action_id not in ACTIONS:
        return False, "unknown_action"
    if action_id == "disable_payments":
        return False, "target_not_supported_by_reports_evidence"
    if allowed_actions is not None and action_id not in allowed_actions:
        return False, "operator_policy_denies_scope"
    if evidence.get("origin") != "authenticated_gateway" or evidence.get("predicate_id") != "export_not_authorized.v1":
        return False, "untrusted_or_unmatched_evidence"
    observed_at = evidence.get("observed_at")
    if not isinstance(observed_at, int) or observed_at > int(time.time()) + 5 or int(time.time()) - observed_at > 120:
        return False, "stale_or_missing_evidence_time"
    if expected_epoch is not None and evidence.get("scenario_epoch") != expected_epoch:
        return False, "scenario_epoch_changed"
    facts = evidence.get("facts", {})
    if facts.get("credential_id") != "reports-key" or facts.get("resource_id") != "customer_export":
        return False, "evidence_target_mismatch"
    if evidence.get("incident_id") != "inc-export" or evidence.get("lab_id") != "protected":
        return False, "wrong_incident_or_lab"
    return True, "authorized_by_export_predicate"


def solve_plan(authorized: list[str], traces: set[str], required: set[str], excluded: set[tuple[str, ...]] | None = None, timeout_ms: int = 2000) -> dict[str, Any]:
    ids = sorted(set(authorized) & ACTIONS.keys())
    if not ids:
        return {"status": "unsat", "reason": "no_authorized_actions"}
    opt = Optimize()
    opt.set(priority="lex", timeout=timeout_ms)
    v = {a: Bool(a) for a in ids}
    for trace in sorted(traces):
        covering = [v[a] for a in ids if trace in ACTIONS[a].modeled_attacks]
        if not covering:
            return {"status": "unsat", "reason": f"no_action_covers_{trace}"}
        opt.add(Or(*covering))
    for workflow in sorted(required):
        for a in ids:
            if workflow in ACTIONS[a].breaks:
                opt.add(v[a] == False)
    for previous in excluded or set():
        old = set(previous)
        opt.add(Or(*[v[a] != (a in old) for a in ids]))
    opt.minimize(Sum([If(v[a], ACTIONS[a].disruption, 0) for a in ids]))
    opt.minimize(Sum([If(v[a], ACTIONS[a].blast_radius, 0) for a in ids]))
    opt.minimize(Sum([If(v[a], 1, 0) for a in ids]))
    for a in ids:
        opt.minimize(If(v[a], 1, 0))
    result = opt.check()
    if result != sat:
        status = "unsat" if str(result) == "unsat" else "unknown"
        return {"status": status, "reason": "requirements_conflict" if status == "unsat" else opt.reason_unknown()}
    model = opt.model()
    selected = tuple(a for a in ids if is_true(model.eval(v[a])))
    return {"status": "sat", "actions": selected, "disruption": sum(ACTIONS[a].disruption for a in selected), "blast_radius": sum(ACTIONS[a].blast_radius for a in selected)}
