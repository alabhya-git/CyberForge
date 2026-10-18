"""Verify the binding and measured results in a downloaded TwoKey run bundle."""
from __future__ import annotations

import json
import os
import sys
import hashlib
import hmac
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from twokey.core import Plan, Receipt, canonical, digest


def historical_receipt_valid(receipt: Receipt, gate: str, plan: Plan, secret: str) -> bool:
    """Audit an expired receipt's original signature; never use for live execution."""
    if receipt.gate != gate or receipt.plan_digest != plan.plan_digest:
        return False
    if receipt.issued_at > receipt.expires_at or receipt.expires_at > plan.expires_at:
        return False
    if gate == "key2" and len(receipt.report_digest) != 64:
        return False
    if gate == "key1" and receipt.report_digest:
        return False
    expected = hmac.new(secret.encode(), canonical(receipt.model_dump(exclude={"signature"})).encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(receipt.signature, expected)


def verify(path: Path) -> list[str]:
    run = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if run.get("status") != "contained":
        errors.append("run does not report contained state")
    try:
        plan = Plan.model_validate(run["plan"])
        key1 = Receipt.model_validate(run["key1"])
        key2 = Receipt.model_validate(run["key2"])
        report = run["replays"][-1]
        if digest(run["evidence"]) != plan.evidence_digest:
            errors.append("evidence digest mismatch")
        if report.get("plan_digest") != plan.plan_digest or key2.report_digest != digest(report):
            errors.append("replay report is not bound to the plan")
        if run["apply_result"].get("plan_digest") != plan.plan_digest:
            errors.append("applied policy digest mismatch")
        if not historical_receipt_valid(key1, "key1", plan, os.getenv("TWOKEY_KEY1_SECRET", "local-demo-key1-signing-secret")):
            errors.append("Key 1 historical signature invalid")
        if not historical_receipt_valid(key2, "key2", plan, os.getenv("TWOKEY_KEY2_SECRET", "local-demo-key2-signing-secret")):
            errors.append("Key 2 historical signature invalid")
        if len(report.get("attack", [])) != 12 or not all(x.get("passed") for x in report["attack"]):
            errors.append("attack replay did not fully pass")
        if len(report.get("business", [])) != 40 or not all(x.get("passed") for x in report["business"]):
            errors.append("business replay did not fully pass")
        post = run.get("post_apply") or {}
        if not post.get("export_blocked") or not post.get("checkout_worked"):
            errors.append("post-apply live checks did not both pass")
    except (KeyError, ValueError, TypeError, IndexError) as exc:
        errors.append(f"missing or malformed bundle: {type(exc).__name__}")
    return errors


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/verify_bundle.py <downloaded-run.json>")
    failures = verify(Path(sys.argv[1]))
    if failures:
        for failure in failures:
            print("FAIL", failure)
        raise SystemExit(1)
    print("PASS: receipts, evidence, replay and applied plan are bound; all recorded assertions passed")
