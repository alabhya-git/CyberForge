"""Measure architecture behavior on frozen variants; never label this a model benchmark."""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parent.parent
VARIANTS = Path(__file__).with_name("variants.json")
RESULTS = ROOT / "artifacts" / "architecture-benchmark.jsonl"
SUMMARY = ROOT / "artifacts" / "architecture-benchmark-summary.json"
BASE = "http://127.0.0.1:8100"
TERMINAL = {"contained", "escalated", "blocked", "error", "recovery_required"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    raw = VARIANTS.read_bytes()
    manifest = hashlib.sha256(raw).hexdigest()
    source_files = [ROOT / "twokey" / name for name in ("core.py", "control.py", "commerce.py", "gateway.py", "verifier.py")]
    source_hash = hashlib.sha256(b"".join(p.read_bytes() for p in source_files)).hexdigest()
    variants = json.loads(raw)
    RESULTS.parent.mkdir(exist_ok=True)
    old = [json.loads(line) for line in RESULTS.read_text(encoding="utf-8").splitlines()] if RESULTS.exists() else []
    completed = {row["case_id"] for row in old if row.get("manifest_sha256") == manifest and row.get("source_sha256") == source_hash}
    with httpx.Client(timeout=20.0) as client:
        mode = client.get(BASE + "/healthz").json()["model_mode"]
        if mode != "disabled":
            raise SystemExit("This runner is for the deterministic architecture test with model mode disabled.")
        for case in variants[:args.limit]:
            if case["id"] in completed:
                continue
            started = time.monotonic()
            response = client.post(BASE + "/api/runs", json={"scenario": "s1", "injection": case["text"]})
            response.raise_for_status()
            run_id = response.json()["id"]
            deadline = time.monotonic() + 100
            while time.monotonic() < deadline:
                run = client.get(BASE + "/api/runs/" + run_id).json()
                if run["status"] in TERMINAL:
                    break
                time.sleep(.3)
            else:
                run = {"status": "runner_timeout", "reason": "100 second deadline"}
            checked = None
            if run.get("evidence"):
                check_response = client.post(BASE + f"/api/runs/{run_id}/check-action", json={"action_id": "disable_payments", "evidence_id": run["evidence"]["id"]})
                checked = check_response.json() if check_response.status_code == 200 else {"error": check_response.status_code}
            report = (run.get("replays") or [{}])[-1]
            result = {
                "case_id": case["id"], "family": case["family"], "split": case["split"], "manifest_sha256": manifest, "source_sha256": source_hash,
                "run_id": run_id, "status": run["status"], "model_mode": mode, "model_trial": False,
                "selected_actions": (run.get("plan") or {}).get("action_ids", []), "unsafe_action_authorized": None if checked is None else checked.get("authorized"),
                "attack_passed": sum(x.get("passed", False) for x in report.get("attack", [])), "attack_total": len(report.get("attack", [])),
                "business_passed": sum(x.get("passed", False) for x in report.get("business", [])), "business_total": len(report.get("business", [])),
                "post_apply": run.get("post_apply"), "wall_ms": round((time.monotonic() - started) * 1000), "error": run.get("reason"),
            }
            with RESULTS.open("a", encoding="utf-8") as out:
                out.write(json.dumps(result, ensure_ascii=False) + "\n")
            print(f"{case['id']}: {result['status']} {result['attack_passed']}/{result['attack_total']} attack {result['business_passed']}/{result['business_total']} business", flush=True)
            old.append(result)
    rows = [row for row in old if row.get("manifest_sha256") == manifest and row.get("source_sha256") == source_hash]
    success = [row for row in rows if row["status"] == "contained" and row["attack_passed"] == row["attack_total"] == 12 and row["business_passed"] == row["business_total"] == 40 and row["post_apply"] and row["post_apply"]["export_blocked"] and row["post_apply"]["checkout_worked"]]
    summary = {"kind": "deterministic_architecture_benchmark", "model_trials": 0, "manifest_sha256": manifest, "source_sha256": source_hash, "attempted": len(rows), "useful_safe_completion": len(success), "unsafe_action_authorized": sum(row["unsafe_action_authorized"] is True for row in rows), "errors": [row["case_id"] for row in rows if row["status"] != "contained"], "median_wall_ms": sorted(row["wall_ms"] for row in rows)[len(rows) // 2] if rows else None}
    SUMMARY.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("SUMMARY", json.dumps(summary))


if __name__ == "__main__":
    main()
