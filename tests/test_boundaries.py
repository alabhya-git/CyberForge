import time
from itertools import combinations

from twokey.core import ACTIONS, CATALOG_ORDER, CONFIG_EPOCH, WORKFLOWS, Plan, Receipt, authorize_action, interruption_inr, sign_receipt, solve_plan, verify_receipt


EVIDENCE = {
    "id": "ev-0001",
    "incident_id": "inc-export",
    "lab_id": "protected",
    "origin": "authenticated_gateway",
    "observed_at": int(time.time()),
    "scenario_epoch": 1,
    "predicate_id": "export_not_authorized.v1",
    "facts": {"credential_id": "reports-key", "resource_id": "customer_export"},
}


def test_evidence_authorizes_scope_not_attacker_named_target():
    assert authorize_action("deny_report_key_export", EVIDENCE)[0]
    assert authorize_action("disable_payments", EVIDENCE) == (False, "target_not_supported_by_reports_evidence")
    assert not authorize_action("deny_report_key_export", {**EVIDENCE, "origin": "client_supplied"})[0]
    assert not authorize_action("deny_report_key_export", {**EVIDENCE, "incident_id": "other"})[0]
    assert not authorize_action("deny_report_key_export", {**EVIDENCE, "facts": {"credential_id": "cfo-key", "resource_id": "customer_export"}})[0]
    assert not authorize_action("deny_report_key_export", {**EVIDENCE, "observed_at": int(time.time()) - 300})[0]
    assert not authorize_action("deny_report_key_export", EVIDENCE, expected_epoch=2)[0]


def test_planner_can_contain_and_preserve_business_and_explain_conflict():
    ids = ["deny_report_key_path", "deny_report_key_export", "revoke_report_key", "deny_export_globally", "disable_reports", "disable_storefront"]
    required = {"checkout", "summary", "cfo_export"}
    assert solve_plan(ids, {"primary", "alias"}, required)["actions"] == ("deny_report_key_export",)
    assert solve_plan(ids, {"primary"}, required)["actions"] == ("deny_report_key_path",)
    assert solve_plan(ids, {"primary"}, required | {"compromised_export"})["status"] == "unsat"


def test_both_receipts_bind_the_complete_plan():
    plan = Plan(plan_id="p1", incident_id="inc-export", scenario="s1", action_ids=("deny_report_key_export",), evidence_digest="a" * 64, expected_revision=0, gateway_epoch=1, config_epoch=CONFIG_EPOCH, identity_epoch="fixture-keys-v1", suite_digest="commerce-suite-v1-12x40", expires_at=int(time.time()) + 120)
    k1 = sign_receipt("key1", plan, "secret-one")
    k2 = sign_receipt("key2", plan, "secret-two", "b" * 64)
    assert verify_receipt(k1, "key1", plan, "secret-one")
    assert verify_receipt(k2, "key2", plan, "secret-two")
    modified = plan.model_copy(update={"action_ids": ("deny_report_key_path",)})
    assert not verify_receipt(k1, "key1", modified, "secret-one")
    assert not verify_receipt(k2, "key2", modified, "secret-two")
    assert not verify_receipt(k1, "key2", plan, "secret-two")
    assert not verify_receipt(Receipt(**{**k1.model_dump(), "signature": "0" * 64}), "key1", plan, "secret-one")


def test_solver_matches_independent_subset_oracle():
    ids = list(CATALOG_ORDER)
    cost_profiles = [
        {w.id: w.default_inr_per_hour for w in WORKFLOWS.values()},
        {"checkout": 30000, "summary": 9000, "cfo_export": 100, "compromised_export": 0},
        {"checkout": 0, "summary": 0, "cfo_export": 0, "compromised_export": 0},
    ]
    for traces in ({"primary"}, {"primary", "alias"}):
        for required in ({"checkout"}, {"checkout", "summary"}, {"checkout", "summary", "cfo_export"}, {"checkout", "summary", "cfo_export", "compromised_export"}):
            for costs in cost_profiles:
                candidates = []
                for size in range(1, len(ids) + 1):
                    for combo in combinations(ids, size):
                        if all(any(t in ACTIONS[a].modeled_attacks for a in combo) for t in traces) and all(not (ACTIONS[a].breaks & required) for a in combo):
                            candidates.append(combo)
                solved = solve_plan(ids, traces, required, costs=costs)
                if not candidates:
                    assert solved["status"] == "unsat"
                    continue
                assert solved["status"] == "sat"
                # Lexicographic: rupee interruption (per workflow, no double counting), then
                # disruption, blast radius and action count.
                key = lambda combo: (interruption_inr(combo, required, costs), sum(ACTIONS[a].disruption for a in combo), sum(ACTIONS[a].blast_radius for a in combo), len(combo))
                expected = min(key(combo) for combo in candidates)
                assert key(solved["actions"]) == expected
                assert solved["estimated_inr_per_hour"] == expected[0]
