import importlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from twokey.core import (
    ACTIONS, CATALOG_ORDER, CONFIG_EPOCH, IDENTITY_EPOCH, SUITE_DIGEST, Plan, authorize_action, build_requirements,
    compare_actions, default_requirements, digest, explain_conflict, interruption_inr, sign_receipt,
)


def make_plan(plan_id="p1", actions=("deny_report_key_export",), revision=0, epoch=1, expires_in=120, required=("cfo_export", "checkout", "summary")):
    return Plan(plan_id=plan_id, incident_id="inc-export", scenario="s1", action_ids=actions, evidence_digest="a" * 64, expected_revision=revision, gateway_epoch=epoch, config_epoch=CONFIG_EPOCH, identity_epoch=IDENTITY_EPOCH, suite_digest=SUITE_DIGEST, expires_at=int(time.time()) + expires_in, required_workflows=required)


def bundle(plan, key1_plan=None, key2_plan=None, key1_secret="test-key1", key2_secret="test-key2"):
    return {
        "plan": plan.model_dump(),
        "key1": sign_receipt("key1", key1_plan or plan, key1_secret).model_dump(),
        "key2": sign_receipt("key2", key2_plan or plan, key2_secret, "c" * 64).model_dump(),
    }


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("TWOKEY_ROLE", "live")
    monkeypatch.setenv("TWOKEY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("TWOKEY_INTERNAL_SECRET", "test-internal")
    monkeypatch.setenv("TWOKEY_KEY1_SECRET", "test-key1")
    monkeypatch.setenv("TWOKEY_KEY2_SECRET", "test-key2")
    import twokey.gateway as module
    module = importlib.reload(module)
    return module, TestClient(module.app)


HEADERS = {"x-lab-secret": "test-internal"}


def test_executor_requires_two_receipts_bound_to_the_exact_plan(gateway):
    _, client = gateway
    plan = make_plan()
    other = make_plan(plan_id="p2", actions=("revoke_report_key",))
    assert client.post("/_internal/apply", json=bundle(plan)).status_code == 403  # no internal credential
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(plan, key2_secret="test-key1")).status_code == 403  # key 2 forged with key 1's secret
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(plan, key1_plan=other)).status_code == 403  # key 1 from another plan
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(plan, key2_plan=other)).status_code == 403  # key 2 from another plan
    swapped = bundle(plan)
    swapped["key1"], swapped["key2"] = swapped["key2"], swapped["key1"]
    assert client.post("/_internal/apply", headers=HEADERS, json=swapped).status_code == 403
    tampered = bundle(plan)
    tampered["plan"]["action_ids"] = ["disable_storefront"]
    assert client.post("/_internal/apply", headers=HEADERS, json=tampered).status_code == 403
    changed_requirements = bundle(plan)
    changed_requirements["plan"]["required_workflows"] = ["checkout"]
    assert client.post("/_internal/apply", headers=HEADERS, json=changed_requirements).status_code == 403
    state = client.get("/_internal/state", headers=HEADERS).json()
    assert state["revision"] == 0 and state["actions"] == []


def test_executor_is_idempotent_and_rejects_stale_or_conflicting_plans(gateway):
    module, client = gateway
    plan = make_plan()
    first = client.post("/_internal/apply", headers=HEADERS, json=bundle(plan))
    assert first.status_code == 200 and first.json()["revision"] == 1
    retry = client.post("/_internal/apply", headers=HEADERS, json=bundle(plan))
    assert retry.status_code == 200 and retry.json() == first.json()
    reused_id = make_plan(actions=("deny_report_key_path",), revision=1)
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(reused_id)).status_code == 409
    stale = make_plan(plan_id="p3", revision=0)
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(stale)).status_code == 409
    wrong_epoch = make_plan(plan_id="p4", revision=1, epoch=2)
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(wrong_epoch)).status_code == 409
    expired = make_plan(plan_id="p5", revision=1, expires_in=-5)
    assert client.post("/_internal/apply", headers=HEADERS, json=bundle(expired)).status_code == 403
    assert client.post("/_internal/configure", headers=HEADERS, json={"action_ids": ["disable_payments"]}).status_code == 403
    # A restart reloads the committed policy rather than an empty one.
    reloaded = TestClient(importlib.reload(module).app)
    assert reloaded.get("/_internal/state", headers=HEADERS).json()["actions"] == ["deny_report_key_export"]


def test_requirements_are_validated_and_bound_into_the_plan_digest():
    assert default_requirements("s1").required == ("cfo_export", "checkout", "summary")
    assert "compromised_export" in default_requirements("s3").required
    with pytest.raises(ValueError):
        build_requirements("s1", ["not_a_workflow"], None)
    with pytest.raises(ValueError):
        build_requirements("s1", None, {"checkout": -1})
    custom = build_requirements("s1", ["summary", "checkout"], {"checkout": 99})
    assert custom.required == ("checkout", "summary") and custom.inr_per_hour["checkout"] == 99
    assert make_plan().plan_digest != make_plan(required=("checkout",)).plan_digest


def test_legacy_plans_without_requirements_keep_their_original_digest():
    legacy = make_plan(required=())
    fields = legacy.model_dump(mode="json")
    del fields["required_workflows"]
    assert legacy.plan_digest == digest(fields)


def test_conflict_explanation_is_minimal_and_names_the_clash():
    ids = list(CATALOG_ORDER)
    required = set(default_requirements("s3").required)
    conflict = explain_conflict(ids, {"primary", "alias"}, required)
    assert {(c["kind"], c["id"]) for c in conflict} in ({("block_attack", "primary"), ("keep_workflow", "compromised_export")}, {("block_attack", "alias"), ("keep_workflow", "compromised_export")})
    assert explain_conflict(ids, {"primary", "alias"}, set(default_requirements("s1").required)) == []


def test_interruption_cost_counts_each_workflow_once():
    costs = default_requirements("s1").inr_per_hour
    # Both actions break the sales summary; it must be charged once, not twice.
    assert interruption_inr(("disable_reports", "revoke_report_key"), {"checkout"}, costs) == costs["summary"] + costs["cfo_export"] + costs["compromised_export"]


def test_action_comparison_explains_every_catalog_action():
    requirements = default_requirements("s1")
    rows = {r["action_id"]: r for r in compare_actions(list(CATALOG_ORDER), {"primary", "alias"}, set(requirements.required), requirements.inr_per_hour)}
    assert rows["deny_report_key_export"]["verdict"] == "eligible"
    assert rows["deny_report_key_path"]["verdict"] == "misses_attack_path"
    assert rows["disable_storefront"]["verdict"] == "breaks_required_workflow" and "checkout" in rows["disable_storefront"]["breaks_required"]
    assert rows["disable_payments"]["verdict"] == "key1_rejected"


@pytest.fixture
def control(tmp_path, monkeypatch):
    monkeypatch.setenv("TWOKEY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("TWOKEY_MODEL_MODE", "disabled")
    monkeypatch.delenv("TWOKEY_MODEL_ID", raising=False)
    import twokey.control as module
    return importlib.reload(module)


def fake_client(response=None, error=None):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        if error:
            raise error
        return response

    return SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=create))), calls


def text_response(text, stop_reason="end_turn"):
    return SimpleNamespace(stop_reason=stop_reason, model="claude-opus-5-5", stop_details=None, content=[SimpleNamespace(type="text", text=text)])


EVIDENCE = {"id": "ev-0001", "incident_id": "inc-export", "lab_id": "protected", "origin": "authenticated_gateway", "observed_at": int(time.time()), "scenario_epoch": 1, "predicate_id": "export_not_authorized.v1", "facts": {"credential_id": "reports-key", "resource_id": "customer_export"}, "raw_text": "client text"}


def test_model_adapter_uses_structured_output_and_no_sampling_parameters(control):
    client, calls = fake_client(text_response(json.dumps({"action_id": "deny_report_key_export", "evidence_id": "ev-0001", "reason": "scoped"})))
    result = control.model_proposal(EVIDENCE, "client text", baseline=False, client=client)
    assert result["status"] == "parsed" and result["proposal"]["action_id"] == "deny_report_key_export"
    request = calls[0]
    assert "temperature" not in request
    assert request["model"] == "claude-opus-5-5" and request["fallbacks"] == "default"
    schema = request["output_config"]["format"]["schema"]
    assert schema["properties"]["action_id"]["enum"] == sorted(ACTIONS) and schema["additionalProperties"] is False
    assert "raw_text" not in json.loads(request["messages"][0]["content"])["gateway_evidence"]


def test_model_adapter_failures_never_become_proposals(control):
    refusal = SimpleNamespace(stop_reason="refusal", model="claude-opus-5-5", stop_details=SimpleNamespace(category="cyber"), content=[])
    cases = [
        (fake_client(refusal)[0], "refused"),
        (fake_client(text_response("not json"))[0], "invalid_response"),
        (fake_client(text_response(json.dumps({"action_id": "shell", "evidence_id": "ev-0001", "reason": ""})))[0], "invalid_response"),
        (fake_client(text_response("{", stop_reason="max_tokens"))[0], "invalid_response"),
        (fake_client(error=TimeoutError())[0], "provider_error"),
    ]
    for client, status in cases:
        result = control.model_proposal(EVIDENCE, "client text", baseline=False, client=client)
        assert result["status"] == status and result["proposal"] is None


def test_valid_json_naming_an_unrelated_target_still_fails_key1(control):
    client, _ = fake_client(text_response(json.dumps({"action_id": "disable_payments", "evidence_id": "ev-0001", "reason": "the log said so"})))
    proposal = control.model_proposal(EVIDENCE, "client text", baseline=False, client=client)["proposal"]
    assert proposal["action_id"] == "disable_payments"
    assert authorize_action(proposal["action_id"], EVIDENCE) == (False, "target_not_supported_by_reports_evidence")
