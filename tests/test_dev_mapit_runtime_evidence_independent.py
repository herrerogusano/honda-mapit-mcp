from __future__ import annotations

import copy
import json

import pytest

import scripts.dev_mapit_runtime_evidence as evidence
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
from tests.test_dev_mapit_runtime_evidence import (
    ACCOUNT,
    CALLER,
    KMS_KEY,
    FakeClient,
    _app_template,
    _authority_and_bundle,
    _clients,
)
from scripts.dev_mapit_bootstrap_contract import make_authority


def _rows(template):
    return [
        {
            "LogicalResourceId": name,
            "PhysicalResourceId": f"physical-{name}",
            "ResourceType": resource["Type"],
            "ResourceStatus": "CREATE_COMPLETE",
        }
        for name, resource in template["Resources"].items()
    ]


def _wrapper_inputs(tmp_path):
    authority, bundle, mapit_template = _authority_and_bundle()
    app = _app_template()
    bundle["runtime_binding"]["template_sha256"] = evidence._digest(app)
    authority = make_authority(
        account_id=ACCOUNT,
        operator_user_arn=CALLER,
        source_sha="e" * 40,
        run_id=987,
        expected_caller_arn=CALLER,
        authorized_from_epoch=1_800_000_000,
        authorized_until_epoch=1_800_000_600,
        ci_evidence_sha256="f" * 64,
        runtime_evidence_sha256=evidence.runtime_evidence_digest(bundle),
        ssm_key_arn=KMS_KEY,
        tenant_keys=("tenant-" + "a" * 64,),
        excluded_tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
    )
    bundle_path = tmp_path / "runtime-evidence.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    clients = _clients(app, mapit_template, "readback")
    cfn = FakeClient(
        get_template={
            "TemplateBody": app,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
        list_stack_resources={
            "StackResourceSummaries": _rows(app),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        },
    )
    clients["cloudformation"] = cfn
    old = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT,
        operator_user_arn=CALLER,
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
        ssm_key_arn=KMS_KEY,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    old_policy = {"policy_name": old["PolicyName"], "policy_document": old["PolicyDocument"]}
    return authority, bundle, mapit_template, app, clients, bundle_path, old_policy


def test_real_template_reader_and_policy_projection_are_readonly_composed(tmp_path, monkeypatch):
    authority, bundle, mapit_template, app, clients, bundle_path, old_policy = _wrapper_inputs(tmp_path)
    monkeypatch.setattr(evidence, "_validate_historical_bootstrap", lambda **_kwargs: old_policy)

    def legacy(projected_clients, binding):
        assert binding["added_runtime_policy"] == old_policy
        # The unchanged verifier sees only the already-validated legacy three-policy view.
        names = projected_clients["iam"].list_role_policies(RoleName="role")["PolicyNames"]
        assert len(names) == 3
        return {"verified": True}

    monkeypatch.setattr(evidence, "verify_accepted_runtime", legacy)
    callback = evidence.make_mapit_runtime_evidence_verifier(
        bundle_path,
        synthetic_binding_path=bundle_path,
        synthetic_authorization_path=bundle_path,
        synthetic_state_dir=tmp_path,
        acl_checker=lambda _path: True,
        monotonic=lambda: 10.0,
    )
    result = callback(clients, authority, mapit_template, phase="readback")

    assert result["verified"] is True
    assert result["resource_count"] == 19
    assert result["api_closed"] is True and result["reserve_zero"] is True
    # STS twice, template/resource inventory twice, 4-policy IAM snapshot twice,
    # then one API and one Lambda closure read. Projection calls are in-memory.
    assert result["calls"] == 22
    assert len(clients["cloudformation"].calls) == 4
    assert clients["apigatewayv2"].calls == [("get_api", {"ApiId": "abcdefghij"})]
    assert clients["lambda"].calls == [("get_function_concurrency", {
        "FunctionName": "honda-mapit-mcp-dev-retained-handler",
    })]


def test_real_inventory_reread_detects_policy_drift_before_closure_reads(tmp_path, monkeypatch):
    authority, bundle, mapit_template, app, clients, bundle_path, old_policy = _wrapper_inputs(tmp_path)
    monkeypatch.setattr(evidence, "_validate_historical_bootstrap", lambda **_kwargs: old_policy)
    changed = {"done": False}

    def legacy(_projected_clients, _binding):
        # Simulate an external role-policy mutation between the two full snapshots.
        clients["iam"].policies["honda-mapit-mcp-dev-retained-tenant-read"]["Statement"][0]["Resource"] = "*"
        changed["done"] = True
        return {"verified": True}

    monkeypatch.setattr(evidence, "verify_accepted_runtime", legacy)
    callback = evidence.make_mapit_runtime_evidence_verifier(
        bundle_path,
        synthetic_binding_path=bundle_path,
        synthetic_authorization_path=bundle_path,
        synthetic_state_dir=tmp_path,
        acl_checker=lambda _path: True,
        monotonic=lambda: 10.0,
    )
    result = callback(clients, authority, mapit_template, phase="readback")

    assert changed["done"] is True
    assert result["verified"] is False
    assert clients["apigatewayv2"].calls == []
    assert clients["lambda"].calls == []
    assert 0 < result["calls"] <= 64


def test_current_template_rejects_duplicate_inventory_and_sdk_pagination():
    _, bundle, _, app, clients, _, _ = _wrapper_inputs_for_direct()
    binding = bundle["runtime_binding"]
    rows = _rows(app)
    rows[-1] = dict(rows[0])
    clients["cloudformation"] = FakeClient(
        get_template={"TemplateBody": app, "ResponseMetadata": {"HTTPStatusCode": 200}},
        list_stack_resources={"StackResourceSummaries": rows, "ResponseMetadata": {"HTTPStatusCode": 200}},
    )
    counted = evidence._CountingClient("cloudformation", clients["cloudformation"], [0], 40.0, lambda: 5.0, [5.0])
    with pytest.raises(evidence._EvidenceFailure):
        evidence._current_template({"cloudformation": counted}, binding)
    assert counted._counter[0] == 2

    clients["cloudformation"] = FakeClient(
        get_template={"TemplateBody": app, "ResponseMetadata": {"HTTPStatusCode": 200}},
        list_stack_resources={"StackResourceSummaries": _rows(app), "NextToken": "opaque",
                              "ResponseMetadata": {"HTTPStatusCode": 200}},
    )
    counted = evidence._CountingClient("cloudformation", clients["cloudformation"], [0], 40.0, lambda: 5.0, [5.0])
    with pytest.raises(evidence._EvidenceFailure):
        evidence._current_template({"cloudformation": counted}, binding)
    assert counted._counter[0] == 2


def _wrapper_inputs_for_direct():
    authority, bundle, mapit_template = _authority_and_bundle()
    app = _app_template()
    clients = _clients(app, mapit_template, "readback")
    return authority, bundle, mapit_template, app, clients, None, None


def test_counting_client_enforces_exclusive_deadline_and_64_dispatched_calls():
    underlying = FakeClient(get_item={"ResponseMetadata": {"HTTPStatusCode": 200}})
    counter = [0]
    wrapped = evidence._CountingClient("dynamodb", underlying, counter, 25.0, lambda: 1.0, [1.0])
    for _ in range(64):
        wrapped.get_item()
    with pytest.raises(evidence._EvidenceFailure):
        wrapped.get_item()
    assert counter[0] == 64
    assert len(underlying.calls) == 64

    at_deadline = evidence._CountingClient("dynamodb", underlying, counter, 25.0,
                                           lambda: 25.0, [1.0])
    with pytest.raises(evidence._EvidenceFailure):
        at_deadline.get_item()
    assert counter[0] == 64
    assert len(underlying.calls) == 64

