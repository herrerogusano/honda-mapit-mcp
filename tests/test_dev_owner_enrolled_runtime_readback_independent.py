from __future__ import annotations

import copy

import pytest

import scripts.dev_owner_enrolled_runtime_readback as readback
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
from test_dev_owner_enrolled_runtime_readback import (
    ACCOUNT,
    CALLER,
    KMS_KEY,
    _Iam,
    _app_template,
    _authority_and_bundle,
)


def _role_fixture():
    _authority, _bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT,
        operator_user_arn=CALLER,
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
        ssm_key_arn=KMS_KEY,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    mapit = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    app_role = app_template["Resources"]["McpHandlerRole"]["Properties"]
    policies = {item["PolicyName"]: copy.deepcopy(item["PolicyDocument"])
                for item in app_role["Policies"]}
    policies[synthetic["PolicyName"]] = copy.deepcopy(synthetic["PolicyDocument"])
    policies[mapit["PolicyName"]] = copy.deepcopy(mapit["PolicyDocument"])
    role = {
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "PermissionsBoundary": None,
        "AssumeRolePolicyDocument": copy.deepcopy(app_role["AssumeRolePolicyDocument"]),
    }
    view = {"iam": _Iam(role, policies)}
    rows = {"McpHandlerRole": {"PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler-role"}}
    expected = copy.deepcopy(app_template)
    expected["__mapit_runtime_policy"] = copy.deepcopy(mapit)
    expected["McpHandlerRole"] = app_template["Resources"]["McpHandlerRole"]
    return view, rows, expected, synthetic


@pytest.mark.parametrize("accepted", [False, True])
def test_full_role_snapshot_rejects_mapit_policy_drift_in_each_phase(accepted):
    view, rows, expected, synthetic = _role_fixture()
    name = expected["__mapit_runtime_policy"]["PolicyName"]
    view["iam"].policies[name]["Statement"][0]["Action"] = "dynamodb:PutItem"
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": ACCOUNT}, expected, rows,
            accepted=accepted, synthetic_policy=synthetic["PolicyDocument"])


@pytest.mark.parametrize("method", ["list_role_policies", "list_attached_role_policies"])
def test_role_inventory_requires_explicit_untruncated_readback(method):
    view, rows, expected, synthetic = _role_fixture()
    target = view["iam"]
    original = getattr(target, method)

    def omit_truncation(**kwargs):
        result = original(**kwargs)
        result.pop("IsTruncated", None)
        return result

    setattr(target, method, omit_truncation)
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": ACCOUNT}, expected, rows,
            accepted=False, synthetic_policy=synthetic["PolicyDocument"])


def test_policy_document_parser_rejects_duplicate_json_keys():
    assert readback._json_document('{"Version":"2012-10-17","Version":"wrong"}') is None

