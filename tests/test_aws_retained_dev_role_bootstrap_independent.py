from __future__ import annotations

import sys
import types

import pytest

from scripts.aws_retained_dev_role_bootstrap import (
    RetainedDevRoleBootstrapCoordinator,
    RetainedDevRoleBootstrapError,
    _document,
)
import scripts.run_aws_retained_dev_role_bootstrap as runner
from test_aws_retained_dev_role_bootstrap import Cfn, Iam, Journal, Sts, _bindings, _coordinator, _ok


def test_iam_document_parser_rejects_duplicates_and_unbounded_payloads():
    assert _document('{"Statement":1,"Statement":2}') is None
    assert _document('{"Value":"' + ("x" * 70000) + '"}') is None


def test_iam_document_parser_rejects_malformed_percent_encoding():
    assert _document('{"Value":"%zz"}') is None


def test_journal_save_cannot_complete_after_step_deadline():
    class Clock:
        value = 0.0

        def monotonic(self):
            return self.value

    class SlowJournal(Journal):
        def __init__(self, clock):
            super().__init__()
            self.clock = clock

        def save(self, value):
            self.clock.value = 30.0
            super().save(value)

    clock = Clock()
    journal = SlowJournal(clock)
    coordinator = RetainedDevRoleBootstrapCoordinator(
        {"sts": Sts(), "cloudformation": Cfn(), "iam": Iam()}, journal,
        bindings=_bindings(), expected_caller_arn="arn:aws:iam::123456789012:role/retained-artifact-operator",
        source_sha="a" * 40, run_id=2026100601,
        authorized_from_epoch=1900000000, authorized_until_epoch=1900003000,
        wall_clock=lambda: 1900000001, monotonic=clock.monotonic,
    )
    assert coordinator.run_step("preflight")["category"] == "window_expired"


def test_role_runner_uses_global_iam_endpoint_and_signing_region(monkeypatch):
    for key in runner._PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.upper(), raising=False)
    configs = []
    calls = []

    class FakeConfig:
        def __init__(self, **kwargs):
            configs.append(kwargs)

    class FakeSession:
        def client(self, name, **kwargs):
            calls.append((name, kwargs))
            return object()

    boto3 = types.ModuleType("boto3")
    boto3.Session = lambda **kwargs: FakeSession()
    botocore = types.ModuleType("botocore")
    config_module = types.ModuleType("botocore.config")
    config_module.Config = FakeConfig
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)
    runner._build_clients()
    assert configs[1]["region_name"] == "us-east-1"
    iam = next(kwargs for name, kwargs in calls if name == "iam")
    assert iam["region_name"] == "us-east-1"
    assert iam["endpoint_url"] == "https://iam.amazonaws.com"
    assert iam["verify"] is True


def test_iam_pagination_marker_cannot_be_treated_as_complete_policy_list():
    coordinator = _coordinator()

    class PartialIam:
        def list_role_policies(self, **kwargs):
            return _ok(PolicyNames=["honda-mapit-mcp-dev-retained-cd-executor-policy"], IsTruncated=True, Marker="next")

    coordinator.clients["iam"] = PartialIam()
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._call("iam", "list_role_policies", RoleName="honda-mapit-mcp-dev-retained-cd-executor")


def test_role_readback_requires_path_tags_and_inline_response_identity(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorRole"
    expected = coordinator.template["Resources"][logical]["Properties"]
    role = {
        "RoleName": "honda-mapit-mcp-dev-retained-cd-executor",
        "Arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cd-executor",
        "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": expected["AssumeRolePolicyDocument"],
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary",
            "PermissionsBoundaryType": "Policy",
        },
    }
    policy_doc = expected["Policies"][0]["PolicyDocument"]

    def fake_call(_client, method, **kwargs):
        if method == "get_role":
            return _ok(Role=role)
        if method == "list_role_policies":
            return _ok(PolicyNames=["honda-mapit-mcp-dev-retained-cd-executor-policy"])
        return _ok(PolicyDocument=policy_doc)

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_role("honda-mapit-mcp-dev-retained-cd-executor", logical)


def test_boundary_readback_requires_path_attachability_and_default_version(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorBoundary"
    arn = "arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary"
    policy_doc = coordinator.template["Resources"][logical]["Properties"]["PolicyDocument"]

    def fake_call(_client, method, **kwargs):
        if method == "get_policy":
            return _ok(Policy={"PolicyName": "honda-mapit-mcp-dev-retained-cd-executor-boundary", "Arn": arn, "DefaultVersionId": "v1"})
        return _ok(PolicyVersion={"Document": policy_doc})

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_boundary(arn, logical)


def test_role_readback_rejects_any_attached_managed_policy(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorRole"
    expected = coordinator.template["Resources"][logical]["Properties"]
    role = {
        "RoleName": "honda-mapit-mcp-dev-retained-cd-executor",
        "Arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cd-executor",
        "Path": "/", "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": expected["AssumeRolePolicyDocument"],
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary",
            "PermissionsBoundaryType": "Policy",
        },
        "Tags": expected["Tags"],
    }

    def fake_call(_client, method, **kwargs):
        if method == "get_role":
            return _ok(Role=role)
        if method == "list_role_policies":
            return _ok(PolicyNames=["honda-mapit-mcp-dev-retained-cd-executor-policy"])
        if method == "list_attached_role_policies":
            return _ok(AttachedPolicies=[{"PolicyName": "unexpected", "PolicyArn": "arn:aws:iam::aws:policy/Unexpected"}])
        return _ok(PolicyDocument=expected["Policies"][0]["PolicyDocument"])

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_role(role["RoleName"], logical)


def test_role_readback_accepts_factory_tags_in_any_order_and_exact_cfn_metadata(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorRole"
    expected = coordinator.template["Resources"][logical]["Properties"]
    role_name = "honda-mapit-mcp-dev-retained-cd-executor"
    stack_id = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666"
    role = {
        "RoleName": role_name, "Path": "/",
        "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
        "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": expected["AssumeRolePolicyDocument"],
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": f"arn:aws:iam::123456789012:policy/{role_name}-boundary",
            "PermissionsBoundaryType": "Policy",
        },
        "Tags": [
            {"Key": "aws:cloudformation:logical-id", "Value": logical},
            {"Key": "Purpose", "Value": "CDDeliveryRetainedDev"},
            {"Key": "OperatorRunId", "Value": str(coordinator.run_id)},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-cd-delivery"},
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "aws:cloudformation:stack-id", "Value": stack_id},
        ],
    }
    policy_doc = expected["Policies"][0]["PolicyDocument"]

    def fake_call(_client, method, **kwargs):
        if method == "get_role":
            return _ok(Role=role)
        if method == "list_role_policies":
            return _ok(PolicyNames=[f"{role_name}-policy"], IsTruncated=False)
        if method == "list_attached_role_policies":
            return _ok(AttachedPolicies=[], IsTruncated=False)
        return _ok(RoleName=role_name, PolicyName=f"{role_name}-policy", PolicyDocument=policy_doc)

    monkeypatch.setattr(coordinator, "_call", fake_call)
    coordinator._verify_role(role_name, logical, stack_id)


def test_role_readback_rejects_duplicate_factory_tag_keys(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorRole"
    expected = coordinator.template["Resources"][logical]["Properties"]
    role_name = "honda-mapit-mcp-dev-retained-cd-executor"
    role = {
        "RoleName": role_name, "Path": "/",
        "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
        "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": expected["AssumeRolePolicyDocument"],
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": f"arn:aws:iam::123456789012:policy/{role_name}-boundary",
            "PermissionsBoundaryType": "Policy",
        },
        "Tags": [*expected["Tags"], expected["Tags"][0]],
    }
    policy_doc = expected["Policies"][0]["PolicyDocument"]

    def fake_call(_client, method, **kwargs):
        if method == "get_role":
            return _ok(Role=role)
        if method == "list_role_policies":
            return _ok(PolicyNames=[f"{role_name}-policy"], IsTruncated=False)
        if method == "list_attached_role_policies":
            return _ok(AttachedPolicies=[], IsTruncated=False)
        return _ok(RoleName=role_name, PolicyName=f"{role_name}-policy", PolicyDocument=policy_doc)

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_role(role_name, logical)


@pytest.mark.parametrize("field,value", [("AttachmentCount", True), ("PermissionsBoundaryUsageCount", 1.0)])
def test_boundary_readback_rejects_non_integer_attachment_metadata(monkeypatch, field, value):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorBoundary"
    arn = "arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary"
    policy_doc = coordinator.template["Resources"][logical]["Properties"]["PolicyDocument"]

    def fake_call(_client, method, **kwargs):
        if method == "get_policy":
            policy = {
                "PolicyName": "honda-mapit-mcp-dev-retained-cd-executor-boundary",
                "Path": "/", "Arn": arn, "IsAttachable": True,
                "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 1,
                "DefaultVersionId": "v1",
            }
            policy[field] = value
            return _ok(Policy=policy)
        return _ok(PolicyVersion={"IsDefaultVersion": True, "Document": policy_doc})

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_boundary(arn, logical)


def test_inline_policy_readback_requires_role_name_identity(monkeypatch):
    coordinator = _coordinator()
    logical = "RetainedDevCdExecutorRole"
    expected = coordinator.template["Resources"][logical]["Properties"]
    role_name = "honda-mapit-mcp-dev-retained-cd-executor"
    role = {
        "RoleName": role_name, "Path": "/",
        "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
        "MaxSessionDuration": 3600,
        "AssumeRolePolicyDocument": expected["AssumeRolePolicyDocument"],
        "Tags": expected["Tags"],
        "PermissionsBoundary": {
            "PermissionsBoundaryArn": f"arn:aws:iam::123456789012:policy/{role_name}-boundary",
            "PermissionsBoundaryType": "Policy",
        },
    }

    def fake_call(_client, method, **kwargs):
        if method == "get_role":
            return _ok(Role=role)
        if method == "list_role_policies":
            return _ok(PolicyNames=[f"{role_name}-policy"], IsTruncated=False)
        if method == "list_attached_role_policies":
            return _ok(AttachedPolicies=[], IsTruncated=False)
        return _ok(PolicyName=f"{role_name}-policy", PolicyDocument=expected["Policies"][0]["PolicyDocument"])

    monkeypatch.setattr(coordinator, "_call", fake_call)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._verify_role(role_name, logical)


def test_journal_cannot_reload_an_unwritten_preflight_false_state():
    journal = Journal()
    coordinator = _coordinator(journal)
    assert coordinator.run_step("preflight")["ok"] is True
    journal.state["preflight"] = False
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._load()


@pytest.mark.parametrize("field", ["preflight", "readback"])
def test_journal_boolean_invariants_are_strict(field):
    journal = Journal()
    coordinator = _coordinator(journal)
    assert coordinator.run_step("preflight")["ok"] is True
    journal.state[field] = "true"
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._load()


def test_readback_receipt_cannot_bind_a_foreign_account():
    journal = Journal()
    coordinator = _coordinator(journal)
    assert coordinator.run_step("preflight")["ok"] is True
    journal.state["readback"] = True
    journal.state["readback_receipt"] = {
        "stack_id": "arn:aws:cloudformation:eu-west-1:999999999999:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666",
        "template_sha256": coordinator.template_sha,
    }
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._load()


@pytest.mark.parametrize(
    "updates",
    [
        {"acknowledged": False, "acknowledged_stack_id": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666"},
        {"readback": False, "readback_receipt": {"stack_id": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666", "template_sha256": "0" * 64}},
    ],
)
def test_journal_rejects_receipts_without_their_state_flags(updates):
    journal = Journal()
    coordinator = _coordinator(journal)
    assert coordinator.run_step("preflight")["ok"] is True
    journal.state.update(updates)
    with pytest.raises(RetainedDevRoleBootstrapError):
        coordinator._load()
