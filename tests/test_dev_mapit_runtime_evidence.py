from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import scripts.dev_mapit_runtime_evidence as evidence
from scripts.dev_mapit_bootstrap_contract import build_plan, make_authority

ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/operator"
KMS_KEY = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"
FRESH_KEYS = tuple(f"tenant-{'a' * 64}")


def _runtime_binding(template_sha="a" * 64):
    from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS
    value = {key: "x" for key in _BINDING_FIELDS}
    value.update({
        "account_id": ACCOUNT,
        "operator_user_arn": CALLER,
        "tenant_keys": ["tenant-" + "1" * 64, "tenant-" + "2" * 64],
        "accepted_runtime_journal_path": "C:/private/runtime",
        "app_stack_arn": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/12345678-1234-1234-1234-123456789abc",
        "app_run_id": 44,
        "api_id": "abcdefghij",
        "user_pool_id": "eu-west-1_Abc123",
        "client_id": "abcdefgh12345678",
        "template_sha256": template_sha,
        "code_sha256": "b" * 64,
        "handler_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "handler_trust_sha256": "c" * 64,
        "handler_policies_sha256": "d" * 64,
        "github_owner_id": 12,
        "github_repository_id": 34,
        "ssm_key_arn": KMS_KEY,
    })
    return value


def _authority_and_bundle():
    common = dict(
        account_id=ACCOUNT, operator_user_arn=CALLER,
        source_sha="e" * 40, run_id=987, expected_caller_arn=CALLER,
        authorized_from_epoch=1_800_000_000, authorized_until_epoch=1_800_000_600,
        ci_evidence_sha256="f" * 64, runtime_evidence_sha256="0" * 64,
        ssm_key_arn=KMS_KEY, tenant_keys=("tenant-" + "a" * 64,),
        excluded_tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
    )
    provisional = make_authority(**common)
    plan = build_plan(provisional)
    bundle = {
        "schema": 1,
        "kind": "dev-mapit-runtime-evidence",
        "account_id": ACCOUNT,
        "caller_arn": CALLER,
        "source_sha": common["source_sha"],
        "run_id": common["run_id"],
        "authorized_from_epoch": common["authorized_from_epoch"],
        "authorized_until_epoch": common["authorized_until_epoch"],
        "mapit_plan_sha256": plan.template_sha256,
        "synthetic_binding_sha256": "1" * 64,
        "synthetic_authorization_sha256": "2" * 64,
        "synthetic_state_sha256": "3" * 64,
        "runtime_binding": _runtime_binding(),
    }
    common["runtime_evidence_sha256"] = evidence.runtime_evidence_digest(bundle)
    return make_authority(**common), bundle, plan.template


def _app_template():
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]}
    policies = [
        {"PolicyName": "honda-mapit-mcp-dev-retained-owned-log-writes",
         "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "arn:aws:logs:eu-west-1:123456789012:log-group:/owned:*"}]}},
        {"PolicyName": "honda-mapit-mcp-dev-retained-tenant-read",
         "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "arn:aws:dynamodb:eu-west-1:123456789012:table/old"}]}},
    ]
    resources = {
        "McpHandlerRole": {"Type": "AWS::IAM::Role", "Properties": {
            "RoleName": "honda-mapit-mcp-dev-retained-handler-role",
            "AssumeRolePolicyDocument": trust,
            "Policies": policies,
        }}
    }
    for index in range(18):
        resources[f"Resource{index}"] = {"Type": "AWS::Logs::LogGroup", "Properties": {}}
    return {"Resources": resources}


class FakeIAM:
    def __init__(self, role, policies):
        self.role = role
        self.policies = policies
        self.reads = []

    def get_role(self, **kwargs):
        self.reads.append("get_role")
        return {"Role": copy.deepcopy(self.role), "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_role_policies(self, **kwargs):
        self.reads.append("list_role_policies")
        return {"PolicyNames": list(self.policies), "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_role_policy(self, *, RoleName, PolicyName):
        self.reads.append("get_role_policy")
        return {"RoleName": RoleName, "PolicyName": PolicyName,
                "PolicyDocument": copy.deepcopy(self.policies[PolicyName]),
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_attached_role_policies(self, **kwargs):
        self.reads.append("list_attached_role_policies")
        return {"AttachedPolicies": [], "ResponseMetadata": {"HTTPStatusCode": 200}}


class FakeClient:
    def __init__(self, **responses):
        self.responses = responses
        self.calls = []

    def __getattr__(self, name):
        if name not in self.responses:
            raise AttributeError(name)
        def call(**kwargs):
            self.calls.append((name, kwargs))
            value = self.responses[name]
            return copy.deepcopy(value() if callable(value) else value)
        return call


def _clients(app_template, mapit_template, phase="readback"):
    from scripts.dev_identity_binding_runtime_evidence import _resolve_context
    from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=CALLER,
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64), ssm_key_arn=KMS_KEY,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    policy_props = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    names = [x["PolicyName"] for x in app_template["Resources"]["McpHandlerRole"]["Properties"]["Policies"]]
    policies = {item["PolicyName"]: copy.deepcopy(item["PolicyDocument"])
                for item in app_template["Resources"]["McpHandlerRole"]["Properties"]["Policies"]}
    policies[synthetic["PolicyName"]] = synthetic["PolicyDocument"]
    if phase == "readback":
        policies[policy_props["PolicyName"]] = policy_props["PolicyDocument"]
    role = {"RoleName": "honda-mapit-mcp-dev-retained-handler-role",
            "Arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
            "PermissionsBoundary": None,
            "AssumeRolePolicyDocument": app_template["Resources"]["McpHandlerRole"]["Properties"]["AssumeRolePolicyDocument"]}
    return {
        "sts": FakeClient(get_caller_identity={"Account": ACCOUNT, "Arn": CALLER,
                                                "ResponseMetadata": {"HTTPStatusCode": 200}}), "cloudformation": FakeClient(),
        "iam": FakeIAM(role, policies), "dynamodb": FakeClient(), "ssm": FakeClient(),
        "cognito": FakeClient(),
        "apigatewayv2": FakeClient(get_api={"ApiId": "abcdefghij", "DisableExecuteApiEndpoint": True,
                                                    "ResponseMetadata": {"HTTPStatusCode": 200}}),
        "lambda": FakeClient(get_function_concurrency={"ReservedConcurrentExecutions": 0,
                                                              "ResponseMetadata": {"HTTPStatusCode": 200}}),
        "kms": FakeClient(),
    }


def test_bundle_digest_binds_every_field_and_rejects_authority_mismatch(tmp_path):
    authority, bundle, template = _authority_and_bundle()
    assert evidence.runtime_evidence_digest(bundle) == authority.runtime_evidence_sha256
    altered = dict(bundle)
    altered["caller_arn"] = "arn:aws:iam::999999999999:user/other"
    assert evidence.runtime_evidence_digest(altered) != authority.runtime_evidence_sha256
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(altered), encoding="utf-8")
    verifier = evidence.make_mapit_runtime_evidence_verifier(
        path, synthetic_binding_path=path, synthetic_authorization_path=path,
        synthetic_state_dir=tmp_path, acl_checker=lambda _: True)
    result = verifier({}, authority, template, phase="preflight")
    assert result["verified"] is False
    assert result["phase"] == "preflight"
    assert set(result) == {"verified", "calls", "phase", "account_id", "source_sha", "run_id",
                           "caller_arn", "evidence_sha256", "resource_count", "api_closed",
                           "reserve_zero", "mapit_policy_attached"}


@pytest.mark.parametrize("bad", [
    {"NextToken": "next"},
    {"IsTruncated": True},
    {"ResponseMetadata": {"HTTPStatusCode": 403}},
    {"ResponseMetadata": {"HTTPStatusCode": True}},
])
def test_sdk_reply_validation_fails_closed_on_pagination_and_status(bad):
    assert evidence._valid_reply({"ResponseMetadata": {"HTTPStatusCode": 200}})
    assert not evidence._valid_reply({**bad, "ResponseMetadata": bad.get(
        "ResponseMetadata", {"HTTPStatusCode": 200})})


def test_counting_client_is_read_only_bounded_and_counts_failed_dispatch():
    class Client:
        def put_parameter(self, **kwargs):
            raise AssertionError("write dispatched")

        def get_item(self, **kwargs):
            raise RuntimeError("private response")

    counter = [0]
    client = evidence._CountingClient("ssm", Client(), counter, 10.0, lambda: 1.0, [1.0])
    with pytest.raises(evidence._EvidenceFailure):
        client.put_parameter(Name="sensitive")
    assert counter[0] == 0
    with pytest.raises(RuntimeError):
        client.get_item(Key={})
    assert counter[0] == 1


def test_counted_services_share_monotonic_rollback_fence():
    times = iter((1.0, 2.0, 1.5))
    now = lambda: next(times)
    counter, clock_state = [0], [1.0]
    first = evidence._CountingClient(
        "lambda", FakeClient(get_state={"ResponseMetadata": {"HTTPStatusCode": 200}}),
        counter, 10.0, now, clock_state,
    )
    second = evidence._CountingClient(
        "sts", FakeClient(get_state={"ResponseMetadata": {"HTTPStatusCode": 200}}),
        counter, 10.0, now, clock_state,
    )
    first.get_state()
    with pytest.raises(evidence._EvidenceFailure):
        second.get_state()
    assert counter[0] == 1


@pytest.mark.parametrize("phase,include_mapit", [("preflight", False), ("readback", True)])
def test_full_policy_snapshot_requires_exact_three_or_four_policy_set(phase, include_mapit):
    authority, bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    clients = _clients(app_template, mapit_template, phase)
    synthetic = evidence._validate_historical_bootstrap
    synthetic_policy = {
        "policy_name": "honda-mapit-mcp-dev-identity-bindings-runtime-read",
        "policy_document": {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-mapit-identity-bindings"}]},
    }
    # Ensure test fixture has an exact synthetic row independent of filesystem evidence.
    clients["iam"].policies[synthetic_policy["policy_name"]] = synthetic_policy["policy_document"]
    if include_mapit:
        clients["iam"].policies[mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyName"]] = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]
    else:
        clients["iam"].policies.pop(mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyName"], None)
    snapshot = evidence._policy_snapshot(
        clients["iam"], expected_template=app_template,
        resource_rows={}, account=ACCOUNT, phase=phase,
        mapit_template={**mapit_template, "__synthetic_policy": synthetic_policy},
    )
    assert len(snapshot["full_names"]) == (4 if include_mapit else 3)
    assert len(snapshot["projected_names"]) == 3
    if include_mapit:
        clients["iam"].policies["unexpected-policy"] = {"Version": "2012-10-17", "Statement": []}
        with pytest.raises(evidence._EvidenceFailure):
            evidence._policy_snapshot(
                clients["iam"], expected_template=app_template,
                resource_rows={}, account=ACCOUNT, phase=phase,
                mapit_template={**mapit_template, "__synthetic_policy": synthetic_policy},
            )


def test_policy_snapshot_rejects_foreign_policy_document_and_role_attachment():
    _, _, template = _authority_and_bundle()
    app = _app_template()
    client = _clients(app, template, "readback")["iam"]
    synthetic = {"policy_name": "honda-mapit-mcp-dev-identity-bindings-runtime-read",
                 "policy_document": {"Version": "2012-10-17", "Statement": []}}
    client.policies[synthetic["policy_name"]] = synthetic["policy_document"]
    mapit = template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    client.policies[mapit["PolicyName"]] = mapit["PolicyDocument"]
    client.policies["honda-mapit-mcp-dev-retained-tenant-read"]["Statement"][0]["Resource"] = "*"
    with pytest.raises(evidence._EvidenceFailure):
        evidence._policy_snapshot(client, expected_template=app, resource_rows={}, account=ACCOUNT,
                                  phase="readback", mapit_template={**template, "__synthetic_policy": synthetic})
    client.policies.pop("honda-mapit-mcp-dev-retained-tenant-read")
    with pytest.raises(evidence._EvidenceFailure):
        evidence._policy_snapshot(client, expected_template=app, resource_rows={}, account=ACCOUNT,
                                  phase="readback", mapit_template={**template, "__synthetic_policy": synthetic})


def test_callback_returns_exact_phase_receipt_after_full_snapshots(tmp_path, monkeypatch):
    authority, bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    bundle["runtime_binding"]["template_sha256"] = evidence._digest(app_template)
    # The authority binds the whole bundle, so rebuild it after the nested
    # runtime binding is finalized.
    authority = make_authority(
        account_id=ACCOUNT, operator_user_arn=CALLER, source_sha="e" * 40, run_id=987,
        expected_caller_arn=CALLER, authorized_from_epoch=1_800_000_000,
        authorized_until_epoch=1_800_000_600, ci_evidence_sha256="f" * 64,
        runtime_evidence_sha256=evidence.runtime_evidence_digest(bundle), ssm_key_arn=KMS_KEY,
        tenant_keys=("tenant-" + "a" * 64,),
        excluded_tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
    old = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=CALLER,
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64), ssm_key_arn=KMS_KEY,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    old_policy = {"policy_name": old["PolicyName"], "policy_document": old["PolicyDocument"]}
    monkeypatch.setattr(evidence, "_validate_historical_bootstrap", lambda **_kwargs: old_policy)
    monkeypatch.setattr(evidence, "_current_template", lambda *_args: (app_template, {}))
    def legacy(clients, binding):
        assert binding["added_runtime_policy"] == old_policy
        rows = clients["iam"].list_role_policies(RoleName="role")["PolicyNames"]
        assert len(rows) == 3
        return {"verified": True}
    monkeypatch.setattr(evidence, "verify_accepted_runtime", legacy)
    clients = _clients(app_template, mapit_template, "readback")
    callback = evidence.make_mapit_runtime_evidence_verifier(
        bundle_path, synthetic_binding_path=bundle_path,
        synthetic_authorization_path=bundle_path, synthetic_state_dir=tmp_path,
        acl_checker=lambda _path: True,
    )
    result = callback(clients, authority, mapit_template, phase="readback")
    assert result == {
        "verified": True, "calls": 18, "phase": "readback", "account_id": ACCOUNT,
        "source_sha": "e" * 40, "run_id": 987, "caller_arn": CALLER,
        "evidence_sha256": authority.runtime_evidence_sha256,
        "resource_count": 19, "api_closed": True, "reserve_zero": True,
        "mapit_policy_attached": True,
    }


def test_historical_provenance_uses_actual_old_constructor_and_readonly_load_projection(tmp_path, monkeypatch):
    from tests.test_aws_dev_identity_binding_bootstrap import _bootstrap_fixture
    from scripts.aws_dev_identity_binding_bootstrap import STACK_NAME as OLD_STACK
    from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap

    old_coordinator, _, _ = _bootstrap_fixture()
    base_binding = copy.deepcopy(old_coordinator.binding)
    binding = {**base_binding, "github_owner_id": 12, "github_repository_id": 34}
    raw_binding = dict(binding)
    raw_binding["tenant_keys"] = list(raw_binding["tenant_keys"])
    historical_caller = old_coordinator.caller
    source, old_run, start, end = "c" * 40, 5678, 1_700_000_000, 1_700_003_600
    authorization = {"account": ACCOUNT, "source_sha": source, "run_id": old_run,
                     "expected_caller_arn": historical_caller, "start": start, "end": end, "ci_run_id": 99}
    stack_id = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{OLD_STACK}/12345678-1234-1234-1234-123456789abc"
    state = {
        "schema": 1, "kind": "dev-identity-binding-bootstrap", "account": ACCOUNT,
        "source_sha": source, "run_id": old_run, "binding_sha256": old_coordinator.binding_sha256,
        "template_sha256": old_coordinator.template_sha256,
        "authorized_from_epoch": start, "authorized_until_epoch": end,
        "last_observed_epoch": start + 10, "expected_caller_arn": historical_caller, "preflight": True,
        "intent": {"token": old_coordinator._create_token(), "stack_name": OLD_STACK},
        "acknowledged": True, "acknowledged_stack_id": stack_id, "readback": True,
        "readback_receipt": {"stack_id": stack_id, "template_sha256": old_coordinator.template_sha256},
    }
    raw_binding_bytes = json.dumps(raw_binding, sort_keys=True, separators=(",", ":")).encode()
    auth_bytes = json.dumps(authorization, sort_keys=True, separators=(",", ":")).encode()
    state_bytes = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()

    class Journal:
        def __init__(self, _directory):
            pass
        class _Lock:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
        def locked(self):
            return self._Lock()
        def load(self):
            return copy.deepcopy(state)
        def save(self, _value):
            raise AssertionError("historical journal must remain read-only")

    monkeypatch.setattr(evidence, "FileJournal", Journal)
    monkeypatch.setattr(evidence, "validate_private_location", lambda path, **_kwargs: Path(path))
    monkeypatch.setattr(evidence, "load_binding", lambda *_args, **_kwargs: copy.deepcopy(binding))
    monkeypatch.setattr(evidence, "load_authorization", lambda *_args, **_kwargs: copy.deepcopy(authorization))
    by_name = {"binding.json": raw_binding_bytes, "authorization.json": auth_bytes,
               "rehearsal-state.json": state_bytes}
    monkeypatch.setattr(evidence, "_read_private", lambda path, **_kwargs: (Path(path), by_name[Path(path).name]))
    authority = make_authority(
        account_id=ACCOUNT, operator_user_arn=historical_caller, source_sha="e" * 40,
        run_id=987, expected_caller_arn=historical_caller,
        authorized_from_epoch=1_800_000_000, authorized_until_epoch=1_800_000_600,
        ci_evidence_sha256="f" * 64, runtime_evidence_sha256="0" * 64,
        ssm_key_arn=KMS_KEY, tenant_keys=("tenant-" + "a" * 64,),
        excluded_tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64),
    )
    _, bundle, _template = _authority_and_bundle()
    bundle["synthetic_binding_sha256"] = hashlib.sha256(raw_binding_bytes).hexdigest()
    bundle["synthetic_authorization_sha256"] = hashlib.sha256(auth_bytes).hexdigest()
    bundle["synthetic_state_sha256"] = hashlib.sha256(state_bytes).hexdigest()
    bundle["runtime_binding"]["app_stack_arn"] = binding["app_stack_arn"]
    bundle["runtime_binding"]["operator_user_arn"] = historical_caller
    bundle["runtime_binding"]["api_id"] = binding["api_id"]
    bundle["runtime_binding"]["handler_role_arn"] = binding["handler_role_arn"]
    result = evidence._validate_historical_bootstrap(
        clients=old_coordinator.clients, binding_path=tmp_path / "binding.json",
        authorization_path=tmp_path / "authorization.json", state_dir=tmp_path / "state",
        bundle=bundle, authority=authority, acl_checker=lambda _path: True,
    )
    expected = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=historical_caller,
        tenant_keys=base_binding["tenant_keys"], ssm_key_arn=base_binding["ssm_key_arn"],
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    assert result == {"policy_name": expected["PolicyName"], "policy_document": expected["PolicyDocument"]}
