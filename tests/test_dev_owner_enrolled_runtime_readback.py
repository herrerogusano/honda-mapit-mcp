from __future__ import annotations

import copy
import hashlib
import inspect
import json
from pathlib import Path

import pytest

import scripts.dev_owner_enrolled_runtime_readback as readback
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
from scripts.dev_mapit_bootstrap_contract import build_plan
from scripts.dev_mapit_runtime_evidence import runtime_evidence_digest
from scripts.dev_owner_enrolled_namespace_readback import _FIELDS as PUBLICATION_FIELDS
from test_dev_mapit_runtime_evidence import (
    ACCOUNT,
    CALLER,
    KMS_KEY,
    _app_template,
    _authority_and_bundle,
)


def _bare_current_state(authority, template, bundle, clients):
    current = object.__new__(readback.OwnerEnrolledCurrentState)
    current.bootstrap_authority = authority
    current.bootstrap_template = template
    current.mapit_evidence_path = "private/evidence.json"
    current.synthetic_binding_path = "private/binding.json"
    current.synthetic_authorization_path = "private/authorization.json"
    current.synthetic_state_dir = "private/state"
    current.acl_checker = lambda _path: True
    current.clients = clients
    return current


def test_historical_policy_is_rebuilt_from_complete_private_bundle(monkeypatch):
    authority, bundle, template = _authority_and_bundle()
    clients = {name: object() for name in (
        "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
        "apigatewayv2", "lambda", "kms")}
    observed = {}
    expected_policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]}

    def load(path, *, acl_checker):
        observed["path"] = path
        assert callable(acl_checker)
        return copy.deepcopy(bundle), b"private bundle bytes"

    def validate_bundle(value, received_authority, expected_template):
        assert value == bundle
        assert received_authority is authority
        assert expected_template == template
        return copy.deepcopy(bundle["runtime_binding"])

    def validate_history(**kwargs):
        observed["history"] = kwargs
        return {"policy_name": "honda-mapit-mcp-dev-identity-bindings-runtime-read",
                "policy_document": copy.deepcopy(expected_policy)}

    monkeypatch.setattr(readback, "_load_mapit_evidence_bundle", load)
    monkeypatch.setattr(readback, "_validate_mapit_evidence_bundle", validate_bundle)
    monkeypatch.setattr(readback, "_validate_historical_mapit_bootstrap", validate_history)
    current = _bare_current_state(authority, template, bundle, clients)

    assert current._historical_synthetic_policy() == expected_policy
    assert observed["history"]["clients"] == clients
    assert observed["history"]["bundle"] == bundle
    assert observed["history"]["authority"] is authority
    assert observed["history"]["binding_path"] == "private/binding.json"
    assert observed["history"]["authorization_path"] == "private/authorization.json"
    assert observed["history"]["state_dir"] == "private/state"
    assert observed["history"]["acl_checker"] is current.acl_checker


def test_modified_or_wrong_context_bundle_fails_before_historical_parser(monkeypatch):
    authority, bundle, template = _authority_and_bundle()
    altered = copy.deepcopy(bundle)
    altered["caller_arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    calls = []
    monkeypatch.setattr(readback, "_load_mapit_evidence_bundle",
                        lambda *_args, **_kwargs: (altered, b"private"))
    monkeypatch.setattr(readback, "_validate_historical_mapit_bootstrap",
                        lambda **_kwargs: calls.append("must-not-run"))
    current = _bare_current_state(authority, template, altered, {})

    with pytest.raises(readback.OwnerEnrolledReadbackError) as caught:
        current._historical_synthetic_policy()
    assert caught.value.category == "current_state_unverified"
    assert calls == []


class _Iam:
    def __init__(self, role, policies):
        self.role = role
        self.policies = policies

    def get_role(self, **_kwargs):
        return {"Role": copy.deepcopy(self.role), "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_role_policies(self, **_kwargs):
        return {"PolicyNames": list(self.policies), "IsTruncated": False,
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_attached_role_policies(self, **_kwargs):
        return {"AttachedPolicies": [], "IsTruncated": False,
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_role_policy(self, *, RoleName, PolicyName):
        return {"RoleName": RoleName, "PolicyName": PolicyName,
                "PolicyDocument": copy.deepcopy(self.policies[PolicyName]),
                "ResponseMetadata": {"HTTPStatusCode": 200}}


def test_full_role_comparison_rejects_synthetic_policy_drift_in_both_phases():
    _authority, _bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    account = ACCOUNT
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=account,
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
        "Arn": f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-handler-role",
        "PermissionsBoundary": None,
        "AssumeRolePolicyDocument": copy.deepcopy(app_role["AssumeRolePolicyDocument"]),
    }
    view = {"iam": _Iam(role, policies)}
    rows = {"McpHandlerRole": {"PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler-role"}}
    expected_template = copy.deepcopy(app_template)
    expected_template["__mapit_runtime_policy"] = copy.deepcopy(mapit)
    expected_template["McpHandlerRole"] = app_template["Resources"]["McpHandlerRole"]

    assert readback._verify_role(view, {"account_id": account}, expected_template, rows,
                                 accepted=False, synthetic_policy=synthetic["PolicyDocument"])
    assert readback._verify_role(view, {"account_id": account}, expected_template, rows,
                                 accepted=True, synthetic_policy=synthetic["PolicyDocument"])

    altered = copy.deepcopy(synthetic["PolicyDocument"])
    altered["Statement"][0]["Action"] = "dynamodb:PutItem"
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": account}, expected_template, rows,
                              accepted=False, synthetic_policy=altered)
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": account}, expected_template, rows,
                              accepted=True, synthetic_policy=altered)

    mapit_name = mapit["PolicyName"]
    saved_mapit = copy.deepcopy(policies[mapit_name])
    policies[mapit_name]["Statement"][0]["Action"] = "dynamodb:PutItem"
    for phase in (False, True):
        with pytest.raises(readback.OwnerEnrolledReadbackError):
            readback._verify_role(view, {"account_id": account}, expected_template, rows,
                                  accepted=phase, synthetic_policy=synthetic["PolicyDocument"])
    policies[mapit_name] = saved_mapit


def test_role_comparison_rejects_truncated_policy_inventory_and_duplicate_json_keys():
    _authority, _bundle, mapit_template = _authority_and_bundle()
    app_template = _app_template()
    synthetic = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=CALLER,
        tenant_keys=("tenant-" + "1" * 64, "tenant-" + "2" * 64), ssm_key_arn=KMS_KEY,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    mapit = mapit_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    app_role = app_template["Resources"]["McpHandlerRole"]["Properties"]
    policies = {item["PolicyName"]: copy.deepcopy(item["PolicyDocument"])
                for item in app_role["Policies"]}
    policies[synthetic["PolicyName"]] = copy.deepcopy(synthetic["PolicyDocument"])
    policies[mapit["PolicyName"]] = copy.deepcopy(mapit["PolicyDocument"])
    role = {"Arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
            "PermissionsBoundary": None,
            "AssumeRolePolicyDocument": copy.deepcopy(app_role["AssumeRolePolicyDocument"])}
    expected_template = copy.deepcopy(app_template)
    expected_template["__mapit_runtime_policy"] = copy.deepcopy(mapit)
    rows = {"McpHandlerRole": {"PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler-role"}}
    view = {"iam": _Iam(role, policies)}

    view["iam"].list_role_policies = lambda **_kwargs: {
        "PolicyNames": list(policies), "ResponseMetadata": {"HTTPStatusCode": 200}}
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": ACCOUNT}, expected_template, rows,
                              accepted=True, synthetic_policy=synthetic["PolicyDocument"])

    view["iam"] = _Iam(role, policies)
    view["iam"].get_role_policy = lambda *, RoleName, PolicyName: {
        "RoleName": RoleName, "PolicyName": PolicyName,
        "PolicyDocument": '{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}',
        "ResponseMetadata": {"HTTPStatusCode": 200}}
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_role(view, {"account_id": ACCOUNT}, expected_template, rows,
                              accepted=True, synthetic_policy=synthetic["PolicyDocument"])


def test_mapit_plan_is_derived_from_validated_bootstrap_authority():
    authority, _bundle, _template = _authority_and_bundle()
    plan = build_plan(authority)
    assert plan.template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert plan.template_sha256
    assert "pre_runtime_verifier" not in inspect.signature(readback.OwnerEnrolledCurrentState).parameters
    assert "mapit_bootstrap_template" not in inspect.signature(readback.OwnerEnrolledCurrentState).parameters


def test_complete_bundle_digest_is_the_mapit_authority_binding():
    authority, bundle, _template = _authority_and_bundle()
    assert runtime_evidence_digest(bundle) == authority.runtime_evidence_sha256


def _publication_state():
    return {
        "schema": 1,
        "operation": "dev_mapit_binding_key_publication",
        "namespace": "mapit",
        "account": ACCOUNT,
        "source": "8" * 40,
        "run_id": 98765,
        "bootstrap_sha256": "a" * 64,
        "parameter_path": "/honda-mapit-mcp/dev/mapit-identity-binding-config",
        "start": 1_800_001_000,
        "end": 1_800_001_600,
        "phase": "accepted",
    }


def test_accepted_publication_loader_uses_private_filejournal_and_canonical_receipt(tmp_path, monkeypatch):
    state_dir = tmp_path / "publication"
    state_dir.mkdir()
    state = _publication_state()
    raw = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    (state_dir / "rehearsal-state.json").write_bytes(raw)
    monkeypatch.setattr(readback, "validate_private_location",
                        lambda path, **_kwargs: Path(path).resolve())
    receipt = hashlib.sha256(readback._canonical(state)).hexdigest()

    assert readback._load_accepted_publication(
        state_dir, acl_checker=lambda _path: True, expected_receipt_sha256=receipt) == state
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._load_accepted_publication(
            state_dir, acl_checker=lambda _path: True, expected_receipt_sha256="0" * 64)


def test_accepted_publication_loader_rejects_extra_fields_and_nonaccepted_phase(tmp_path, monkeypatch):
    state_dir = tmp_path / "publication"
    state_dir.mkdir()
    state = _publication_state()
    monkeypatch.setattr(readback, "validate_private_location",
                        lambda path, **_kwargs: Path(path).resolve())
    for mutation in (lambda value: value.update({"secret": "never accepted"}),
                     lambda value: value.update({"phase": "put_intent"})):
        altered = copy.deepcopy(state)
        mutation(altered)
        (state_dir / "rehearsal-state.json").write_text(
            json.dumps(altered, sort_keys=True, separators=(",", ":")), encoding="ascii")
        digest = hashlib.sha256(readback._canonical(altered)).hexdigest()
        with pytest.raises(readback.OwnerEnrolledReadbackError):
            readback._load_accepted_publication(
                state_dir, acl_checker=lambda _path: True, expected_receipt_sha256=digest)


def test_bootstrap_lineage_is_reloaded_and_cannot_be_rebound_between_phases(monkeypatch):
    authority, _bundle, _template = _authority_and_bundle()
    current = object.__new__(readback.OwnerEnrolledCurrentState)
    current.clients = {name: object() for name in (
        "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
        "apigatewayv2", "lambda", "kms")}
    current.mapit_bootstrap_authority_path = Path("private/bootstrap/authority.json")
    current.mapit_bootstrap_state_dir = Path("private/bootstrap/state")
    current.acl_checker = lambda _path: True
    current.clock = lambda: 1_800_000_010
    current.monotonic = lambda: 50.0
    current.bootstrap_authority = authority
    current.bootstrap_source = {"source_sha": authority.source_sha}
    current.bootstrap_github = {"github_owner_id": 12, "github_repository_id": 34}
    current.bootstrap_state = {"readback": True}
    current.bootstrap_plan = build_plan(authority)
    current.bootstrap_receipt_sha = "9" * 64
    load_results = [
        (authority, current.bootstrap_source, current.bootstrap_github,
         current.bootstrap_state, current.bootstrap_plan, current.bootstrap_receipt_sha),
        (authority, current.bootstrap_source, current.bootstrap_github,
         {"readback": False}, current.bootstrap_plan, current.bootstrap_receipt_sha),
    ]

    def loader(*_args, **_kwargs):
        return load_results.pop(0)

    monkeypatch.setattr(readback, "_load_accepted_bootstrap", loader)
    current._reload_bootstrap_lineage()
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        current._reload_bootstrap_lineage()


def _build_owner_enrolled_current_state_fixture(tmp_path):
    """Build a genuine private-lineage/current-state fixture for phase tests."""
    from scripts.dev_mapit_bootstrap_contract import make_authority
    from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator
    from scripts.run_aws_closed_rehearsal import FileJournal
    from scripts.run_dev_mapit_bootstrap import ci_evidence_digest
    from scripts.run_aws_retained_dev_bootstrap import validate_authorization
    from scripts.dev_mapit_runtime_evidence import _BUNDLE_KIND
    from tests.test_dev_mapit_bootstrap_coordinator import Clock, Journal, _callbacks, _clients, KEY_ARN
    from tests.test_aws_dev_identity_binding_bootstrap import _bootstrap_fixture
    from scripts.aws_dev_identity_binding_bootstrap import STACK_NAME as SYNTHETIC_STACK
    from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS, _COORDINATOR_FIELDS

    owner_key = "tenant-" + "a" * 64
    storage_keys = ("tenant-" + "8" * 64, "tenant-" + "9" * 64)
    from tests.test_dev_owner_enrolled_delivery import Harness as DeliveryHarness, _accepted
    delivery = DeliveryHarness()
    hosted_historical_keys = tuple(
        row["key"] for row in delivery.prior["Metadata"]["ManifestContract"]["tenants"])
    from tests.test_dev_mapit_bootstrap_coordinator import CALLER as MAPIT_CALLER
    caller = MAPIT_CALLER
    delivery.auth["operator_arn"] = caller
    source = "e" * 40
    run_id = 33
    start, end = 1_800_000_000, 1_800_000_600
    github = {"github_owner_id": 12, "github_repository_id": 34}
    source_auth = validate_authorization({"account": ACCOUNT, "expected_caller_arn": caller,
        "source_sha": source, "ci_run_id": 88, "run_id": run_id,
        "start": start, "end": end})
    ci_sha = ci_evidence_digest(source_auth, github)
    provisional = make_authority(account_id=ACCOUNT, operator_user_arn=caller,
        source_sha=source, run_id=run_id, expected_caller_arn=caller,
        authorized_from_epoch=start, authorized_until_epoch=end, ci_evidence_sha256=ci_sha,
        runtime_evidence_sha256="0" * 64, ssm_key_arn=KEY_ARN, tenant_keys=(owner_key,),
        excluded_tenant_keys=(*hosted_historical_keys, *storage_keys))
    plan = build_plan(provisional)

    synthetic_coordinator, _synthetic_journal, _synthetic_evidence = _bootstrap_fixture()
    synthetic_binding = copy.deepcopy(synthetic_coordinator.binding)
    synthetic_binding["tenant_keys"] = storage_keys
    synthetic_binding["account_id"] = ACCOUNT
    synthetic_binding["operator_user_arn"] = caller
    synthetic_binding["app_stack_arn"] = delivery.auth["stack_id"]
    synthetic_binding["api_id"] = delivery.auth["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
    synthetic_binding["user_pool_id"] = "eu-west-1_Technical12345"
    synthetic_binding["client_id"] = "technicalclient123456"
    synthetic_binding["app_run_id"] = 7
    synthetic_binding["handler_role_arn"] = (
        f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role")
    from scripts.dev_mapit_runtime_evidence import _digest as runtime_digest
    synthetic_binding["template_sha256"] = runtime_digest(delivery.prior)
    synthetic_binding["code_sha256"] = delivery.auth["prior_zip_sha256"]
    from scripts.dev_identity_binding_runtime_evidence import _resolve_context as resolve_runtime, _digest as digest_runtime
    role_properties = delivery.prior["Resources"]["McpHandlerRole"]["Properties"]
    baseline_policy_documents = {item["PolicyName"]:resolve_runtime(item["PolicyDocument"],
        account=ACCOUNT,resource_rows={}) for item in role_properties["Policies"]}
    synthetic_binding["handler_trust_sha256"] = digest_runtime(role_properties["AssumeRolePolicyDocument"])
    synthetic_binding["handler_policies_sha256"] = digest_runtime(baseline_policy_documents)
    synthetic_binding["github_owner_id"] = 12
    synthetic_binding["github_repository_id"] = 34
    accepted_runtime_dir = tmp_path / "synthetic" / "accepted-runtime"
    accepted_runtime_dir.mkdir(parents=True)
    synthetic_binding["accepted_runtime_journal_path"] = str(accepted_runtime_dir)
    from scripts.run_dev_multiuser_runtime_update import CasFileJournal
    CasFileJournal(accepted_runtime_dir).save({"phase":"accepted","binding":{
        "operation":"dev_multiuser_closed_update","account":ACCOUNT,
        "stack":delivery.auth["stack_id"],"target":runtime_digest(delivery.prior)}})
    binding_path = tmp_path / "synthetic" / "binding.json"
    authorization_path = tmp_path / "synthetic" / "authorization.json"
    synthetic_state_dir = tmp_path / "synthetic" / "state"
    binding_path.parent.mkdir(parents=True, exist_ok=True)
    synthetic_state_dir.mkdir()
    raw_binding = {**synthetic_binding, "tenant_keys": list(storage_keys)}
    assert set(raw_binding) == set(_BINDING_FIELDS)
    binding_bytes = json.dumps(raw_binding, sort_keys=True, separators=(",", ":")).encode("ascii")
    synthetic_start, synthetic_end, synthetic_run = 1_700_000_000, 1_700_003_600, 5678
    synthetic_source = "c" * 40
    synthetic_auth = {"account": ACCOUNT, "expected_caller_arn": caller, "source_sha": synthetic_source,
        "ci_run_id": 77, "run_id": synthetic_run, "start": synthetic_start, "end": synthetic_end}
    synthetic_auth = validate_authorization(synthetic_auth)
    auth_bytes = json.dumps(synthetic_auth, sort_keys=True, separators=(",", ":")).encode("ascii")
    # The historical coordinator's own parser is used with its exact immutable
    # binding projection and accepted state; no run_step is called here.
    from scripts.aws_dev_identity_binding_bootstrap import DevIdentityBindingBootstrapCoordinator
    binding_loaded = {key: synthetic_binding[key] for key in _COORDINATOR_FIELDS}
    binding_loaded["tenant_keys"] = tuple(storage_keys)
    from tests.test_aws_dev_identity_binding_bootstrap import _Journal as SyntheticMemoryJournal
    memory_journal = SyntheticMemoryJournal()
    old = DevIdentityBindingBootstrapCoordinator(
        synthetic_coordinator.clients, memory_journal, binding=binding_loaded,
        source_sha=synthetic_source, run_id=synthetic_run, expected_caller_arn=caller,
        authorized_from_epoch=synthetic_start, authorized_until_epoch=synthetic_end,
        accepted_runtime_verifier=lambda *_a, **_k: {},
        wall_clock=lambda: synthetic_start + 10, monotonic=lambda: 100.0)
    old_state = {"schema": 1, "kind": "dev-identity-binding-bootstrap", "account": ACCOUNT,
        "source_sha": synthetic_source, "run_id": synthetic_run,
        "template_sha256": old.template_sha256, "binding_sha256": old.binding_sha256,
        "expected_caller_arn": caller, "authorized_from_epoch": synthetic_start,
        "authorized_until_epoch": synthetic_end, "last_observed_epoch": synthetic_start + 10,
        "preflight": True, "intent": {"token": old._create_token(), "stack_name": SYNTHETIC_STACK},
        "acknowledged": True,
        "acknowledged_stack_id": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{SYNTHETIC_STACK}/12345678-1234-1234-1234-123456789abc",
        "readback": True,
        "readback_receipt": {"stack_id": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{SYNTHETIC_STACK}/12345678-1234-1234-1234-123456789abc",
            "template_sha256": old.template_sha256}}
    (binding_path).write_bytes(binding_bytes)
    from scripts.run_aws_dev_identity_binding_bootstrap import load_binding
    assert load_binding(binding_path, acl_checker=lambda _path: True)["account_id"] == ACCOUNT
    authorization_path.write_bytes(auth_bytes)
    FileJournal(synthetic_state_dir).save(old_state)
    old_state_bytes = FileJournal(synthetic_state_dir).path.read_bytes()

    runtime_binding = {key: binding_loaded[key] for key in _BINDING_FIELDS if key in binding_loaded}
    runtime_binding.update(github_owner_id=12, github_repository_id=34)
    runtime_binding["tenant_keys"] = list(storage_keys)
    bundle = {"schema": 1, "kind": _BUNDLE_KIND, "account_id": ACCOUNT,
        "caller_arn": caller, "source_sha": source, "run_id": run_id,
        "authorized_from_epoch": start, "authorized_until_epoch": end,
        "mapit_plan_sha256": plan.template_sha256,
        "synthetic_binding_sha256": hashlib.sha256(binding_bytes).hexdigest(),
        "synthetic_authorization_sha256": hashlib.sha256(auth_bytes).hexdigest(),
        "synthetic_state_sha256": hashlib.sha256(old_state_bytes).hexdigest(),
        "runtime_binding": runtime_binding}
    from scripts.dev_mapit_runtime_evidence import runtime_evidence_digest
    authority = make_authority(account_id=ACCOUNT, operator_user_arn=caller,
        source_sha=source, run_id=run_id, expected_caller_arn=caller,
        authorized_from_epoch=start, authorized_until_epoch=end,
        ci_evidence_sha256=ci_sha,
        runtime_evidence_sha256=runtime_evidence_digest(bundle), ssm_key_arn=KEY_ARN,
        tenant_keys=(owner_key,), excluded_tenant_keys=(*hosted_historical_keys, *storage_keys))
    authority_path = tmp_path / "mapit-bootstrap" / "authority.json"
    mapit_state_dir = tmp_path / "mapit-bootstrap" / "state"
    mapit_state_dir.mkdir(parents=True)
    raw_authority = {key: getattr(authority, key) for key in (
        "account_id", "operator_user_arn", "source_sha", "run_id", "expected_caller_arn",
        "authorized_from_epoch", "authorized_until_epoch", "ci_evidence_sha256",
        "runtime_evidence_sha256", "ssm_key_arn")}
    raw_authority.update(tenant_keys=[owner_key],
        excluded_tenant_keys=[*hosted_historical_keys, *storage_keys])
    from scripts.run_dev_mapit_bootstrap import KIND as MAPIT_KIND
    authority_path.parent.mkdir(exist_ok=True)
    authority_path.write_text(json.dumps({"schema": 1, "kind": MAPIT_KIND,
        "authority": raw_authority, "source_authorization": source_auth, "github": github},
        sort_keys=True, separators=(",", ":")), encoding="ascii")
    bootstrap_clients, _cfn, _ddb, _iam = _clients(plan)
    source_cb, protection_cb, runtime_cb = _callbacks(authority)
    from scripts.dev_mapit_bootstrap_coordinator import _valid_runtime_evidence
    assert _valid_runtime_evidence(
        runtime_cb(bootstrap_clients, authority, plan.template, phase="preflight"),
        authority, "preflight")
    coordinator_journal = Journal()
    clock = Clock()
    coordinator = MapitBootstrapCoordinator(bootstrap_clients, coordinator_journal,
        authority=authority, fresh_source=source_cb, fresh_protections=protection_cb,
        closed_runtime_verifier=runtime_cb, wall_clock=clock.time, monotonic=clock.monotonic)
    preflight = coordinator.run_step("preflight")
    assert preflight["ok"] is True, preflight
    assert coordinator.run_step("create")["ok"] is True
    _ddb.created = _iam.created = True
    accepted_mapit = coordinator.run_step("readback")
    assert accepted_mapit["ok"] is True, accepted_mapit
    FileJournal(mapit_state_dir).save(coordinator_journal.state)
    bundle_path = tmp_path / "runtime-evidence.json"
    bundle_path.write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")), encoding="ascii")

    current = _bare_current_state(authority, plan.template, bundle, bootstrap_clients)
    current.mapit_evidence_path = bundle_path
    current.synthetic_binding_path = binding_path
    current.synthetic_authorization_path = authorization_path
    current.synthetic_state_dir = synthetic_state_dir
    current.bootstrap_authority = authority
    current.bootstrap_template = plan.template
    current._historical_synthetic_policy()

    from tests.test_dev_owner_enrolled_delivery_sdk import _bundle_for
    from scripts.run_dev_mapit_binding_key_setup import _digest as key_setup_digest

    mapit_receipt = _bootstrap_receipt_digest(authority, coordinator_journal.state,
                                               plan.template_sha256)
    scenario = _OwnerEnrolledSdkScenario(
        delivery=delivery, bootstrap_clients=bootstrap_clients,
        mapit_authority=authority, mapit_state=coordinator_journal.state,
        mapit_plan=plan, mapit_receipt_sha256=mapit_receipt,
        synthetic_tenant_keys=storage_keys,
    )
    raw_clients = scenario.clients()
    client_bundle = _bundle_for(raw_clients)
    from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
    owner_probe = OwnerOAuthSdkBindings(
        raw_clients, account_id=ACCOUNT, operator_user_arn=caller,
        until_epoch=delivery.auth["authorized_until_epoch"],
        wall_clock=lambda: delivery.auth["authorized_from_epoch"] + 20, monotonic=lambda: 100.0,
    )
    owner_snapshot = owner_probe.capture_context(exclude_client_id=delivery.auth["owner_client_id"])
    delivery.auth["owner_context_sha256"] = owner_snapshot["context_sha256"]
    from tests.test_dev_owner_login_context import receipt as owner_receipt
    from tests.test_dev_owner_enrolled_login_lineage import _context_for_delivery
    from scripts.build_aws_dev_owner_oauth import STACK_NAME as OWNER_OAUTH_STACK, build_dev_owner_oauth_template
    owner_auth, owner_binding, _owner_state, _trusted_owner = owner_receipt()
    candidate_rows, candidate_stack = owner_probe._stack(OWNER_OAUTH_STACK, 3)
    owner_template = build_dev_owner_oauth_template(account_id=owner_auth["account"],
        api_id=scenario.api_id, owner_pool_id=delivery.auth["owner_pool_id"],
        callback_url="http://127.0.0.1:8787/callback")
    candidate_result = owner_probe.validate_candidate(candidate_stack["stack_id"], owner_template,
        owner_binding["run_uuid"], owner_auth["start"], owner_auth["end"],
        {name: row["PhysicalResourceId"] for name, row in candidate_rows.items()})
    owner_context = _context_for_delivery(
        delivery, candidate_readback_sha256=candidate_result["readback_sha256"])
    publication_state = _publication_state()
    publication_state.update(
        account=ACCOUNT, source="d" * 40, run_id=delivery.auth["ci_run_id"] + 1,
        bootstrap_sha256=mapit_receipt, start=start, end=end,
    )
    scenario.publication_state = publication_state
    publication_dir = tmp_path / "mapit-publication" / "state"
    publication_dir.mkdir(parents=True)
    FileJournal(publication_dir).save(publication_state)
    delivery_authority = delivery.auth
    delivery_authority.update(
        owner_context_sha256=owner_context.context_digest,
        owner_oauth_receipt_sha256=owner_context.readback_digest,
        mapit_bootstrap_authority_sha256=authority._binding_sha256,
        mapit_bootstrap_receipt_sha256=mapit_receipt,
        mapit_table_id=coordinator_journal.state["readback_receipt"]["table_id"],
        runtime_evidence_sha256=authority.runtime_evidence_sha256,
        owner_tenant_key=owner_key,
        historical_tenant_keys=list(hosted_historical_keys),
        mapit_config_path=publication_state["parameter_path"],
        mapit_config_version=1,
        key_publication_receipt_sha256=key_setup_digest(publication_state),
    )
    assert authority.account_id == delivery_authority["account_id"]
    assert authority.expected_caller_arn == delivery_authority["operator_arn"]
    assert authority._binding_sha256 == delivery_authority["mapit_bootstrap_authority_sha256"]
    assert authority.runtime_evidence_sha256 == delivery_authority["runtime_evidence_sha256"]
    assert delivery_authority["owner_tenant_key"] in authority._tenant_keys
    assert set(delivery_authority["historical_tenant_keys"]).issubset(
        authority._excluded_tenant_keys)
    assert mapit_receipt == delivery_authority["mapit_bootstrap_receipt_sha256"]
    instance = readback.OwnerEnrolledCurrentState(
        client_bundle=client_bundle, authority=delivery_authority,
        accepted=_accepted(delivery_authority), prior_template=delivery.prior,
        manifest_raw=delivery.args["manifest_raw"],
        invitation_jwks=delivery.args["invitation_jwks"], mapit_jwks=delivery.args["mapit_jwks"],
        archive_bytes=delivery.archive, archive_size=len(delivery.archive),
        owner_oauth_context=owner_context,
        mapit_bootstrap_authority_path=authority_path, mapit_bootstrap_state_dir=mapit_state_dir,
        mapit_publication_state_dir=publication_dir, mapit_evidence_path=bundle_path,
        synthetic_binding_path=binding_path, synthetic_authorization_path=authorization_path,
        synthetic_state_dir=synthetic_state_dir, acl_checker=lambda _path: True,
        clock=lambda: delivery.auth["authorized_from_epoch"] + 20, monotonic=lambda: 100.0,
    )
    return {
        "current": instance,
        "delivery": delivery,
        "delivery_binding": copy.deepcopy(instance.delivery_binding),
        "owner_context": owner_context,
        "mapit_authority": authority,
        "mapit_state": coordinator_journal.state,
        "mapit_plan": plan,
        "mapit_bundle": bundle,
        "runtime_binding": runtime_binding,
        "synthetic_binding": synthetic_binding,
        "bootstrap_clients": bootstrap_clients,
        "scenario": scenario,
    }


def test_owner_enrolled_current_state_constructor_runs_real_pre_and_accepted_phases(tmp_path, monkeypatch):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    current = fixture["current"]
    scenario = fixture["scenario"]
    assert repr(current) == "OwnerEnrolledCurrentState(<redacted>)"
    import scripts.dev_identity_binding_runtime_evidence as legacy_evidence
    monkeypatch.setattr(legacy_evidence, "validate_private_location", lambda path: Path(path))

    pre = current("pre_update", fixture["delivery_binding"])
    assert pre["phase"] == "pre_update"
    assert pre["template_sha256"] == fixture["delivery"].auth["prior_template_sha256"]
    assert pre["api_disabled"] is True and pre["lambda_reserved_concurrency"] == 0
    assert pre["runtime_checks"]["owner_jwt_authorizer"] is False
    assert pre["runtime_checks"]["authorization_row"] is True

    scenario.phase = "accepted"
    accepted = current("accepted", fixture["delivery_binding"])
    assert accepted["phase"] == "accepted"
    assert accepted["template_sha256"] == current.target_sha
    assert accepted["api_disabled"] is True and accepted["lambda_reserved_concurrency"] == 0
    assert accepted["owner_issuer"] == current.target["Resources"]["McpJwtAuthorizer"]["Properties"][
        "JwtConfiguration"]["Issuer"]
    assert accepted["authorization_row_status"] == "active"
    assert accepted["authorization_row_revision"] == 1
    assert accepted["leading_keys"] == [*fixture["delivery"].auth["historical_tenant_keys"],
        fixture["delivery"].auth["owner_tenant_key"]]


def _bootstrap_receipt_digest(authority, state, template_sha256):
    from scripts.run_dev_mapit_binding_key_setup import _digest
    return _digest({"authority_sha256": authority._binding_sha256,
                    "intent": state["intent"], "readback_receipt": state["readback_receipt"],
                    "template_sha256": template_sha256})


class _OwnerEnrolledSdkScenario:
    """SDK-shaped fake read surface for the actual current-state adapter."""

    def __init__(self, *, delivery, bootstrap_clients, mapit_authority, mapit_state,
                 mapit_plan, mapit_receipt_sha256, synthetic_tenant_keys):
        from types import SimpleNamespace
        from datetime import datetime, timezone
        from tests.test_dev_owner_enrolled_delivery_sdk import _CLIENT_ENDPOINTS
        from scripts.dev_owner_enrolled_runtime_readback import _LOGICAL_TYPES
        from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template
        from scripts.dev_owner_oauth_sdk import DOMAIN, IDENTITY_STACK
        from scripts.dev_owner_enrolled_runtime_readback import _STACK_NAME
        self.delivery = delivery
        self.bootstrap = bootstrap_clients
        self.mapit_authority, self.mapit_state = mapit_authority, mapit_state
        self.mapit_plan, self.mapit_receipt = mapit_plan, mapit_receipt_sha256
        self.synthetic_tenant_keys = tuple(synthetic_tenant_keys)
        self.phase = "pre"
        self.account = delivery.auth["account_id"]
        self.operator = delivery.auth["operator_arn"]
        self.api_id = delivery.auth["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
        self.owner_pool = delivery.auth["owner_pool_id"]
        self.owner_client = delivery.auth["owner_client_id"]
        self.prior = delivery.prior
        self.target = delivery.coordinator.target
        self.archive = delivery.archive
        self.owner_stack = IDENTITY_STACK
        self.owner_stack_id = (
            f"arn:aws:cloudformation:eu-west-1:{self.account}:stack/{self.owner_stack}/"
            "123e4567-e89b-42d3-a456-426614174002")
        self.candidate_stack = "honda-mapit-mcp-dev-owner-oauth"
        self.candidate_stack_id = (
            f"arn:aws:cloudformation:eu-west-1:{self.account}:stack/{self.candidate_stack}/"
            "123e4567-e89b-42d3-a456-426614174001")
        self.artifact_stack = "honda-mapit-mcp-dev-retained-runtime-artifacts"
        self.artifact_stack_id = (
            f"arn:aws:cloudformation:eu-west-1:{self.account}:stack/{self.artifact_stack}/"
            "123e4567-e89b-42d3-a456-426614174003")
        self.domain = DOMAIN
        self._LOGICAL_TYPES = _LOGICAL_TYPES
        self.ids = self._physical_ids(self.prior)
        self.owner_template = build_dev_owner_oauth_template(
            account_id=self.account, api_id=self.api_id, owner_pool_id=self.owner_pool,
            callback_url="http://127.0.0.1:8787/callback")
        self.owner_ids = {
            "McpUserPool": self.owner_pool,
            "McpUserPoolDomain": self.domain,
            "McpUserPoolClient": "prodclient456",
            "McpManagedLoginBranding": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
        self.candidate_ids = {
            "McpResourceServer": self.owner_template["Resources"]["McpResourceServer"]["Properties"]["Identifier"],
            "McpUserPoolClient": self.owner_client,
            "McpManagedLoginBranding": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        }
        self.artifact_bucket = delivery.auth["artifact_bucket"]
        from tests.owner_enrolled_artifact_fixture import ArtifactResponses
        self.artifact_responses = ArtifactResponses(delivery.auth, {
            delivery.auth["prior_zip_sha256"]: 100,
            delivery.coordinator.zip_sha: len(self.archive),
        })
        self.original_run_id = 7
        self.calls = []
        self._clients = {}
        self._responses = {}
        # The bundle factory validates service/region/endpoint/TLS metadata.
        for name, (service, region, endpoint) in _CLIENT_ENDPOINTS.items():
            client_type = type(f"_{name.title()}ReadClient", (SimpleNamespace,), {
                "__getattr__": lambda obj, method, n=name: self._method(n, method)})
            client = client_type(
                meta=SimpleNamespace(service_model=SimpleNamespace(service_name=service),
                    region_name=region, endpoint_url=endpoint,
                    config=SimpleNamespace(retries={"mode": "standard", "total_max_attempts": 1},
                        signature_version="v4", proxies={}, connect_timeout=2, read_timeout=3)),
                _endpoint=SimpleNamespace(http_session=SimpleNamespace(_verify=True)))
            self._clients[name] = client

    def clients(self):
        return self._clients

    def _physical_ids(self, template):
        values = {
            "McpApi": self.api_id,
            "McpApiStage": "$default",
            "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
            "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
            "McpHandler": "honda-mapit-mcp-dev-retained-handler",
            "McpUserPool": "eu-west-1_Technical12345",
            "McpUserPoolClient": "technicalclient123456",
            "McpUserPoolDomain": f"honda-mapit-mcp-dev-multiuser-{self.account}",
            "McpResourceServer": f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp",
            "McpManagedLoginBranding": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff",
            "McpTenantsTable": "honda-mapit-mcp-dev-tenants",
            "McpJwtAuthorizer": "ownerjwt123",
            "McpLambdaIntegration": "ownerint123",
            "McpPostRoute": "ownerpost123",
            "McpProtectedResourceMetadataRoute": "ownermeta123",
            "McpAuthorizationServerMetadataRoute": "ownerserver123",
            "McpLambdaInvokePermission": "ownerinvoke123",
            "McpProtectedResourceMetadataInvokePermission": "ownermetainvoke123",
            "McpAuthorizationServerMetadataInvokePermission": "ownerserverinvoke123",
        }
        return {name: values.get(name, f"physical-{name}") for name in template["Resources"]}

    def _rows(self, template, *, stack_id, stack_name, physical=None):
        physical = physical or self._physical_ids(template)
        return [{"LogicalResourceId": name, "PhysicalResourceId": physical[name],
                 "ResourceType": resource["Type"], "ResourceStatus": "UPDATE_COMPLETE",
                 "StackId": stack_id, "StackName": stack_name}
                for name, resource in template["Resources"].items()]

    def _ok(self, **body):
        return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def _method(self, service, method):
        def call(**kwargs):
            self.calls.append((service, method, copy.deepcopy(kwargs)))
            return self._dispatch(service, method, kwargs)
        return call

    def _dispatch(self, service, method, kw):
        artifact_reply = self.artifact_responses.dispatch(service, method, kw)
        if artifact_reply is not None:
            return artifact_reply
        from datetime import datetime, timezone
        from botocore.exceptions import ClientError
        from scripts.dev_owner_enrolled_runtime_readback import _resolve
        from scripts.dev_mapit_bootstrap_contract import build_plan
        from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
        from scripts.dev_mapit_bootstrap_coordinator import STACK_NAME as MAPIT_STACK
        from scripts.run_dev_mapit_binding_key_setup import CONFIG_PARAMETER, OPERATOR_ROLE_NAME
        from scripts.dev_owner_enrolled_runtime_readback import _AUTH_TABLE, _HANDLER, _ROLE, _REGION, _STACK_NAME

        def missing(code="ParameterNotFound", status=400):
            raise ClientError({"Error": {"Code": code, "Message": "not found"},
                               "ResponseMetadata": {"HTTPStatusCode": status}}, method)

        if service == "sts" and method == "get_caller_identity":
            return self._ok(Account=self.account, Arn=self.operator)
        if service == "cloudformation":
            name = kw.get("StackName")
            if name == MAPIT_STACK:
                return getattr(self.bootstrap["cloudformation"], method)(**kw)
            if method == "describe_stacks":
                if name in {_STACK_NAME, self.delivery.auth["stack_id"]}:
                    template = self.target if self.phase == "accepted" else self.prior
                    return self._ok(Stacks=[{"StackName": _STACK_NAME,
                        "StackId": self.delivery.auth["stack_id"], "StackStatus": "UPDATE_COMPLETE",
                        "EnableTerminationProtection": True,
                        "RoleARN": self.delivery.auth["service_role_arn"],
                        "Tags": [{"Key": k, "Value": v} for k, v in {
                            "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev",
                            "OperatorRunId": "7"}.items()]}])
                if name == self.artifact_stack:
                    return self._ok(Stacks=[{"StackName": self.artifact_stack,
                        "StackId": self.artifact_stack_id, "StackStatus": "CREATE_COMPLETE",
                        "EnableTerminationProtection": True, "RoleARN": None,
                        "Tags": [{"Key": k, "Value": v} for k, v in {
                            "Project": "honda-mapit-mcp", "Environment": "dev",
                            "Purpose": "retained-dev-artifacts", "OperatorRunId": "8"}.items()]}])
                if name == self.owner_stack:
                    return self._ok(Stacks=[{"StackName": self.owner_stack, "StackId": self.owner_stack_id,
                        "StackStatus": "UPDATE_COMPLETE", "EnableTerminationProtection": True}])
                if name == self.candidate_stack:
                    return self._ok(Stacks=[{"StackName": self.candidate_stack,
                        "StackId": self.candidate_stack_id, "StackStatus": "UPDATE_COMPLETE",
                        "EnableTerminationProtection": True}])
            if method == "get_template":
                if name == MAPIT_STACK:
                    return getattr(self.bootstrap["cloudformation"], method)(**kw)
                if name in {_STACK_NAME, self.delivery.auth["stack_id"]}:
                    return self._ok(TemplateBody=self.target if self.phase == "accepted" else self.prior)
                if name in {self.owner_stack, self.owner_stack_id}:
                    return self._ok(TemplateBody={"Resources": {"McpUserPool": {"Type": "AWS::Cognito::UserPool"}}})
                if name in {self.candidate_stack, self.candidate_stack_id}:
                    return self._ok(TemplateBody=self.owner_template)
            if method == "describe_stack_resources":
                if name == MAPIT_STACK:
                    return getattr(self.bootstrap["cloudformation"], method)(**kw)
                if name in {_STACK_NAME, self.delivery.auth["stack_id"]}:
                    template = self.target if self.phase == "accepted" else self.prior
                    return self._ok(StackResources=self._rows(template, stack_id=self.delivery.auth["stack_id"],
                        stack_name=_STACK_NAME))
                if name == self.artifact_stack:
                    return self._ok(StackResources=[
                        {"LogicalResourceId": "RuntimeArtifactBucket", "PhysicalResourceId": self.artifact_bucket,
                         "ResourceType": "AWS::S3::Bucket", "ResourceStatus": "CREATE_COMPLETE",
                         "StackId": self.artifact_stack_id, "StackName": self.artifact_stack},
                        {"LogicalResourceId": "RuntimeArtifactBucketPolicy", "PhysicalResourceId": self.artifact_bucket,
                         "ResourceType": "AWS::S3::BucketPolicy", "ResourceStatus": "CREATE_COMPLETE",
                         "StackId": self.artifact_stack_id, "StackName": self.artifact_stack}])
            if method == "list_stack_resources":
                if name in {self.owner_stack, self.owner_stack_id}:
                    return self._ok(StackResourceSummaries=self._rows_owner_stack())
                if name in {self.candidate_stack, self.candidate_stack_id}:
                    return self._ok(StackResourceSummaries=self._rows_candidate_stack())
                if name in {_STACK_NAME, self.delivery.auth["stack_id"]}:
                    template = self.target if self.phase == "accepted" else self.prior
                    rows = self._rows(template, stack_id=self.delivery.auth["stack_id"], stack_name=_STACK_NAME)
                    return self._ok(StackResourceSummaries=rows)
            if method == "describe_stack_events" and name == MAPIT_STACK:
                return getattr(self.bootstrap["cloudformation"], method)(**kw)
            if method == "describe_stack_events" and name == self.delivery.auth["stack_id"]:
                stack = self.delivery.auth["stack_id"]
                token = "owner-enrolled-" + self.delivery.auth["run_id"]
                return self._ok(StackEvents=[{"ClientRequestToken": token, "StackId": stack,
                    "StackName": _STACK_NAME, "LogicalResourceId": _STACK_NAME,
                    "PhysicalResourceId": stack, "ResourceType": "AWS::CloudFormation::Stack",
                    "ResourceStatus": "UPDATE_COMPLETE",
                    "Timestamp": datetime.fromtimestamp(self.delivery.auth["execution_start_epoch"] + 10,
                        tz=timezone.utc)}])
        if service == "dynamodb":
            table_name = kw.get("TableName", "")
            if table_name == MAPIT_STACK or kw.get("ResourceArn", "").endswith(":table/" + MAPIT_STACK):
                return getattr(self.bootstrap["dynamodb"], method)(**kw)
            if method == "describe_table" and table_name == _AUTH_TABLE:
                props = self.prior["Resources"]["McpTenantsTable"]["Properties"]
                return self._ok(Table={"TableName": _AUTH_TABLE,
                    "TableArn": f"arn:aws:dynamodb:{_REGION}:{self.account}:table/{_AUTH_TABLE}",
                    "TableStatus": "ACTIVE", "BillingModeSummary":{"BillingMode":props["BillingMode"]},
                    "OnDemandThroughput":props["OnDemandThroughput"], "KeySchema":props["KeySchema"],
                    "AttributeDefinitions":props["AttributeDefinitions"], "DeletionProtectionEnabled":True,
                    "SSEDescription":None, "TableId":"33333333-3333-4333-8333-333333333333",
                    "GlobalSecondaryIndexes":[], "LocalSecondaryIndexes":[]})
            if method == "list_tags_of_resource" and table_name == "":
                if kw["ResourceArn"].endswith(":table/" + MAPIT_STACK):
                    return getattr(self.bootstrap["dynamodb"], method)(**kw)
                return self._ok(Tags=[{"Key":k,"Value":v} for k,v in {
                    "Project":"honda-mapit-mcp","Environment":"dev","Purpose":"multiuser-authorization",
                    "OperatorRunId":"7"}.items()])
            if method == "get_item":
                key = kw["Key"]["key"]["S"]
                if key == "identity-bindings-v1":
                    return getattr(self.bootstrap["dynamodb"], method)(**kw)
                if key == self.delivery.auth["owner_tenant_key"]:
                    return self._ok(Item={"key":{"S":key},"status":{"S":"active"},"revision":{"N":"1"}})
                if key == self.delivery.auth["historical_tenant_keys"][0]:
                    return self._ok(Item={"key":{"S":key},"status":{"S":"revoked"},"revision":{"N":"6"}})
                if key == self.delivery.auth["historical_tenant_keys"][1]:
                    return self._ok(Item={"key":{"S":key},"status":{"S":"active"},"revision":{"N":"1"}})
                raise AssertionError("unexpected tenant key")
            if method == "describe_time_to_live":
                return self._ok(TimeToLiveDescription={"TimeToLiveStatus":"DISABLED"})
            if method == "describe_continuous_backups":
                return self._ok(ContinuousBackupsDescription={"ContinuousBackupsStatus":"ENABLED",
                    "PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"DISABLED"}})
        if service == "iam":
            role_name = kw.get("RoleName")
            if role_name != _ROLE:
                reply = getattr(self.bootstrap["iam"], method)(**kw)
                if method == "get_role_policy" and isinstance(reply, dict):
                    reply = dict(reply)
                    reply.update(RoleName=role_name, PolicyName=kw["PolicyName"])
                return reply
            template = self.target if self.phase == "accepted" else self.prior
            props = template["Resources"]["McpHandlerRole"]["Properties"]
            rows = self._rows(template, stack_id=self.delivery.auth["stack_id"], stack_name=_STACK_NAME)
            rowmap = {row["LogicalResourceId"]: row for row in rows}
            table_arn = f"arn:aws:dynamodb:{_REGION}:{self.account}:table/{_AUTH_TABLE}"
            if method == "get_role":
                return self._ok(Role={"RoleName":_ROLE,"Arn":f"arn:aws:iam::{self.account}:role/{_ROLE}",
                    "Path":"/","PermissionsBoundary":None,
                    "AssumeRolePolicyDocument":_resolve(props["AssumeRolePolicyDocument"],account=self.account,
                        rows=rowmap,table_arn=table_arn)})
            names = [item["PolicyName"] for item in props["Policies"]]
            synthetic = build_dev_identity_binding_bootstrap(account_id=self.account,
                operator_user_arn=self.operator,tenant_keys=self.synthetic_tenant_keys,
                ssm_key_arn=self.mapit_authority.ssm_key_arn)["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
            mapit = self.mapit_plan.template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
            policies = {item["PolicyName"]:_resolve(item["PolicyDocument"],account=self.account,
                rows=rowmap,table_arn=table_arn) for item in props["Policies"]}
            policies[synthetic["PolicyName"]] = synthetic["PolicyDocument"]
            policies[mapit["PolicyName"]] = _resolve(mapit["PolicyDocument"],account=self.account,
                rows=rowmap,table_arn=table_arn)
            if method == "list_role_policies":
                return self._ok(PolicyNames=names+[synthetic["PolicyName"],mapit["PolicyName"]],IsTruncated=False)
            if method == "list_attached_role_policies":
                return self._ok(AttachedPolicies=[],IsTruncated=False)
            if method == "get_role_policy":
                policy_name = kw["PolicyName"]
                return self._ok(RoleName=_ROLE,PolicyName=policy_name,PolicyDocument=policies[policy_name])
        if service == "ssm":
            name = kw.get("Name", "")
            if method == "describe_parameters":
                parameter_path = kw["ParameterFilters"][0]["Values"][0]
                return self._ok(Parameters=[{"Name":parameter_path,"Type":"SecureString","Version":1,
                    "Tier":"Standard","DataType":"text","KeyId":"alias/aws/ssm",
                    "LastModifiedUser":f"arn:aws:sts::{self.account}:assumed-role/{OPERATOR_ROLE_NAME}/mapit-key-{self.publication_state['run_id']}",
                    "LastModifiedDate":datetime.fromtimestamp(self.mapit_state["readback_receipt"]["table_created_at_utc"] if False else 1_800_000_020,tz=timezone.utc),"Policies":[]}])
            if method == "get_parameter":
                missing()
        if service == "kms" and method == "describe_key":
            return getattr(self.bootstrap["kms"], method)(**kw)
        if service == "cognito":
            return self._cognito(method, kw)
        if service == "apigatewayv2":
            return self._api(method, kw)
        if service == "lambda":
            return self._lambda(method, kw)
        if service == "s3":
            return self._s3(method, kw)
        raise AssertionError(f"unexpected fake operation: {service}.{method}")

    def _rows_owner_stack(self):
        return [{"LogicalResourceId":name,"PhysicalResourceId":physical,
                 "ResourceType":"AWS::Cognito::Resource","ResourceStatus":"CREATE_COMPLETE"}
                for name,physical in self.owner_ids.items()]

    def _rows_candidate_stack(self):
        return [{"LogicalResourceId":name,"PhysicalResourceId":physical,
                 "ResourceType":self.owner_template["Resources"][name]["Type"],"ResourceStatus":"CREATE_COMPLETE"}
                for name,physical in self.candidate_ids.items()]

    def _cognito(self, method, kw):
        from datetime import datetime, timezone
        from scripts.dev_owner_oauth_sdk import DOMAIN
        from scripts.dev_owner_enrolled_runtime_readback import _resolve
        if method == "describe_user_pool":
            pool_id=kw["UserPoolId"]
            if pool_id != self.owner_pool:
                return self._ok(UserPool={"Id":pool_id,"Name":"honda-mapit-mcp-dev-multiuser",
                    "Arn":f"arn:aws:cognito-idp:eu-west-1:{self.account}:userpool/{pool_id}",
                    "MfaConfiguration":"OFF","DeletionProtection":"ACTIVE",
                    "AdminCreateUserConfig":{"AllowAdminCreateUserOnly":True},"UserPoolTier":"ESSENTIALS",
                    "UserPoolTags":{"Project":"honda-mapit-mcp","Environment":"dev",
                        "Purpose":"retained-dev","OperatorRunId":"7",
                        "aws:cloudformation:stack-id":self.delivery.auth["stack_id"],
                        "aws:cloudformation:stack-name":"honda-mapit-mcp-dev-retained",
                        "aws:cloudformation:logical-id":"McpUserPool"}})
            return self._ok(UserPool={"Id":pool_id,
                "Arn":f"arn:aws:cognito-idp:eu-west-1:{self.account}:userpool/{pool_id}",
                "Name":"honda-mapit-mcp-identity","MfaConfiguration":"ON","DeletionProtection":"ACTIVE",
                "AdminCreateUserConfig":{"AllowAdminCreateUserOnly":True},"UserPoolTier":"ESSENTIALS"})
        if method == "get_user_pool_mfa_config":
            return self._ok(MfaConfiguration="ON",SoftwareTokenMfaConfiguration={"Enabled":True},SmsConfiguration={"Enabled":False})
        if method == "describe_user_pool_domain":
            pool= self.owner_pool if kw["Domain"] == DOMAIN else self.ids["McpUserPool"]
            return self._ok(DomainDescription={"Domain":kw["Domain"],"UserPoolId":pool,
                "AWSAccountId":self.account,"Status":"ACTIVE","ManagedLoginVersion":2})
        if method == "list_user_pool_clients":
            return self._ok(UserPoolClients=[{"ClientId":"prodclient456"},{"ClientId":self.owner_client}])
        if method == "describe_user_pool_client":
            client=kw["ClientId"]
            if client == self.owner_client:
                props=self.owner_template["Resources"]["McpUserPoolClient"]["Properties"]
                return self._ok(UserPoolClient={**props,"ClientId":client,"CreationDate":datetime.fromtimestamp(1_800_000_020,tz=timezone.utc)})
            if client != "technicalclient123456":
                return self._ok(UserPoolClient={"ClientId":client,"UserPoolId":self.owner_pool,
                    "ClientName":"existing","AllowedOAuthScopes":["https://production.example/mcp/use"]})
            from scripts.run_dev_multiuser_hosted_acceptance import CALLBACK_URL
            resource_uri=f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
            return self._ok(UserPoolClient={"UserPoolId":"eu-west-1_Technical12345",
                "ClientId":client,"AllowedOAuthFlowsUserPoolClient":True,"AllowedOAuthFlows":["code"],
                "AllowedOAuthScopes":[resource_uri+"/use"],"CallbackURLs":[CALLBACK_URL],
                "DefaultRedirectURI":CALLBACK_URL,"SupportedIdentityProviders":["COGNITO"],
                "EnableTokenRevocation":True,"PreventUserExistenceErrors":"ENABLED",
                "AccessTokenValidity":60,"IdTokenValidity":60,"RefreshTokenValidity":30,
                "TokenValidityUnits":{"AccessToken":"minutes","IdToken":"minutes","RefreshToken":"days"}})
        if method == "describe_resource_server":
            if kw["UserPoolId"] == self.owner_pool:
                template = self.owner_template
                resource=template["Resources"].get("McpResourceServer")
                if resource:
                    return self._ok(ResourceServer=resource["Properties"])
            else:
                template = self.prior
            resource=template["Resources"].get("McpResourceServer")
            if resource:
                return self._ok(ResourceServer={"UserPoolId":kw["UserPoolId"],
                    "Identifier":kw["Identifier"],"Name":"honda-mapit-mcp-identity",
                    "Scopes":[{"ScopeName":"use","ScopeDescription":"Read-only MCP access."}]})
            return self._ok(ResourceServer={"UserPoolId":kw["UserPoolId"],"Identifier":kw["Identifier"],
                "Name":"honda-mapit-mcp-identity","Scopes":[{"ScopeName":"use","ScopeDescription":"Read-only MCP access."}]})
        if method == "describe_managed_login_branding_by_client":
            client=kw["ClientId"]
            return self._ok(ManagedLoginBranding={"ManagedLoginBrandingId":self.candidate_ids["McpManagedLoginBranding"] if client==self.owner_client else self.ids["McpManagedLoginBranding"],
                "UserPoolId":kw["UserPoolId"],"ClientId":client,"UseCognitoProvidedValues":True})
        raise AssertionError(method)

    def _api(self, method, kw):
        from scripts.dev_owner_enrolled_runtime_readback import _resolve
        template=self.target if self.phase=="accepted" else self.prior
        rows=self._rows(template,stack_id=self.delivery.auth["stack_id"],stack_name="honda-mapit-mcp-dev-retained")
        rowmap={row["LogicalResourceId"]:row for row in rows}
        table_arn=f"arn:aws:dynamodb:eu-west-1:{self.account}:table/honda-mapit-mcp-dev-tenants"
        props=template["Resources"]
        if method == "get_api":
            return self._ok(ApiId=self.api_id,Name="honda-mapit-mcp-dev-retained-api",ProtocolType="HTTP",
                DisableExecuteApiEndpoint=True,ApiEndpoint=f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com")
        if method == "get_authorizers":
            auth=props["McpJwtAuthorizer"]["Properties"]
            return self._ok(Items=[{"AuthorizerId":self.ids["McpJwtAuthorizer"],"AuthorizerType":"JWT",
                "Name":auth["Name"],"IdentitySource":auth["IdentitySource"],
                "JwtConfiguration":_resolve(auth["JwtConfiguration"],account=self.account,rows=rowmap,table_arn=table_arn)}])
        if method == "get_routes":
            result=[]
            for logical in ("McpPostRoute","McpProtectedResourceMetadataRoute","McpAuthorizationServerMetadataRoute"):
                prop=props[logical]["Properties"]
                auth_type=prop["AuthorizationType"]
                route={"RouteId":rowmap[logical]["PhysicalResourceId"],
                    "RouteKey":prop["RouteKey"],"AuthorizationType":auth_type,
                    "Target":"integrations/ownerint123"}
                scopes=_resolve(prop.get("AuthorizationScopes"),account=self.account,rows=rowmap,table_arn=table_arn)
                if scopes is not None:
                    route["AuthorizationScopes"]=scopes
                if auth_type=="JWT":
                    route["AuthorizerId"]=self.ids["McpJwtAuthorizer"]
                result.append(route)
            return self._ok(Items=result)
        if method == "get_integrations":
            item=_resolve(props["McpLambdaIntegration"]["Properties"],account=self.account,rows=rowmap,table_arn=table_arn)
            item.pop("ApiId", None)
            return self._ok(Items=[{"IntegrationId":"ownerint123",**item}])
        raise AssertionError(method)

    def _lambda(self, method, kw):
        from scripts.dev_owner_enrolled_runtime_readback import _resolve, _HANDLER, _ROLE
        template=self.target if self.phase=="accepted" else self.prior
        rows=self._rows(template,stack_id=self.delivery.auth["stack_id"],stack_name="honda-mapit-mcp-dev-retained")
        rowmap={row["LogicalResourceId"]:row for row in rows}
        table_arn=f"arn:aws:dynamodb:eu-west-1:{self.account}:table/honda-mapit-mcp-dev-tenants"
        props=template["Resources"]
        handler_properties = copy.deepcopy(props["McpHandler"]["Properties"])
        if handler_properties.get("Role") == {"Fn::GetAtt": ["McpHandlerRole", "Arn"]}:
            handler_properties["Role"] = f"arn:aws:iam::{self.account}:role/{_ROLE}"
        handler=_resolve(handler_properties,account=self.account,rows=rowmap,table_arn=table_arn)
        import base64
        code_sha=self.delivery.coordinator.zip_sha if self.phase=="accepted" else self.delivery.auth["prior_zip_sha256"]
        if method == "get_function_concurrency": return self._ok(ReservedConcurrentExecutions=0)
        if method == "get_account_settings": return self._ok(AccountLimit={"ConcurrentExecutions":10,"UnreservedConcurrentExecutions":10})
        if method == "get_function_configuration":
            return self._ok(FunctionName=_HANDLER,FunctionArn=f"arn:aws:lambda:eu-west-1:{self.account}:function:{_HANDLER}",
                Role=f"arn:aws:iam::{self.account}:role/honda-mapit-mcp-dev-retained-handler-role",
                State="Active",LastUpdateStatus="Successful",CodeSha256=base64.b64encode(bytes.fromhex(code_sha)).decode("ascii"),
                Handler=handler["Handler"],Runtime=handler["Runtime"],Architectures=handler.get("Architectures"),
                Timeout=handler["Timeout"],MemorySize=handler["MemorySize"],Environment=handler["Environment"])
        if method == "get_function": return self._ok(Configuration={
            "FunctionArn":f"arn:aws:lambda:eu-west-1:{self.account}:function:{_HANDLER}",
            "Role":f"arn:aws:iam::{self.account}:role/{_ROLE}",
            "CodeSha256":base64.b64encode(bytes.fromhex(code_sha)).decode("ascii")})
        if method == "get_policy":
            statements=[]
            for logical in ("McpLambdaInvokePermission","McpProtectedResourceMetadataInvokePermission","McpAuthorizationServerMetadataInvokePermission"):
                p=_resolve(props[logical]["Properties"],account=self.account,rows=rowmap,table_arn=table_arn)
                statements.append({"Sid":logical,"Effect":"Allow","Action":p["Action"],
                    "Resource":f"arn:aws:lambda:eu-west-1:{self.account}:function:{_HANDLER}",
                    "Principal":{"Service":p["Principal"]},"Condition":{"ArnLike":{"AWS:SourceArn":p["SourceArn"]},
                    "StringEquals":{"AWS:SourceAccount":p["SourceAccount"]}}})
            return self._ok(Policy=json.dumps({"Version":"2012-10-17","Statement":statements}))
        raise AssertionError(method)

    def _s3(self, method, kw):
        from scripts.dev_owner_enrolled_runtime_readback import _ARTIFACT_STACK
        from scripts.dev_owner_enrolled_runtime_readback import _canonical
        bucket=self.artifact_bucket
        body={
            "get_public_access_block":{"PublicAccessBlockConfiguration":{"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True}},
            "get_bucket_encryption":{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}},
            "get_bucket_ownership_controls":{"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}},
            "get_bucket_versioning":{},"get_bucket_location":{"LocationConstraint":"eu-west-1"},
            "get_bucket_policy_status":{"PolicyStatus":{"IsPublic":False}},
            "get_bucket_tagging":{"TagSet":[{"Key":"Project","Value":"honda-mapit-mcp"},{"Key":"Environment","Value":"dev"},{"Key":"Purpose","Value":"retained-dev-artifacts"},{"Key":"OperatorRunId","Value":"8"}]},
            "get_bucket_lifecycle_configuration":{"Rules":[{"ID":"DevTerminalJournalRetention","Status":"Enabled","Filter":{"And":{"Prefix":"journals/","Tags":[{"Key":"cd-terminal","Value":"true"}]}},"Expiration":{"Days":30}}]},
            "get_bucket_policy":{"Policy":{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransportForThisBucketOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":[f"arn:aws:s3:::{bucket}",f"arn:aws:s3:::{bucket}/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}},
        }
        if method == "head_object":
            import base64
            sha=kw["Key"].split("/")[1].split(".")[0]
            return self._ok(ContentLength=len(self.archive) if sha==self.delivery.coordinator.zip_sha else 100,
                ChecksumSHA256=base64.b64encode(bytes.fromhex(sha)).decode("ascii"),
                ServerSideEncryption="AES256",ContentType="application/zip")
        return self._ok(**body[method])
