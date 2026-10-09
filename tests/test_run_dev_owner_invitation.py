import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from mapit.durable_tenants import DurableTenantRecord
from scripts import run_dev_owner_invitation as invitation
from scripts.run_aws_closed_rehearsal import MemoryJournal


def _binding(state_dir, *, start=1_900_000_000, end=1_900_000_600):
    return {
        "schema": 1, "kind": invitation.KIND, "account_id": "123456789012",
        "operator_user_arn": "arn:aws:iam::123456789012:user/operator",
        "source_sha": "a" * 40, "ci_run_id": 123, "run_id": 7,
        "authorized_from_epoch": start, "authorized_until_epoch": end,
        "github_owner_id": 11, "github_repository_id": 22,
        "owner_context_sha256": "b" * 64,
        "owner_oauth_stack_id": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-identity/" + "1" * 8 + "-" + "2" * 4 + "-" + "3" * 4 + "-" + "4" * 4 + "-" + "5" * 12,
        "owner_oauth_client_id": "C" * 20,
        "mapit_bootstrap_authority_sha256": "c" * 64,
        "mapit_bootstrap_receipt_sha256": "d" * 64,
        "runtime_evidence_sha256": "e" * 64,
        "owner_tenant_key": "tenant-" + "f" * 64,
        "state_directory": str(Path(state_dir).resolve()),
    }


def test_invitation_authority_requires_exact_schema_window_and_private_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    good = _binding(state)
    assert invitation._validate_authority(good, state_dir=state) == good
    for mutate in (
        lambda x: x.update(extra=True),
        lambda x: x.update(authorized_until_epoch=x["authorized_from_epoch"] + 601),
        lambda x: x.update(run_id=True),
        lambda x: x.update(state_directory=str(tmp_path / "other")),
        lambda x: x.update(owner_tenant_key="tenant-" + "a" * 63),
    ):
        changed = dict(good)
        mutate(changed)
        with pytest.raises(ValueError):
            invitation._validate_authority(changed, state_dir=state)


def test_private_preparation_uses_fresh_source_and_parser_only_client_shapes(tmp_path, monkeypatch):
    private = tmp_path / "private"
    private.mkdir()
    state = private / "new-state"
    state.mkdir()
    owner_state = private / "owner-state"
    owner_state.mkdir()
    mapit_state = private / "mapit-state"
    mapit_state.mkdir()
    synthetic_state = private / "synthetic-state"
    synthetic_state.mkdir()
    files = {}
    for name in ("owner-auth.json", "owner-binding.json", "owner-release.json",
                 "mapit-authority.json"):
        path = private / name
        path.write_text("{}")
        files[name] = path
    authorization_path = private / "authorization.json"
    owner_auth = {"account": "123456789012", "expected_caller_arn": "arn:aws:iam::123456789012:user/operator",
        "source_sha": "1" * 40, "run_id": 9, "start": 1_800_000_000,
        "end": 1_800_000_600, "ci_run_id": 99}
    owner_context = SimpleNamespace(account="123456789012", operator=owner_auth["expected_caller_arn"],
        context_digest="b" * 64, stack_id=_binding(state)["owner_oauth_stack_id"],
        policy=SimpleNamespace(client_id="C" * 20), github_owner_id=11, github_repository_id=22)
    mapit_authority = SimpleNamespace(account_id="123456789012",
        expected_caller_arn=owner_auth["expected_caller_arn"], _tenant_keys=("tenant-" + "f" * 64,),
        _binding_sha256="c" * 64, runtime_evidence_sha256="e" * 64)
    plan = SimpleNamespace(template={})
    monkeypatch.setattr(invitation, "load_authorization", lambda _: owner_auth)
    monkeypatch.setattr(invitation, "_load_owner_binding", lambda *_a, **_k: {})
    monkeypatch.setattr(invitation, "load_trusted_owner_policy", lambda *_a, **_k: object())
    monkeypatch.setattr(invitation, "parse_accepted_owner_login_context", lambda *_a, **_k: owner_context)
    monkeypatch.setattr(invitation, "FileJournal", lambda _: SimpleNamespace(load=lambda: {"accepted": True}))
    captured = {}
    def load_bootstrap(_authority_path, _state_dir, clients, **_kwargs):
        invitation._validate_clients(clients)
        captured["client_count"] = len(clients)
        return mapit_authority, {}, {}, {"accepted": True}, plan, "d" * 64
    monkeypatch.setattr(invitation, "_load_accepted_bootstrap", load_bootstrap)
    seen = []
    def source(auth):
        seen.append(auth)
        assert auth["source_sha"] == "a" * 40
        assert auth["source_sha"] != owner_auth["source_sha"]
    result = invitation.prepare_private_authorization(
        authorization_path, state, source_sha="a" * 40, ci_run_id=123,
        owner_release_receipt=files["owner-release.json"],
        owner_oauth_authorization_path=files["owner-auth.json"],
        owner_oauth_binding_path=files["owner-binding.json"], owner_oauth_state_dir=owner_state,
        mapit_bootstrap_authority_path=files["mapit-authority.json"],
            mapit_bootstrap_state_dir=mapit_state, synthetic_state_dir=synthetic_state,
        acl_checker=lambda _: True,
        source_validator=source, protection_reader=lambda **kwargs: (11, 22),
        wall_clock=lambda: 1_900_000_000, run_id_factory=lambda: "9" * 32,
    )
    assert result["ok"] is True, result
    assert result["category"] == "invitation_authority_prepared"
    assert captured == {"client_count": 9}
    assert len(seen) == 1
    value = json.loads(authorization_path.read_text())
    assert value["owner_tenant_key"] == mapit_authority._tenant_keys[0]
    assert value["source_sha"] == "a" * 40 and value["authorized_until_epoch"] == 1_900_000_600
    assert "owner_subject" not in value and "refresh_token" not in value


class _Dynamo:
    def __init__(self, *, fail_put=False, commit_then_fail=False):
        self.item = None
        self.calls = []
        self.fail_put = fail_put
        self.commit_then_fail = commit_then_fail

    def get_item(self, **kwargs):
        self.calls.append(("get", kwargs))
        response = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.item is not None:
            response["Item"] = self.item
        return response

    def put_item(self, **kwargs):
        self.calls.append(("put", kwargs))
        self.item = dict(kwargs["Item"])
        if self.fail_put or self.commit_then_fail:
            error = RuntimeError("sensitive provider text")
            error.response = {"Error": {"Code": "Timeout", "Message": "private"}}
            raise error
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class _SourceClients:
    def __init__(self, ddb, *, api_status=200, lambda_status=200, reserve=0):
        self.ddb = ddb
        self.sts = SimpleNamespace(get_caller_identity=lambda: {
            "Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/operator",
            "ResponseMetadata": {"HTTPStatusCode": 200}})
        self.api = SimpleNamespace(get_api=lambda **kwargs: {
            "ApiId": kwargs.get("ApiId"), "DisableExecuteApiEndpoint": True,
            "ResponseMetadata": {"HTTPStatusCode": api_status}})
        self.lambda_client = SimpleNamespace(get_function_concurrency=lambda **kwargs: {
            "ReservedConcurrentExecutions": reserve, "ResponseMetadata": {"HTTPStatusCode": lambda_status}})
    def mapping(self):
        return {
            "sts": self.sts, "cloudformation": object(), "iam": object(), "dynamodb": self.ddb,
            "ssm": object(), "cognito": object(), "apigatewayv2": self.api,
            "lambda": self.lambda_client, "kms": object(),
        }


def _make_paths(tmp_path):
    private = tmp_path / "private"
    private.mkdir()
    state = private / "new-state"
    state.mkdir()
    owner_state = private / "owner-state"
    owner_state.mkdir()
    mapit_state = private / "mapit-state"
    mapit_state.mkdir()
    synthetic_state = private / "synthetic-state"
    synthetic_state.mkdir()
    files = {}
    for name in ("authority.json", "owner-auth.json", "owner-binding.json", "owner-release.json",
                 "mapit-authority.json", "runtime.json", "synthetic-binding.json", "synthetic-auth.json"):
        path = private / name
        path.write_text("{}")
        files[name] = path
    return private, state, owner_state, mapit_state, synthetic_state, files


def _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, owner_key):
    owner_auth = {"account": "123456789012", "expected_caller_arn": "arn:aws:iam::123456789012:user/operator",
        "source_sha": "1" * 40, "run_id": 9, "start": 1_800_000_000, "end": 1_800_000_600, "ci_run_id": 9}
    context = SimpleNamespace(account="123456789012", operator=owner_auth["expected_caller_arn"],
        context_digest="b" * 64, stack_id=_binding(owner_state)["owner_oauth_stack_id"],
        policy=SimpleNamespace(client_id="C" * 20, api_id="a" * 10), github_owner_id=11, github_repository_id=22)
    mapit = SimpleNamespace(account_id="123456789012", expected_caller_arn=owner_auth["expected_caller_arn"],
        source_sha="1" * 40, run_id=8, _binding_sha256="c" * 64,
        runtime_evidence_sha256="e" * 64, _tenant_keys=(owner_key,))
    state = {"acknowledged_stack_id": "accepted"}
    plan = SimpleNamespace(template={"Resources": {}})
    monkeypatch.setattr(invitation, "load_authorization", lambda _: owner_auth)
    monkeypatch.setattr(invitation, "_load_owner_binding", lambda *_a, **_k: {})
    monkeypatch.setattr(invitation, "load_trusted_owner_policy", lambda *_a, **_k: object())
    monkeypatch.setattr(invitation, "parse_accepted_owner_login_context", lambda *_a, **_k: context)
    monkeypatch.setattr(invitation, "_load_accepted_bootstrap", lambda *_a, **_k: (
        mapit, {}, {}, state, plan, "d" * 64))
    monkeypatch.setattr(invitation, "verify_current_context", lambda *_a: True)
    monkeypatch.setattr(invitation, "_verify_current_bootstrap", lambda *_a: None)
    return context, mapit, state, plan


def _runtime_proof():
    return {"verified": True, "calls": 20, "phase": "readback", "account_id": "123456789012",
        "source_sha": "1" * 40, "run_id": 8, "caller_arn": "arn:aws:iam::123456789012:user/operator",
        "evidence_sha256": "e" * 64, "resource_count": 19, "api_closed": True,
        "reserve_zero": True, "mapit_policy_attached": True}


@pytest.mark.parametrize("fail_put,commit_then_fail", [(True, False), (False, True)])
def test_one_shot_unknown_cas_is_fenced_and_redacted(tmp_path, monkeypatch, fail_put, commit_then_fail):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    ddb = _Dynamo(fail_put=fail_put, commit_then_fail=commit_then_fail)
    clients = _SourceClients(ddb).mapping()
    journal = MemoryJournal()
    proof = _runtime_proof()
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal, wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1200)).__next__,
    )
    assert result["ok"] is False and result["category"] == "write_outcome_unknown", result
    assert "sensitive" not in repr(result)
    assert [name for name, _ in ddb.calls].count("put") == 1
    assert ddb.calls[0][1]["ConsistentRead"] is True
    assert all(call[1]["TableName"] ==
               "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants"
               for call in ddb.calls)
    assert journal.value["phase"] == "write_outcome_unknown"
    assert journal.value["write_dispatched"] is True
    replay = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal, wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(2000, 2200)).__next__,
    )
    assert replay["ok"] is False and replay["category"] == "journal_consumed"
    assert [name for name, _ in ddb.calls].count("put") == 1


def test_cached_owner_row_conflicts_before_any_write(tmp_path, monkeypatch):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    ddb = _Dynamo()
    ddb.item = {"key": {"S": binding["owner_tenant_key"]}, "status": {"S": "active"}, "revision": {"N": "1"}}
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: _SourceClients(ddb).mapping(),
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: _runtime_proof(),
        journal_factory=lambda _: MemoryJournal(), wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1200)).__next__,
    )
    assert result["ok"] is False and result["category"] == "invitation_conflict", result
    assert [name for name, _ in ddb.calls].count("put") == 0


def test_source_gate_failure_precedes_sdk_construction(tmp_path):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    calls = []
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: calls.append("client") or {},
        source_validator=lambda _: (_ for _ in ()).throw(ValueError("sensitive")),
        protection_reader=lambda **_: calls.append("protection"),
    )
    assert result["ok"] is False and result["category"] == "source_ci_failed"
    assert calls == []


def test_positive_invitation_is_single_owner_cas_with_exact_readback(tmp_path, monkeypatch):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    ddb = _Dynamo()
    clients = _SourceClients(ddb).mapping()
    proof = _runtime_proof()
    journal = MemoryJournal()
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal, wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1500)).__next__,
    )
    assert result["ok"] is True and result["category"] == "owner_invitation_accepted", result
    assert [name for name, _ in ddb.calls].count("put") == 1
    assert len([call for call in ddb.calls if call[0] == "get"]) == 3
    assert ddb.item == {
        "key": {"S": binding["owner_tenant_key"]},
        "status": {"S": "active"},
        "revision": {"N": "1"},
    }
    assert {call[1]["TableName"] for call in ddb.calls} == {
        "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants"
    }
    assert journal.value["phase"] == "invitation_accepted"
    assert journal.value["readback_verified"] is True
    assert binding["owner_tenant_key"] in journal.value["owner_key"]


def test_default_client_factory_freezes_one_explicit_credential_tuple_for_all_clients(monkeypatch):
    from botocore.config import Config

    for name in list(os.environ):
        if name.casefold().startswith("aws_") and any(
                marker in name.casefold() for marker in invitation._CREDENTIAL_ENV_MARKERS):
            monkeypatch.delenv(name, raising=False)

    class Credentials:
        def __init__(self):
            self.freeze_calls = 0
        def get_frozen_credentials(self):
            self.freeze_calls += 1
            return SimpleNamespace(access_key="AKIAEXAMPLE", secret_key="secret-canary",
                                   token="session-canary")

    class Session:
        def __init__(self, **kwargs):
            assert kwargs == {"region_name": invitation.REGION}
            self.credentials = Credentials()
            self.requests = []
        def get_credentials(self):
            return self.credentials
        def client(self, service, **kwargs):
            self.requests.append((service, kwargs))
            return object()

    session = Session(region_name=invitation.REGION)
    fake_boto3 = SimpleNamespace(Session=lambda **kwargs: session)
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
    clients = invitation._default_clients()
    assert set(clients) == set(invitation._ENDPOINTS)
    assert session.credentials.freeze_calls == 1
    assert len(session.requests) == 9
    for _service, kwargs in session.requests:
        assert kwargs["aws_access_key_id"] == "AKIAEXAMPLE"
        assert kwargs["aws_secret_access_key"] == "secret-canary"
        assert kwargs["aws_session_token"] == "session-canary"
        assert kwargs["verify"] is True
        config = kwargs["config"]
        assert isinstance(config, Config)
        assert config.signature_version == "v4" and config.proxies == {}
        assert config.retries["total_max_attempts"] == 1


@pytest.mark.parametrize("env_name", ["AWS_ACCESS_KEY_ID", "AWS_CONFIG_FILE", "BOTO_CONFIG"])
def test_default_client_factory_rejects_ambient_credential_environment_before_session(monkeypatch, env_name):
    called = []
    monkeypatch.setenv(env_name, "canary")
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=lambda **_: called.append(True)))
    with pytest.raises(invitation.OwnerInvitationError) as exc:
        invitation._default_clients()
    assert exc.value.category == "client_setup_failed"
    assert called == []


def test_preparation_rejects_fresh_state_nested_in_synthetic_history(tmp_path, monkeypatch):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    owner_key = "tenant-" + "f" * 64
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, owner_key)
    nested_state = synthetic_state / "new-attempt"
    nested_state.mkdir()
    destination = private / "nested-authority.json"
    result = invitation.prepare_private_authorization(
        destination, nested_state, source_sha="a" * 40, ci_run_id=123,
        owner_release_receipt=files["owner-release.json"],
        owner_oauth_authorization_path=files["owner-auth.json"],
        owner_oauth_binding_path=files["owner-binding.json"], owner_oauth_state_dir=owner_state,
        mapit_bootstrap_authority_path=files["mapit-authority.json"],
        mapit_bootstrap_state_dir=mapit_state, synthetic_state_dir=synthetic_state,
        acl_checker=lambda _: True, source_validator=lambda _: None,
        protection_reader=lambda **_: (11, 22), wall_clock=lambda: 1_900_000_000,
        run_id_factory=lambda: "8" * 32)
    assert result["ok"] is False and result["category"] == "invitation_authority_unverified"
    assert not destination.exists()


def test_preparation_rejects_authority_file_nested_in_synthetic_history(tmp_path, monkeypatch):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, "tenant-" + "f" * 64)
    nested_parent = synthetic_state / "new-authority"
    nested_parent.mkdir()
    destination = nested_parent / "authorization.json"
    result = invitation.prepare_private_authorization(
        destination, state, source_sha="a" * 40, ci_run_id=123,
        owner_release_receipt=files["owner-release.json"],
        owner_oauth_authorization_path=files["owner-auth.json"],
        owner_oauth_binding_path=files["owner-binding.json"], owner_oauth_state_dir=owner_state,
        mapit_bootstrap_authority_path=files["mapit-authority.json"],
        mapit_bootstrap_state_dir=mapit_state, synthetic_state_dir=synthetic_state,
        acl_checker=lambda _: True, source_validator=lambda _: None,
        protection_reader=lambda **_: (11, 22), wall_clock=lambda: 1_900_000_000,
        run_id_factory=lambda: "7" * 32)
    assert result["ok"] is False and result["category"] == "invitation_authority_unverified"
    assert not destination.exists()


def test_exclusive_authority_write_retains_partial_file_as_consumed_path(tmp_path, monkeypatch):
    target = tmp_path / "authority.json"
    monkeypatch.setattr(invitation.os, "fsync", lambda _fd: (_ for _ in ()).throw(OSError("canary")))
    with pytest.raises(OSError):
        invitation._exclusive_write(target, b'{"safe":true}')
    assert target.exists()
    with pytest.raises(ValueError):
        invitation._exclusive_write(target, b'{"replacement":true}')


def test_guarded_clients_refuse_second_put_even_after_first_response():
    ddb = _Dynamo()
    raw = _SourceClients(ddb).mapping()
    guard = invitation._GuardedClients(raw, owner_key="tenant-" + "f" * 64,
        account_id="123456789012", start=1_900_000_000, end=1_900_000_600,
        wall_clock=lambda: 1_900_000_001, monotonic=iter(range(1000, 1100)).__next__)
    clients = guard.wrap()
    guard.armed = True
    request = {
        "TableName": "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants",
        "Item": {"key": {"S": guard.owner_key}, "status": {"S": "active"}, "revision": {"N": "1"}},
        "ConditionExpression": "attribute_not_exists(#key)", "ExpressionAttributeNames": {"#key": "key"},
        "ReturnValues": "NONE", "ReturnConsumedCapacity": "NONE",
    }
    clients["dynamodb"].put_item(**request)
    with pytest.raises(ValueError):
        clients["dynamodb"].put_item(**request)
    assert [name for name, _ in ddb.calls].count("put") == 1


def test_accepted_owner_context_repository_ids_must_match_authority_before_clients(tmp_path, monkeypatch):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    context, *_ = _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state,
                                           binding["owner_tenant_key"])
    context.github_owner_id = 999
    client_calls = []
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: client_calls.append(True),
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        journal_factory=lambda _: MemoryJournal(), wall_clock=lambda: binding["authorized_from_epoch"] + 1)
    assert result["ok"] is False and result["category"] == "accepted_receipt_invalid"
    assert client_calls == []


@pytest.mark.parametrize("api_status,lambda_status,reserve", [(500, 200, 0), (200, 200.0, 0), (200, 200, False)])
def test_bad_closed_control_response_shapes_fence_cas(tmp_path, monkeypatch, api_status, lambda_status, reserve):
    private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    ddb = _Dynamo()
    journal = MemoryJournal()
    clients = _SourceClients(ddb, api_status=api_status, lambda_status=lambda_status,
                             reserve=reserve).mapping()
    proof = _runtime_proof()
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda _: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal, wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1500)).__next__)
    assert result["ok"] is False and result["category"] == "current_state_unverified"
    assert journal.value["phase"] == "intent_saved"
    assert [name for name, _ in ddb.calls].count("put") == 0
