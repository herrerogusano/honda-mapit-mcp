from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from scripts.dev_mapit_bootstrap_contract import build_plan, make_authority
from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator
from scripts.run_aws_retained_dev_bootstrap import validate_authorization
from scripts.run_dev_mapit_bootstrap import ci_evidence_digest
from scripts.run_dev_mapit_binding_key_setup import (
    _ReadClient, _digest, _validate_key_clients, _verify_current_bootstrap, run_authorized_step,
)
from tests.test_dev_mapit_bootstrap_coordinator import _coordinator


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-mapit-operator"
SOURCE = "a" * 40
START = 1_800_000_000


def _write_json(path: Path, value):
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _inputs(root: Path):
    bootstrap_dir = root / "old-bootstrap"
    bootstrap_dir.mkdir()
    synthetic_dir = root / "old-synthetic"
    synthetic_dir.mkdir()
    fresh_dir = root / "fresh-publication"
    fresh_dir.mkdir()
    config_path = root / "config.json"
    _write_json(config_path, {
        "region": "eu-west-1", "user_pool_id": "eu-west-1_Abcdefghi",
        "user_pool_client_id": "SyntheticClient123",
        "identity_pool_id": "eu-west-1:12345678-1234-4234-8234-123456789abc",
        "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
        "frontend_url": "https://app.mapit.me/", "discovery_enabled": False, "http_timeout": 2,
    })
    github = {"github_owner_id": 12, "github_repository_id": 34}
    source_auth = validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER, "source_sha": SOURCE,
        "ci_run_id": 77, "run_id": 11, "start": START, "end": START + 600,
    })
    authority = make_authority(
        account_id=ACCOUNT, operator_user_arn=CALLER, source_sha=SOURCE, run_id=11,
        expected_caller_arn=CALLER, authorized_from_epoch=START, authorized_until_epoch=START + 600,
        ci_evidence_sha256=ci_evidence_digest(source_auth, github), runtime_evidence_sha256="b" * 64,
        ssm_key_arn=f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
        tenant_keys=("tenant-" + "1" * 64,), excluded_tenant_keys=("tenant-" + "2" * 64, "tenant-" + "3" * 64),
    )
    authority_path = root / "authority.json"
    raw = {
        "account_id": authority.account_id, "operator_user_arn": authority.operator_user_arn,
        "source_sha": authority.source_sha, "run_id": authority.run_id,
        "expected_caller_arn": authority.expected_caller_arn,
        "authorized_from_epoch": authority.authorized_from_epoch,
        "authorized_until_epoch": authority.authorized_until_epoch,
        "ci_evidence_sha256": authority.ci_evidence_sha256,
        "runtime_evidence_sha256": authority.runtime_evidence_sha256,
        "ssm_key_arn": authority.ssm_key_arn,
        "tenant_keys": list(authority._tenant_keys), "excluded_tenant_keys": list(authority._excluded_tenant_keys),
    }
    _write_json(authority_path, {"schema": 1, "kind": "dev-mapit-bootstrap-runner",
                                 "authority": raw, "source_authorization": source_auth, "github": github})
    auth_path = root / "fresh-auth.json"
    auth = validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER, "source_sha": SOURCE,
        "ci_run_id": 78, "run_id": 12, "start": START, "end": START + 600,
    })
    _write_json(auth_path, auth)
    return {
        "authorization_path": auth_path, "bootstrap_authority_path": authority_path,
        "bootstrap_state_dir": bootstrap_dir, "runtime_evidence_path": root / "runtime.json",
        "synthetic_binding_path": root / "synthetic-binding.json",
        "synthetic_authorization_path": root / "synthetic-auth.json",
        "synthetic_state_dir": synthetic_dir, "config_path": config_path,
        "publication_state_dir": fresh_dir,
    }


def test_fresh_source_and_protection_gates_precede_client_construction(tmp_path):
    args = _inputs(tmp_path)
    calls = []

    def command_runner(command, **kwargs):
        calls.append(tuple(command))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def source_validator(_auth, *, command_runner):
        command_runner(["source-gate"])

    def protection_validator(_binding, *, command_runner):
        command_runner(["protection-gate"])

    def no_clients():
        raise AssertionError("clients must not be constructed after failed source gate")

    result = run_authorized_step(
        **args, acl_checker=lambda _path: True,
        source_validator=source_validator, protection_validator=protection_validator,
        client_factory=no_clients, command_runner=command_runner,
        clock=lambda: START + 10, monotonic=lambda: 1.0,
    )
    assert result == {"step": "publish", "ok": False, "category": "clients_invalid",
                      "calls": 0, "command_calls": 2}
    assert calls == [("source-gate",), ("protection-gate",)]
    assert not list(args["publication_state_dir"].glob("*.json"))


def test_fresh_source_may_advance_beyond_historical_bootstrap_source(tmp_path):
    args = _inputs(tmp_path)
    _write_json(args["authorization_path"], validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER, "source_sha": "c" * 40,
        "ci_run_id": 79, "run_id": 13, "start": START, "end": START + 600,
    }))
    invoked = []
    result = run_authorized_step(
        **args, acl_checker=lambda _path: True,
        source_validator=lambda *_a, **_k: None,
        protection_validator=lambda *_a, **_k: None,
        client_factory=lambda: invoked.append(True) or {},
        clock=lambda: START + 10, monotonic=lambda: 1.0,
    )
    assert result["category"] == "clients_invalid"
    assert invoked == [True]


def test_publication_state_cannot_alias_historical_state(tmp_path):
    args = _inputs(tmp_path)
    args["publication_state_dir"] = args["synthetic_state_dir"]
    calls = []
    result = run_authorized_step(
        **args, acl_checker=lambda _path: True,
        source_validator=lambda *_a, **_k: calls.append("source"),
        protection_validator=lambda *_a, **_k: calls.append("protections"),
        client_factory=lambda: calls.append("clients"),
        clock=lambda: START + 10, monotonic=lambda: 1.0,
    )
    assert result["ok"] is False
    assert result["category"] == "authorization_invalid"
    assert calls == []


def test_key_client_contract_is_exact_and_read_proxy_counts_failed_dispatch():
    def fake(service):
        return SimpleNamespace(
            meta=SimpleNamespace(service_model=SimpleNamespace(service_name=service), region_name="eu-west-1",
                endpoint_url=f"https://{service}.eu-west-1.amazonaws.com",
                config=SimpleNamespace(retries={"total_max_attempts": 1}, signature_version="v4",
                    proxies={}, connect_timeout=2, read_timeout=2)),
            _endpoint=SimpleNamespace(http_session=SimpleNamespace(_verify=True)),
        )

    clients = {"sts": fake("sts"), "ssm": fake("ssm")}
    _validate_key_clients(clients)
    with pytest.raises(ValueError):
        _validate_key_clients({"sts": clients["sts"], "ssm": clients["ssm"], "iam": object()})
    calls = [0, 0]

    class Failing:
        def get_caller_identity(self):
            raise RuntimeError("private-canary")

    proxy = _ReadClient(Failing(), calls, 1.0, 10.0, lambda: 2.0,
                        lambda: START + 10, START, START + 600, [float(START)])
    try:
        proxy.get_caller_identity()
    except RuntimeError:
        pass
    assert calls[0] == 1


def _accepted_coordinator_state():
    coordinator, journal, _cfn, ddb, iam = _coordinator()
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["ok"] is True
    ddb.created = iam.created = True
    accepted = coordinator.run_step("readback")
    assert accepted["ok"] is True, accepted
    policy_name = coordinator.plan.template["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyName"]
    original_get_policy = iam.get_role_policy

    def get_role_policy(*, RoleName, PolicyName):
        reply = original_get_policy(RoleName=RoleName, PolicyName=PolicyName)
        return {**reply, "RoleName": RoleName, "PolicyName": PolicyName}

    iam.get_role_policy = get_role_policy
    iam.list_role_policies = lambda **_kwargs: {
        "PolicyNames": [policy_name], "IsTruncated": False,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    return coordinator, journal.state


def _verify_current(coordinator, state):
    authority, plan = coordinator.authority, coordinator.plan
    receipt_digest = _digest({
        "authority_sha256": authority._binding_sha256,
        "intent": state["intent"], "readback_receipt": state["readback_receipt"],
        "template_sha256": plan.template_sha256,
    })
    count = [0, 99.0]
    tick = [99.0]

    def monotonic():
        tick[0] += 0.01
        return tick[0]

    clients = {name: _ReadClient(client, count, 99.0, 120.0, monotonic,
                                lambda: START + 10, START, START + 600, [float(START)])
               for name, client in coordinator.clients.items()}
    _verify_current_bootstrap(clients, authority, state, plan, receipt_digest,
                              count, 99.0, 120.0, monotonic)
    return count[0]


def test_current_bootstrap_readback_accepts_sdk_shaped_coordinator_receipt():
    coordinator, state = _accepted_coordinator_state()
    assert _verify_current(coordinator, state) >= 10


def test_current_bootstrap_readback_rejects_unknown_table_tag():
    coordinator, state = _accepted_coordinator_state()
    coordinator.clients["dynamodb"].extra_tags["unexpected-owner-tag"] = "value"
    with pytest.raises(ValueError):
        _verify_current(coordinator, state)


def test_complete_runner_uses_fresh_auth_and_one_assumed_role_publication(tmp_path):
    from scripts.build_aws_dev_mapit_binding_bootstrap import OPERATOR_ROLE_NAME
    from scripts.run_aws_closed_rehearsal import FileJournal
    from tests.test_dev_mapit_bootstrap_coordinator import Clock, Journal, _callbacks, _clients
    from tests.test_dev_mapit_binding_key_setup import _SSM, _STS
    from scripts.run_dev_mapit_bootstrap import KIND

    args = _inputs(tmp_path)
    github = {"github_owner_id": 12, "github_repository_id": 34}
    old_auth = validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER, "source_sha": SOURCE,
        "ci_run_id": 77, "run_id": 33, "start": START - 500, "end": START + 50,
    })
    authority = make_authority(
        account_id=ACCOUNT, operator_user_arn=CALLER, source_sha=SOURCE, run_id=33,
        expected_caller_arn=CALLER, authorized_from_epoch=START - 500, authorized_until_epoch=START + 50,
        ci_evidence_sha256=ci_evidence_digest(old_auth, github), runtime_evidence_sha256="b" * 64,
        ssm_key_arn=f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
        tenant_keys=("tenant-" + "1" * 64,), excluded_tenant_keys=("tenant-" + "2" * 64, "tenant-" + "3" * 64),
    )
    plan = build_plan(authority)
    clients, _cfn, ddb, iam = _clients(plan)
    source_cb, protection_cb, runtime_cb = _callbacks(authority)
    journal = Journal()
    bootstrap_clock = Clock()
    coordinator = MapitBootstrapCoordinator(
        clients, journal, authority=authority, fresh_source=source_cb,
        fresh_protections=protection_cb, closed_runtime_verifier=runtime_cb,
        wall_clock=bootstrap_clock.time, monotonic=bootstrap_clock.monotonic,
    )
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["ok"] is True
    ddb.created = iam.created = True
    accepted = coordinator.run_step("readback")
    assert accepted["ok"] is True, accepted
    policy_name = plan.template["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyName"]
    original_get_policy = iam.get_role_policy

    def get_role_policy(*, RoleName, PolicyName):
        reply = original_get_policy(RoleName=RoleName, PolicyName=PolicyName)
        return {**reply, "RoleName": RoleName, "PolicyName": PolicyName}

    iam.get_role_policy = get_role_policy
    iam.list_role_policies = lambda **_kwargs: {
        "PolicyNames": [policy_name], "IsTruncated": False,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    bootstrap_state_dir = args["bootstrap_state_dir"]
    (bootstrap_state_dir / "rehearsal-state.json").write_text(
        json.dumps(journal.state, sort_keys=True, separators=(",", ":")), encoding="ascii")
    raw_authority = {
        "account_id": authority.account_id, "operator_user_arn": authority.operator_user_arn,
        "source_sha": authority.source_sha, "run_id": authority.run_id,
        "expected_caller_arn": authority.expected_caller_arn,
        "authorized_from_epoch": authority.authorized_from_epoch,
        "authorized_until_epoch": authority.authorized_until_epoch,
        "ci_evidence_sha256": authority.ci_evidence_sha256,
        "runtime_evidence_sha256": authority.runtime_evidence_sha256,
        "ssm_key_arn": authority.ssm_key_arn, "tenant_keys": list(authority._tenant_keys),
        "excluded_tenant_keys": list(authority._excluded_tenant_keys),
    }
    _write_json(args["bootstrap_authority_path"], {
        "schema": 1, "kind": KIND, "authority": raw_authority,
        "source_authorization": old_auth, "github": github,
    })
    _write_json(args["authorization_path"], validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER, "source_sha": "c" * 40,
        "ci_run_id": 78, "run_id": 32, "start": START, "end": START + 600,
    }))
    clients["sts"].assume_role = lambda **_kwargs: {
        "Credentials": {"AccessKeyId": "access-placeholder", "SecretAccessKey": "secret-placeholder",
                        "SessionToken": "session-placeholder",
                        "Expiration": __import__("datetime").datetime.fromtimestamp(START + 900, tz=__import__("datetime").timezone.utc)},
        "AssumedRoleUser": {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{OPERATOR_ROLE_NAME}/mapit-key-32"},
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    key_clients = {"sts": _STS(), "ssm": _SSM()}
    runtime_proof = {
        "verified": True, "calls": 32, "phase": "readback", "account_id": ACCOUNT,
        "source_sha": authority.source_sha, "run_id": authority.run_id,
        "caller_arn": CALLER, "evidence_sha256": authority.runtime_evidence_sha256,
        "resource_count": 19, "api_closed": True, "reserve_zero": True,
        "mapit_policy_attached": True,
    }

    result = run_authorized_step(
        **args, acl_checker=lambda _path: True,
        source_validator=lambda *_a, **_k: None,
        protection_validator=lambda *_a, **_k: None,
        client_factory=lambda: clients,
        assume_role_client_factory=lambda _credentials, wall_clock: key_clients,
        runtime_verifier_factory=lambda **_kwargs: lambda *_a, **_k: runtime_proof,
        clock=lambda: START + 100, monotonic=lambda: 100.0,
    )
    assert result["ok"] is True, result
    assert result["category"] == "key_publication_verified"
    assert result["calls"] > 20
    publication = FileJournal(args["publication_state_dir"]).load()
    assert publication["phase"] == "accepted"
    assert publication["bootstrap_sha256"] == _digest({
        "authority_sha256": authority._binding_sha256, "intent": journal.state["intent"],
        "readback_receipt": journal.state["readback_receipt"], "template_sha256": plan.template_sha256,
    })
    assert len([row for row in key_clients["ssm"].calls if row[0] == "put"]) == 1
