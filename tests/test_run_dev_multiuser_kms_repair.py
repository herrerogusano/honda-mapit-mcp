from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import scripts.run_dev_multiuser_kms_repair as repair
from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.dev_multiuser_closed_update import _digest

ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
APP = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ROLES = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666"
KEY = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/33333333-4444-4555-8666-777777777777"
TOKEN = "dev-multiuser-" + "b" * 32
OLD_TOKEN = "dev-multiuser-" + "a" * 32
SOURCE = "b" * 40
OLD_SOURCE = "a" * 40
POOL = "eu-west-1_AbCdEfG123"


def _bindings():
    subject = "repo:herrerogusano/honda-mapit-mcp:environment:dev"
    return {
        "account_id": ACCOUNT,
        "provider_arn": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
        "owner_id": "123", "repository_id": "456",
        "observed_dev_subject_format": "legacy_environment",
        "observed_dev_subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
        "stack_arn": APP,
        "artifact_stack_arn": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/44444444-5555-4666-8777-888888888888",
        "handler_arn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler",
        "api_arn": "arn:aws:apigateway:eu-west-1::/apis/abcdefghij",
        "shutdown_state_machine_arn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown",
        "artifact_bucket_arn": f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1",
        "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
    }


def _prior_setup():
    return build_retained_dev_multiuser_setup(
        api_id="abcdefghij", callback_url="http://localhost:39031/callback")


def _old_state(prior=None, *, token=OLD_TOKEN, source=OLD_SOURCE, start=1_900_000_000, end=1_900_000_300):
    prior = prior or _prior_setup()
    return {"phase": "acknowledged", "binding": {
        "schema": 1, "operation": "dev_multiuser_closed_update", "account": ACCOUNT,
        "caller": CALLER, "stack": APP,
        "role": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
        "source": source, "start": start, "end": end, "token": token,
        "prior": _digest(prior), "target": "c" * 64,
    }}


def test_failed_event_key_requires_exact_old_token_stack_and_single_key():
    rows = [
        {"ClientRequestToken": OLD_TOKEN, "LogicalResourceId": "McpHandler",
         "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_FAILED",
         "StackId": APP, "ResourceStatusReason": f"KMS key {KEY} was not authorized"},
        {"ClientRequestToken": OLD_TOKEN, "LogicalResourceId": "honda-mapit-mcp-dev-retained",
         "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "UPDATE_ROLLBACK_COMPLETE",
         "StackId": APP},
    ]
    assert repair._extract_event_key(rows, old_token=OLD_TOKEN, app_stack_arn=APP, account=ACCOUNT) == KEY
    for mutate in (
        lambda x: x[0].update(ClientRequestToken=TOKEN),
        lambda x: x[0].update(StackId=ROLES),
        lambda x: x[0].update(ResourceStatusReason=f"{KEY} and {KEY}"),
    ):
        bad = copy.deepcopy(rows)
        mutate(bad)
        with pytest.raises(repair.KmsRepairError):
            repair._extract_event_key(bad, old_token=OLD_TOKEN, app_stack_arn=APP, account=ACCOUNT)


def test_old_consumed_journal_is_bound_to_prior_source_token_and_fresh_window():
    prior = _prior_setup()
    valid = _old_state(prior)
    assert repair._old_runtime_evidence(valid, account=ACCOUNT, caller_arn=CALLER,
        app_stack_arn=APP, prior_setup=prior, new_start=1_900_000_301,
        new_token=TOKEN) == (OLD_TOKEN, OLD_SOURCE)
    bad_values = [
        _old_state(prior, start=1_900_000_301, end=1_900_000_600),
        _old_state(prior, end=1_900_000_301, token=TOKEN),
        _old_state(prior, start=True),
        _old_state(prior, start=1, end=8_000),
    ]
    wrong_prior = copy.deepcopy(valid)
    wrong_prior["binding"]["prior"] = "d" * 64
    bad_values.append(wrong_prior)
    for state in bad_values:
        with pytest.raises(repair.KmsRepairError):
            repair._old_runtime_evidence(state, account=ACCOUNT, caller_arn=CALLER,
                app_stack_arn=APP, prior_setup=prior, new_start=1_900_000_301,
                new_token=TOKEN)


def test_kms_alias_accepts_only_enabled_same_account_aws_managed_key():
    class Client:
        def __init__(self, metadata): self.metadata = metadata
        def describe_key(self, **kwargs):
            assert kwargs == {"KeyId": "alias/aws/lambda"}
            return {"KeyMetadata": self.metadata, "ResponseMetadata": {"HTTPStatusCode": 200}}

    metadata = {"Arn": KEY, "KeyManager": "AWS", "KeyState": "Enabled",
        "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT",
        "Origin": "AWS_KMS", "MultiRegion": False, "Enabled": True}
    assert repair._kms_alias({"kms": Client(metadata)}, account=ACCOUNT) == KEY
    for key, value in (("KeyManager", "CUSTOMER"), ("KeyState", "Disabled"),
                       ("MultiRegion", True), ("Enabled", 1),
                       ("Arn", KEY.replace(ACCOUNT, "210987654321"))):
        changed = dict(metadata); changed[key] = value
        with pytest.raises(repair.KmsRepairError):
            repair._kms_alias({"kms": Client(changed)}, account=ACCOUNT)


def test_role_templates_change_only_cfn_role_and_boundary():
    bindings = _bindings()
    prior = repair._role_templates(bindings, pool_id=POOL, key_arn=None)
    target = repair._role_templates(bindings, pool_id=POOL, key_arn=KEY)
    repair._verify_templates(prior, target)
    wrong = copy.deepcopy(target)
    wrong["Resources"]["RetainedDevCdExecutorRole"]["Properties"]["RoleName"] = "changed"
    with pytest.raises(repair.KmsRepairError):
        repair._verify_templates(prior, wrong)
    wrong = copy.deepcopy(target)
    wrong["Metadata"]["NoRuntimeTenantWrites"] = False
    with pytest.raises(repair.KmsRepairError):
        repair._verify_templates(prior, wrong)


@pytest.mark.parametrize("phase", ["pending", "accepted"])
def test_check_update_defers_target_role_readback_until_acceptance(monkeypatch, phase):
    prior = _prior_setup()
    roles_binding = _bindings()
    fake_roles = {"Resources": {
        "RetainedDevCdExecutorRole": {}, "RetainedDevCdExecutorBoundary": {},
        "RetainedDevCdCloudFormationRole": {}, "RetainedDevCdCloudFormationBoundary": {},
    }, "Metadata": {}}
    event_rows = [
        {"ClientRequestToken": OLD_TOKEN, "LogicalResourceId": "McpHandler",
         "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_FAILED",
         "StackId": APP, "ResourceStatusReason": KEY},
        {"ClientRequestToken": OLD_TOKEN, "LogicalResourceId": "honda-mapit-mcp-dev-retained",
         "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "UPDATE_ROLLBACK_COMPLETE",
         "StackId": APP},
    ]

    class Sts:
        def get_caller_identity(self):
            return {"Account": ACCOUNT, "Arn": CALLER, "ResponseMetadata": {"HTTPStatusCode": 200}}
    class Cfn:
        def describe_stack_events(self, **kwargs):
            assert kwargs == {"StackName": APP}
            return {"StackEvents": event_rows, "ResponseMetadata": {"HTTPStatusCode": 200}}
    class Kms:
        def describe_key(self, **kwargs):
            return {"KeyMetadata": {"Arn": KEY, "KeyManager": "AWS", "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "Origin": "AWS_KMS",
                "MultiRegion": False, "Enabled": True}, "ResponseMetadata": {"HTTPStatusCode": 200}}
    clients = {name: object() for name in repair._METHODS}
    clients.update(sts=Sts(), cloudformation=Cfn(), kms=Kms())
    monkeypatch.setattr(repair, "_app_snapshot", lambda *a, **k: (prior, "abcdefghij", POOL))
    monkeypatch.setattr(repair, "_role_templates", lambda *a, **k: fake_roles)
    monkeypatch.setattr(repair, "_verify_templates", lambda *a, **k: None)
    pair_reads = []
    def verify_pair(*args, **kwargs):
        pair_reads.append(True)
        if phase == "pending":
            pytest.fail("partial IAM readback attempted")
        return {"success": True, "category": "role_pair_verified", "calls": 1}
    monkeypatch.setattr(repair, "verify_role_pair", verify_pair)

    class Journal:
        def locked(self): return _NullContext()
        def load(self): return {"binding": {}, "phase": "acknowledged"}
        def save(self, value): pass
    class _NullContext:
        def __enter__(self): return self
        def __exit__(self, *exc): return False
    class Pending:
        def __init__(self, *a, **kw): pass
        def run(self, step):
            assert step == "readback"
            return {"ok": True, "phase": phase}
    monkeypatch.setattr(repair, "ClosedDevUpdate", Pending)
    old = _old_state(prior)
    output = []
    result = repair.run_kms_repair_step(
        clients, step="check-update", journal=Journal(), old_runtime_journal=old,
        account_id=ACCOUNT, caller_arn=CALLER, app_stack_arn=APP,
        app_creation_run_id=2026100601, roles_stack_arn=ROLES,
        roles_creation_run_id=2026100602, role_bindings=roles_binding,
        source_sha=SOURCE, run_token=TOKEN, authorized_from_epoch=1_900_000_301,
        authorized_until_epoch=1_900_003_301, clock=lambda: 1_900_000_400,
        accepted_key_sink=output.append,
    )
    if phase == "pending":
        assert result["category"] == "update_pending"
        assert result["success"] is False and pair_reads == [] and output == []
    else:
        assert result["category"] == "readback_verified"
        assert result["success"] is True and pair_reads == [True] and output == [KEY]
    assert old == _old_state(prior)


def test_cli_check_update_writes_fourteenth_binding_only_after_accepted_result(tmp_path, monkeypatch):
    from scripts import dev_multiuser_journal, run_aws_retained_dev_bootstrap

    base = tmp_path / "private"
    base.mkdir()
    paths = {}
    for name in ("old", "new"):
        paths[name] = base / name
        paths[name].mkdir()
    auth = {"account": ACCOUNT, "source_sha": SOURCE, "run_id": 2026100601,
            "expected_caller_arn": CALLER, "start": 1_900_000_000,
            "end": 1_900_003_600, "ci_run_id": 19}
    auth_path = base / "authorization.json"
    auth_path.write_text(json.dumps(auth), encoding="utf-8")
    bindings = _bindings()
    bindings_path = base / "role-bindings.json"
    bindings_path.write_text(json.dumps(bindings), encoding="utf-8")
    app_path = base / "app-binding.json"
    app_path.write_text(json.dumps({"stack_arn": APP, "original_creation_run_id": 2026100601}), encoding="utf-8")
    roles_path = base / "roles-binding.json"
    roles_path.write_text(json.dumps({"stack_arn": ROLES, "original_creation_run_id": 2026100602}), encoding="utf-8")
    prior = _old_state()
    dev_multiuser_journal.PlainFileJournal(paths["old"]).save(prior)
    old_state_path = paths["old"] / "rehearsal-state.json"
    old_bytes = old_state_path.read_bytes()
    old_lock_path = paths["old"] / "rehearsal-state.lock"
    output_path = base / "accepted-role-bindings.json"
    produced = []
    monkeypatch.setattr(run_aws_retained_dev_bootstrap, "validate_private_location", lambda p, **kw: Path(p).resolve())

    class NewJournal:
        def __init__(self, path): self.path = path

    def accepted_core(clients, **kwargs):
        assert kwargs["step"] == "check-update"
        assert kwargs["old_runtime_journal"] == prior
        assert kwargs["role_bindings"] == bindings
        sink = kwargs["accepted_key_sink"]
        assert callable(sink)
        sink(KEY)
        produced.append(True)
        return {"success": True, "category": "readback_verified", "calls": 23}

    monkeypatch.setattr(repair, "run_kms_repair_step", accepted_core)
    result = repair.run_authorized_step(
        auth_path, bindings_path, app_path, roles_path, paths["old"], paths["new"],
        "check-update", accepted_bindings_path=output_path,
        acl_checker=lambda _path: True, source_ci_validator=lambda _auth: None,
        client_factory=lambda: {"synthetic": object()}, journal_factory=NewJournal,
    )
    assert result == {"success": True, "category": "readback_verified", "calls": 23}
    assert produced == [True]
    output = json.loads(output_path.read_text(encoding="ascii"))
    assert set(output) == set(bindings) | {"lambda_environment_key_arn"}
    assert output["lambda_environment_key_arn"] == KEY
    assert KEY not in json.dumps(result)
    assert old_state_path.read_bytes() == old_bytes
    assert not old_lock_path.exists()

    # A later step may not overwrite the accepted private binding.
    called = []
    blocked = repair.run_authorized_step(
        auth_path, bindings_path, app_path, roles_path, paths["old"], paths["new"],
        "check-update", accepted_bindings_path=output_path,
        acl_checker=lambda _path: True, source_ci_validator=lambda _auth: None,
        client_factory=lambda: called.append(True), journal_factory=NewJournal,
    )
    assert blocked["category"] == "accepted_bindings_path_exists"
    assert called == []


def test_cli_requires_output_only_for_accepted_readback(tmp_path, monkeypatch):
    from scripts import dev_multiuser_journal, run_aws_retained_dev_bootstrap

    base = tmp_path / "private"; base.mkdir()
    old_dir = base / "old"; old_dir.mkdir()
    new_dir = base / "new"; new_dir.mkdir()
    auth = {"account": ACCOUNT, "source_sha": SOURCE, "run_id": 2026100601,
            "expected_caller_arn": CALLER, "start": 1_900_000_000,
            "end": 1_900_003_600, "ci_run_id": 19}
    auth_path = base / "authorization.json"; auth_path.write_text(json.dumps(auth), encoding="utf-8")
    bindings_path = base / "role-bindings.json"; bindings_path.write_text(json.dumps(_bindings()), encoding="utf-8")
    app_path = base / "app-binding.json"; app_path.write_text(json.dumps({"stack_arn": APP, "original_creation_run_id": 2026100601}), encoding="utf-8")
    roles_path = base / "roles-binding.json"; roles_path.write_text(json.dumps({"stack_arn": ROLES, "original_creation_run_id": 2026100602}), encoding="utf-8")
    dev_multiuser_journal.PlainFileJournal(old_dir).save(_old_state())
    monkeypatch.setattr(run_aws_retained_dev_bootstrap, "validate_private_location", lambda p, **kw: Path(p).resolve())
    called = []
    result = repair.run_authorized_step(
        auth_path, bindings_path, app_path, roles_path, old_dir, new_dir,
        "check-update", acl_checker=lambda _path: True,
        source_ci_validator=lambda _auth: None, client_factory=lambda: called.append(True),
    )
    assert result["category"] == "accepted_bindings_path_required"
    assert called == []


def test_private_accepted_bindings_never_overwrites_and_rejects_wrong_account(tmp_path):
    path = tmp_path / "bindings.json"
    bindings = _bindings()
    repair._write_accepted_role_bindings(path, bindings, KEY, acl_checker=lambda _path: True)
    assert json.loads(path.read_text(encoding="ascii"))["lambda_environment_key_arn"] == KEY
    with pytest.raises(repair.KmsRepairError):
        repair._write_accepted_role_bindings(path, bindings, KEY, acl_checker=lambda _path: True)
    other = KEY.replace(ACCOUNT, "210987654321")
    with pytest.raises(repair.KmsRepairError):
        repair._write_accepted_role_bindings(tmp_path / "wrong.json", bindings, other,
                                            acl_checker=lambda _path: True)
