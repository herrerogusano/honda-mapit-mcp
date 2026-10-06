from __future__ import annotations

import json
import time

import pytest

from scripts import run_aws_retained_dev_proof_bootstrap as runner
from tests.test_aws_retained_dev_proof_bootstrap import (
    ACCOUNT,
    CALLER,
    SOURCE,
    CloudFormation,
    Iam,
    Sts,
    _bindings,
    build_cd_retained_dev_proof_role,
)


def test_binding_loader_requires_exact_unique_private_shape(tmp_path):
    path = tmp_path / "bindings.json"
    path.write_text(json.dumps({key: "fixture" for key in runner._BINDING_FIELDS}), encoding="utf-8")
    assert set(runner._load_bindings(path)) == set(runner._BINDING_FIELDS)
    path.write_text('{"account_id":"a","account_id":"b"}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="bindings_file_invalid"):
        runner._load_bindings(path)


def test_runner_rejects_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    with pytest.raises(RuntimeError, match="proxy_or_custom_endpoint_rejected"):
        runner._build_clients()


def test_file_journal_adapter_is_real_cas_and_uuid_is_deterministic(tmp_path):
    adapter = runner.FileCasJournal(runner.FileJournal(tmp_path))
    state = {
        "schema": 1,
        "kind": "retained-dev-proof-role",
        "revision": 1,
        "binding_sha256": "b" * 64,
        "source_sha": "a" * 40,
        "run_id": "12345678-1234-4234-8234-123456789abc",
        "template_sha256": "c" * 64,
        "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:role/retained-dev-executor",
        "authorized_from_epoch": 1_893_455_000,
        "authorized_until_epoch": 1_893_458_000,
        "last_observed_epoch": 1_893_456_100,
        "preflight": True,
        "intent": None,
        "acknowledged": False,
        "acknowledged_stack_id": None,
        "readback": False,
        "readback_receipt": None,
    }
    with adapter.locked():
        assert adapter.load() is None
        assert adapter.compare_and_set(None, state)
        assert adapter.compare_and_set(1, {**state, "revision": 3}) is False
    first = runner._operation_uuid("a" * 40, 2026100601)
    assert first == runner._operation_uuid("a" * 40, 2026100601)
    assert first != runner._operation_uuid("a" * 40, 2026100602)


def test_default_runner_filejournal_adapter_completes_private_synthetic_flow(tmp_path):
    auth_path = tmp_path / "authorization.json"
    bindings_path = tmp_path / "bindings.json"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    auth_run_id = 2026100601
    now = int(time.time())
    authorization = {
        "account": ACCOUNT,
        "source_sha": SOURCE,
        "run_id": auth_run_id,
        "expected_caller_arn": CALLER,
        "start": now - 60,
        "end": now + 3540,
        "ci_run_id": 123456789,
    }
    bindings = _bindings()
    auth_path.write_text(json.dumps(authorization), encoding="utf-8")
    bindings_path.write_text(json.dumps(bindings), encoding="utf-8")

    operation = runner._operation_uuid(SOURCE, auth_run_id)
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-readonly-proof/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    template = build_cd_retained_dev_proof_role(**bindings)
    cfn = CloudFormation(template, run_id=operation, stack=stack)
    clients = {"sts": Sts(), "cloudformation": cfn, "iam": Iam(template, cfn)}
    kwargs = {
        "authorization_path": auth_path,
        "bindings_path": bindings_path,
        "state_dir": state_dir,
        "acl_checker": lambda path: True,
        "source_ci_validator": lambda value: None,
        "client_factory": lambda: clients,
    }
    assert runner.run_authorized_step(step="preflight", **kwargs)["category"] == "preflight_verified"
    assert runner.run_authorized_step(step="create", **kwargs)["category"] == "create_acknowledged"
    assert runner.run_authorized_step(step="readback", **kwargs)["category"] == "readback_verified"
    assert sum(name == "create_stack" for name, _ in cfn.calls) == 1
