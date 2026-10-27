"""Offline holdouts for the private DEV identity-binding preparation step."""

import json
from pathlib import Path

import pytest

import scripts.prepare_dev_identity_binding_private as preparer
from scripts.dev_multiuser_closed_update import _digest
from scripts.run_dev_multiuser_runtime_update import CasFileJournal


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
STACK = (f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/"
         "12345678-1234-1234-1234-123456789abc")
SOURCE = "a" * 40


def _reply(**payload):
    return {"ResponseMetadata": {"HTTPStatusCode": 200}, **payload}


def _template():
    logicals = ["McpApi", "McpUserPool", "McpUserPoolClient", "McpHandler", "McpHandlerRole",
                "McpTenantsTable", *[f"Synthetic{i}" for i in range(13)]]
    resources = {name: {"Type": "Synthetic::Resource", "Properties": {}} for name in logicals}
    resources["McpHandler"] = {"Type": "AWS::Lambda::Function", "Properties": {
        "Code": {"S3Key": "runtime/" + "a" * 64 + ".zip"},
    }}
    return {"Resources": resources}


class _Client:
    def __init__(self, handlers, calls, name):
        self.handlers, self.calls, self.name = handlers, calls, name

    def __getattr__(self, operation):
        if operation not in self.handlers:
            raise AssertionError(f"unexpected {self.name}.{operation}")

        def call(**kwargs):
            self.calls.append((self.name, operation, kwargs))
            return self.handlers[operation](**kwargs)

        return call


def _context(monkeypatch, tmp_path, *, variants=None, sts_account=ACCOUNT, source_ci=None,
             runtime_verifier=None, clock_value=1_800_000_000, monotonic=None):
    variants = variants or {}
    historical = tmp_path / "accepted"
    parent = tmp_path / "private"
    historical.mkdir()
    parent.mkdir()
    template = _template()
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    policy_names = ["honda-mapit-mcp-dev-retained-owned-log-writes",
                    "honda-mapit-mcp-dev-retained-tenant-read"]
    policies = {name: {"Version": "2012-10-17", "Statement": []} for name in policy_names}
    stack_arn = STACK
    run_id = 827
    physical = {"McpApi": "abcdefghij", "McpUserPool": "eu-west-1_SyntheticPool",
                "McpUserPoolClient": "SyntheticClient123456"}
    physical.update({name: f"physical-{name}" for name in template["Resources"] if name not in physical})
    rows = [{"LogicalResourceId": key, "PhysicalResourceId": value} for key, value in physical.items()]
    template_digest = _digest(template)
    journal = {"phase": "accepted", "binding": {
        "operation": "dev_multiuser_closed_update", "account": ACCOUNT,
        "caller": CALLER, "stack": stack_arn, "target": template_digest,
    }}
    CasFileJournal(historical).save(journal)
    historical_snapshot = {path.name: path.read_bytes() for path in historical.iterdir()}
    calls = []
    repo_calls = []
    source_calls = []
    runtime_inputs = []

    def maybe(name, response):
        value = variants.get(name)
        if callable(value):
            return value(response)
        if isinstance(value, dict):
            response.update(value)
        return response

    handlers = {
        "kms": {"describe_key": lambda **kw: maybe("describe_key", _reply(KeyMetadata={
            "Arn": f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
            "AWSAccountId": ACCOUNT, "KeyManager": "AWS", "Enabled": True,
            "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"}))},
        "sts": {"get_caller_identity": lambda **kw: maybe("sts", _reply(
            Account=sts_account, Arn=CALLER, UserId="synthetic-user"))},
        "cloudformation": {
            "get_template": lambda **kw: maybe("get_template", _reply(TemplateBody=template)),
            "describe_stacks": lambda **kw: maybe("describe_stacks", _reply(Stacks=[{
                "StackId": stack_arn, "StackName": "honda-mapit-mcp-dev-retained",
                "StackStatus": "UPDATE_COMPLETE", "Tags": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "dev"},
                    {"Key": "OperatorRunId", "Value": str(run_id)},
                ],
            }])),
            "list_stack_resources": lambda **kw: maybe("list_stack_resources", _reply(StackResourceSummaries=rows)),
        },
        "iam": {
            "get_role": lambda **kw: maybe("get_role", _reply(Role={
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
                "AssumeRolePolicyDocument": trust,
            })),
            "list_role_policies": lambda **kw: maybe("list_role_policies", _reply(PolicyNames=policy_names)),
            "get_role_policy": lambda **kw: maybe("get_role_policy", _reply(
                RoleName="honda-mapit-mcp-dev-retained-handler-role", PolicyName=kw["PolicyName"],
                PolicyDocument=policies[kw["PolicyName"]])),
        },
    }
    clients = {key: _Client(value, calls, key) for key, value in handlers.items()}

    monkeypatch.setattr(preparer, "_create_private_directory",
                        lambda path, acl_checker=None: (Path(path).mkdir(), Path(path))[1])
    monkeypatch.setattr(preparer, "validate_private_location", lambda path, acl_checker=None: Path(path))

    def read_repo():
        repo_calls.append(1)
        return {"full_name": "herrerogusano/honda-mapit-mcp", "id": 123456,
                "owner": {"id": 654321, "login": "herrerogusano"}}

    def validate_source(auth):
        source_calls.append(dict(auth))

    def verify_runtime(seen_clients, binding):
        runtime_inputs.append(binding)
        return {"verified": True}

    if source_ci is not None:
        validate_source = source_ci
    if runtime_verifier is not None:
        verify_runtime = runtime_verifier
    kwargs = {
        "parent": parent,
        "accepted_runtime_directory": historical,
        "source_sha": SOURCE,
        "ci_run_id": 998877,
        "client_factory": lambda: clients,
        "source_ci_validator": validate_source,
        "acl_checker": lambda path: True,
        "clock": clock_value if callable(clock_value) else (lambda: clock_value),
        "monotonic": monotonic or (lambda: 100.0),
        "runtime_verifier": verify_runtime,
        "repository_reader": read_repo,
    }
    return kwargs, parent, historical, calls, repo_calls, source_calls, runtime_inputs, historical_snapshot


def test_prepare_creates_only_new_private_binding_and_authorization(monkeypatch, tmp_path):
    args, parent, historical, calls, repo_calls, source_calls, runtime_inputs, snapshot = _context(monkeypatch, tmp_path)
    target = preparer.prepare(**args)
    assert target.parent == parent and target.name.startswith("ib-")
    assert {path.name for path in target.iterdir()} == {"authorization.json", "bindings.json", "bootstrap"}
    authorization = json.loads((target / "authorization.json").read_text(encoding="utf-8"))
    binding = json.loads((target / "bindings.json").read_text(encoding="utf-8"))
    assert authorization["account"] == ACCOUNT and authorization["expected_caller_arn"] == CALLER
    assert authorization["end"] - authorization["start"] <= 3600
    assert len(binding["tenant_keys"]) == 2 and len(set(binding["tenant_keys"])) == 2
    assert binding["accepted_runtime_journal_path"].endswith("accepted")
    assert "binding_mac_key" not in binding and "identity_proof_hmac_key" not in binding
    assert len(calls) == 9 and len(repo_calls) == 1 and len(source_calls) == 1 and len(runtime_inputs) == 1
    assert runtime_inputs[0]["tenant_keys"] == binding["tenant_keys"]
    assert {path.name: path.read_bytes() for path in historical.iterdir()} == snapshot


def test_wrong_sts_account_stops_before_repository_or_artifact_creation(monkeypatch, tmp_path):
    args, parent, _, calls, repo_calls, _, _, _ = _context(monkeypatch, tmp_path, sts_account="999999999999")
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert len(calls) == 1 and not repo_calls
    assert list(parent.iterdir()) == []


def test_source_ci_rejection_stops_before_repository_or_cloudformation(monkeypatch, tmp_path):
    args, parent, _, calls, repo_calls, _, _, _ = _context(monkeypatch, tmp_path)
    args["source_ci_validator"] = lambda auth: (_ for _ in ()).throw(ValueError("source gate failed"))
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert [operation for _, operation, _ in calls] == ["get_caller_identity"]
    assert repo_calls == [] and list(parent.iterdir()) == []


@pytest.mark.parametrize("repo", [
    {"full_name": "other/repo", "id": 123456, "owner": {"id": 654321, "login": "herrerogusano"}},
    {"full_name": "herrerogusano/honda-mapit-mcp", "id": True, "owner": {"id": 654321, "login": "herrerogusano"}},
    {"full_name": "herrerogusano/honda-mapit-mcp", "id": 123456, "owner": {"id": False, "login": "herrerogusano"}},
])
def test_wrong_repository_identity_stops_before_stack_reads(monkeypatch, tmp_path, repo):
    args, parent, _, calls, _, _, _, _ = _context(monkeypatch, tmp_path)
    args["repository_reader"] = lambda: repo
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert [operation for _, operation, _ in calls] == ["get_caller_identity"]
    assert list(parent.iterdir()) == []


def test_runtime_evidence_failure_never_creates_preparation_files(monkeypatch, tmp_path):
    args, parent, _, _, _, _, _, _ = _context(monkeypatch, tmp_path)
    args["runtime_verifier"] = lambda *_: {"verified": False, "category": "accepted_runtime_unverified"}
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize("case", ["template_http", "template_status_type", "stack_http", "resources_http",
                                  "resources_truncated", "resources_next_marker", "policies_http",
                                  "policies_marker", "policies_truncated_type"])
def test_malformed_readback_stops_before_creating_private_outputs(monkeypatch, tmp_path, case):
    variants = {
        "template_http": {"get_template": {"ResponseMetadata": {"HTTPStatusCode": 403}}},
        "template_status_type": {"get_template": {"ResponseMetadata": {"HTTPStatusCode": 200.0}}},
        "stack_http": {"describe_stacks": {"ResponseMetadata": {"HTTPStatusCode": 403}}},
        "resources_http": {"list_stack_resources": {"ResponseMetadata": {"HTTPStatusCode": 403}}},
        "resources_truncated": {"list_stack_resources": {"IsTruncated": True}},
        "resources_next_marker": {"list_stack_resources": {"NextMarker": "next-page"}},
        "policies_http": {"list_role_policies": {"ResponseMetadata": {"HTTPStatusCode": 403}}},
        "policies_marker": {"list_role_policies": {"Marker": "next-page"}},
        "policies_truncated_type": {"list_role_policies": {"IsTruncated": 0}},
    }[case]
    args, parent, _, _, _, _, _, _ = _context(monkeypatch, tmp_path, variants=variants)
    with pytest.raises((ValueError, KeyError, TypeError)):
        preparer.prepare(**args)
    assert list(parent.iterdir()) == []


def test_expired_wallclock_after_readbacks_never_creates_authority(monkeypatch, tmp_path):
    base = 1_800_000_000
    wall = iter((base, base + 3600))
    args, parent, _, calls, _, _, _, _ = _context(monkeypatch, tmp_path, clock_value=lambda: next(wall))
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert len(calls) == 9
    assert list(parent.iterdir()) == []


def test_partial_binding_metadata_never_leaves_authorization_file(monkeypatch, tmp_path):
    args, parent, _, _, _, _, _, _ = _context(monkeypatch, tmp_path)
    monkeypatch.setattr(preparer.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk-full-canary")))
    with pytest.raises(OSError):
        preparer.prepare(**args)
    children = list(parent.iterdir())
    assert len(children) == 1
    target = children[0]
    assert not (target / "authorization.json").exists()
    assert not (target / "bootstrap" / "authorization.json").exists()
    assert "disk-full-canary" not in str(target)


@pytest.mark.parametrize("bad_clock", [True, float("nan"), float("inf")])
def test_invalid_wallclock_is_rejected_before_repository_or_artifact(monkeypatch, tmp_path, bad_clock):
    args, parent, _, calls, _, _, _, _ = _context(monkeypatch, tmp_path, clock_value=bad_clock)
    with pytest.raises((ValueError, OverflowError)):
        preparer.prepare(**args)
    assert [operation for _, operation, _ in calls] == ["get_caller_identity"]
    assert list(parent.iterdir()) == []


def test_clock_expiry_during_readonly_preflight_creates_no_authority(monkeypatch, tmp_path):
    ticks = iter((100.0, 100.0, 100.0, 280.0))
    args, parent, _, calls, _, _, _, _ = _context(monkeypatch, tmp_path, monotonic=lambda: next(ticks))
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert [operation for _, operation, _ in calls] == ["get_caller_identity"]
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize("first_tick", [float("nan"), True])
def test_invalid_initial_monotonic_sample_cannot_disable_budget(monkeypatch, tmp_path, first_tick):
    ticks = iter((first_tick, 100.0, 100.0))
    args, parent, _, calls, _, _, _, _ = _context(monkeypatch, tmp_path, monotonic=lambda: next(ticks))
    with pytest.raises(ValueError):
        preparer.prepare(**args)
    assert calls == [] and list(parent.iterdir()) == []
