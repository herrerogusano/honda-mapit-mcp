from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from scripts import run_cd_release as release


def _bindings() -> dict:
    return {
        "account_id": "123456789012",
        "stack_arn": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-prod/11111111-2222-3333-4444-555555555555",
        "prod_run_id": "11111111-2222-3333-4444-555555555555",
        "api_id": "a1b2c3d4e5",
        "function_name": "honda-mapit-mcp-prod-handler",
        "shutdown_state_machine_arn": "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-prod-shutdown",
        "artifact_bucket": "honda-mapit-mcp-prod-runtime-artifacts-123456789012",
        "policy": {
            "user_pool_id": "eu-west-1_A1b2C3d4E", "api_id": "a1b2c3d4e5",
            "client_id": "ProdClient123456", "owner_subject": "18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
        },
        "mapit_config": {
            "region": "eu-west-1", "user_pool_id": "eu-west-1_A1b2C3d4E",
            "user_pool_client_id": "ProdClient123456",
            "identity_pool_id": "eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
            "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
            "discovery_enabled": False, "http_timeout": 2,
        },
        "parameter_version": 1,
        "parameter_tier": "Standard",
        "jwks": {"keys": [{"kid": "synthetic", "kty": "RSA", "use": "sig", "alg": "RS256", "n": "AQ", "e": "AQAB"}]},
        "service_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cfn-update",
        "executor_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cd-executor",
        "owner_id": "1234567", "repository_id": "7654321",
        "initial_service_role_attachment": True,
        "artifact_tags_sha256": "5" * 64,
    }


def test_private_binding_is_strict_and_retains_attachment_mode():
    bindings = release._parse_bindings(json.dumps(_bindings()))
    assert bindings["initial_service_role_attachment"] is True
    assert bindings["_validated_policy"].environment == "prod"


def test_upstream_mapit_identity_is_independent_of_owner_cognito_identity():
    value = _bindings()
    value["mapit_config"]["user_pool_id"] = "eu-west-1_Z9y8X7w6V"
    value["mapit_config"]["user_pool_client_id"] = "MapitClientABC123"

    bindings = release._parse_bindings(json.dumps(value))

    assert bindings["_validated_policy"].user_pool_id == "eu-west-1_A1b2C3d4E"
    assert bindings["_validated_policy"].client_id == "ProdClient123456"
    assert bindings["_validated_mapit_config"].user_pool_id == "eu-west-1_Z9y8X7w6V"
    assert bindings["_validated_mapit_config"].user_pool_client_id == "MapitClientABC123"


def test_distinct_identity_validation_remains_independent():
    value = _bindings()
    value["mapit_config"]["user_pool_id"] = "eu-west-1_Z9y8X7w6V"
    value["mapit_config"]["user_pool_client_id"] = "MapitClientABC123"
    value["mapit_config"]["core_api_url"] = "https://untrusted.example/api"

    with pytest.raises(release.ReleaseError) as error:
        release._parse_bindings(json.dumps(value))

    assert error.value.category == "binding_invalid"


@pytest.mark.parametrize("mutate", [
    lambda b: b.update(initial_service_role_attachment=1),
    lambda b: b.update(extra="canary"),
    lambda b: b.update(service_role_arn="arn:aws:iam::123456789012:role/other"),
    lambda b: b.update(source_sha="secret-canary"),
])
def test_private_binding_rejects_unexpected_or_wrongly_typed_values(mutate):
    value = _bindings()
    mutate(value)
    with pytest.raises(release.ReleaseError) as error:
        release._parse_bindings(json.dumps(value))
    assert error.value.category == "binding_invalid"
    assert "canary" not in str(error.value)


def test_duplicate_binding_keys_are_rejected_without_echo():
    raw = json.dumps(_bindings())[:-1] + ',"account_id":"000000000000"}'
    with pytest.raises(release.ReleaseError) as error:
        release._parse_bindings(raw)
    assert error.value.category == "binding_invalid"
    assert "000000000000" not in str(error.value)


def test_source_context_binds_verified_checkout_not_event_default_sha():
    sha = "a" * 40
    env = {
        "SOURCE_SHA": sha, "CHECKED_OUT_SHA": sha,
        "GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp", "GITHUB_REF": "refs/heads/main",
        "TARGET": "prod", "GITHUB_ENVIRONMENT": "prod", "GITHUB_RUN_ID": "42",
        "GITHUB_REPOSITORY_ID": "7654321", "GITHUB_REPOSITORY_OWNER_ID": "1234567",
    }
    assert release._source_context(env) == (sha, "42")
    env["CHECKED_OUT_SHA"] = "b" * 40
    with pytest.raises(release.ReleaseError) as error:
        release._source_context(env)
    assert error.value.category == "source_context_invalid"


def test_reopen_uses_nested_delivery_binding_and_requires_workflow_receipts(monkeypatch):
    binding = _bindings()
    state = {
        "kind": "prod_cd_delivery", "prod_run_id": binding["prod_run_id"],
        "delivery_binding": {
            "source_sha": "a" * 40, "service_role_arn": binding["service_role_arn"],
            "initial_service_role_attachment": True, "retained_recovery": False,
        },
        "authorization_start_epoch": 1000, "authorization_cutoff_epoch": 1600,
        "old_zip_sha256": "1" * 64, "old_manifest_sha256": "2" * 64,
        "new_zip_sha256": "3" * 64, "new_manifest_sha256": "4" * 64,
        "close_intent": {"execution_name": "11111111-2222-3333-4444-555555555556",
                         "execution_arn": "arn:aws:states:eu-west-1:123456789012:execution:honda-mapit-mcp-prod-shutdown:11111111-2222-3333-4444-555555555556"},
    }
    monkeypatch.setattr(release, "_journal_state", lambda _journal: state)
    monkeypatch.setattr(release, "_core", lambda *a, **kw: object())
    monkeypatch.setattr(release, "_close_age", lambda *a, **kw: True)
    class Core:
        def run_step(self, step):
            state["production_open_verified"] = True
            return {"category": "production_open_verified", "verified": True}
    fake = Core()
    monkeypatch.setattr(release, "_core", lambda *a, **kw: fake)
    runner = release.CDReleaseRunner(environ={"GITHUB_RUN_ID": "42"}, clock=lambda: 1200)
    services = {"stepfunctions": object()}
    result = runner._reopen_or_close(
        "reopen", binding, services, object(), "42", "a" * 40,
    )
    assert result["category"] == "reopen_verified_retention_pending"
    assert result["source_sha"] == "a" * 40


def test_bucket_readback_requires_private_unversioned_encrypted_owned_configuration():
    class S3:
        def __init__(self):
            self.calls = []
        def _reply(self, name, **kwargs):
            self.calls.append((name, kwargs))
            base = {"ResponseMetadata": {"HTTPStatusCode": 200}}
            shapes = {
                "get_bucket_versioning": {"Status": None},
                "get_bucket_location": {"LocationConstraint": "eu-west-1"},
                "get_public_access_block": {"PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                }},
                "get_bucket_ownership_controls": {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
                "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}},
                ]}},
                "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                "get_bucket_policy": {"Policy": json.dumps({
                    "Version": "2012-10-17", "Statement": [{
                        "Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny",
                        "Principal": "*", "Action": "s3:*",
                        "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                    }],
                })},
                "get_bucket_tagging": {"TagSet": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "prod"},
                    {"Key": "Purpose", "Value": "production-runtime-artifact"},
                ]},
            }
            base.update(shapes[name])
            return base
        def __getattr__(self, name):
            return lambda **kwargs: self._reply(name, **kwargs)

    s3 = S3()
    assert release._verify_private_artifact_bucket(s3, "bucket", "123456789012")
    assert len(s3.calls) == 8
    assert all(call[1]["ExpectedBucketOwner"] == "123456789012" for call in s3.calls)
    s3._reply = lambda name, **kwargs: {"ResponseMetadata": {"HTTPStatusCode": 200}, "Status": "Suspended"}
    assert not release._verify_private_artifact_bucket(s3, "bucket", "123456789012")


def test_bucket_readback_rejects_cross_account_access_policy():
    class S3:
        def __getattr__(self, name):
            values = {
                "get_bucket_versioning": {"Status": None},
                "get_bucket_location": {"LocationConstraint": "eu-west-1"},
                "get_public_access_block": {"PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }},
                "get_bucket_ownership_controls": {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}},
                "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}},
                ]}},
                "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                "get_bucket_policy": {"Policy": json.dumps({
                    "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                        "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}],
                })},
                "get_bucket_tagging": {"TagSet": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "prod"},
                    {"Key": "Purpose", "Value": "production-runtime-artifact"},
                ]},
            }
            return lambda **kwargs: {"ResponseMetadata": {"HTTPStatusCode": 200}, **values[name]}

    assert not release._verify_private_artifact_bucket(S3(), "bucket", "123456789012")


def test_emergency_close_checks_fixed_workflow_and_polls_once_execution():
    from scripts.build_aws_prod_controls import fixed_prod_controls_template

    account = "123456789012"
    api_id = "a1b2c3d4e5"
    machine_arn = f"arn:aws:states:eu-west-1:{account}:stateMachine:honda-mapit-mcp-prod-shutdown"
    props = fixed_prod_controls_template(api_id)["Resources"]["ShutdownStateMachine"]["Properties"]

    class StepFunctions:
        def __init__(self):
            self.describe_count = 0
            self.started = []
        def describe_state_machine(self, **kwargs):
            assert kwargs == {"stateMachineArn": machine_arn}
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "stateMachineArn": machine_arn,
                    "name": "honda-mapit-mcp-prod-shutdown", "type": "STANDARD",
                    "roleArn": f"arn:aws:iam::{account}:role/honda-mapit-mcp-prod-shutdown-workflow",
                    "definition": props["DefinitionString"]}
        def start_execution(self, **kwargs):
            self.started.append(kwargs)
            name = kwargs["name"]
            return {"ResponseMetadata": {"HTTPStatusCode": 200},
                    "executionArn": f"arn:aws:states:eu-west-1:{account}:execution:honda-mapit-mcp-prod-shutdown:{name}"}
        def describe_execution(self, **kwargs):
            self.describe_count += 1
            name = kwargs["executionArn"].rsplit(":", 1)[1]
            status = "RUNNING" if self.describe_count == 1 else "SUCCEEDED"
            output = None if status == "RUNNING" else json.dumps({
                "verified": True, "api_closed": True, "function_reserved": True,
                "api_write_call_returned": True, "function_write_call_returned": True,
            })
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "executionArn": kwargs["executionArn"],
                    "status": status, "output": output}

    class API:
        def get_api(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "ApiId": kwargs["ApiId"],
                    "DisableExecuteApiEndpoint": True}
    class Lambda:
        def get_function_concurrency(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "ReservedConcurrentExecutions": 0}

    sf = StepFunctions()
    runner = release.CDReleaseRunner()
    assert runner._emergency_close({"stepfunctions": sf, "apigatewayv2": API(), "lambda": Lambda()}, {
        "account_id": account, "api_id": api_id, "shutdown_state_machine_arn": machine_arn,
    })
    assert len(sf.started) == 1 and sf.describe_count == 2


def test_emergency_close_refuses_changed_state_machine_before_start():
    account = "123456789012"
    machine_arn = f"arn:aws:states:eu-west-1:{account}:stateMachine:honda-mapit-mcp-prod-shutdown"
    class StepFunctions:
        started = False
        def describe_state_machine(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "stateMachineArn": machine_arn,
                    "name": "honda-mapit-mcp-prod-shutdown", "type": "STANDARD",
                    "roleArn": f"arn:aws:iam::{account}:role/honda-mapit-mcp-prod-shutdown-workflow",
                    "definition": "{}"}
        def start_execution(self, **kwargs):
            self.started = True
            raise AssertionError("must not dispatch altered workflow")
    sf = StepFunctions()
    assert not release.CDReleaseRunner()._emergency_close({"stepfunctions": sf}, {
        "account_id": account, "api_id": "a1b2c3d4e5", "shutdown_state_machine_arn": machine_arn,
    })
    assert not sf.started


def test_workflow_terminal_output_ready_flag_is_category_bound(tmp_path):
    path = tmp_path / "output"
    env = {"GITHUB_OUTPUT": str(path)}
    release._emit_outputs({"category": "release_ready_for_reopen", "artifact_sha256": "a" * 64}, env)
    release._emit_outputs({"category": "update_pending"}, env)
    text = path.read_text(encoding="utf-8")
    assert "ready=true" in text
    assert "ready=false" in text


def test_release_workflow_is_readiness_gated_and_never_uses_deploy_action():
    from pathlib import Path

    workflow = Path(".github/workflows/cd-release.yml").read_text(encoding="utf-8")
    assert "workflow_run:" in workflow and "workflows: [CI]" in workflow
    assert "branches: [main]" in workflow
    assert "ubuntu-24.04-arm" in workflow and "probe_aws_prod_runtime_arm" in workflow
    assert "needs.arm-runtime-probe.result == 'success'" in workflow
    assert "needs.release.outputs.ready == 'true'" in workflow
    assert workflow.count("environment: prod") == 2
    assert "id-token: write" in workflow
    assert "persist-credentials: false" in workflow
    assert "configure-aws-credentials" not in workflow
    assert "workflow_dispatch:" not in workflow
    assert "upload-artifact" not in workflow and "download-artifact" not in workflow
    assert "AWS_ACCESS_KEY_ID" not in workflow and "AWS_SECRET_ACCESS_KEY" not in workflow
    assert "GITHUB_OUTPUT" in workflow
    assert "MAPIT_CD_BINDING_JSON" in workflow


def _source_gate_script():
    from pathlib import Path
    import textwrap

    lines = Path(".github/workflows/cd-release.yml").read_text(encoding="utf-8").splitlines()
    start = lines.index("          python - <<'PY'") + 1
    end = lines.index("          PY", start)
    return textwrap.dedent("\n".join(line[10:] for line in lines[start:end]))


def _source_gate_documents():
    sha = "a" * 40
    repo = "herrerogusano/honda-mapit-mcp"
    run_id = 37357964963
    checks = [
        "Offline geographic queries and public boundary", "Offline CloudFormation schemas",
        "Offline shutdown SDK contract", "ubuntu-latest / Python 3.11",
        "ubuntu-latest / Python 3.12", "ubuntu-latest / Python 3.13",
        "windows-latest / Python 3.13", "Known dependency advisories",
    ]
    return sha, repo, run_id, {
        f"repos/{repo}/actions/runs/{run_id}": {
            "id": run_id, "head_sha": sha, "event": "push", "head_branch": "main",
            "conclusion": "success", "name": "CI", "path": ".github/workflows/ci.yml",
            "workflow_id": 365146925,
            "head_repository": {"full_name": repo, "id": 7654321},
        },
        f"repos/{repo}/actions/workflows/ci.yml": {"id": 365146925, "path": ".github/workflows/ci.yml"},
        f"repos/{repo}/branches/main": {"commit": {"sha": sha}},
        f"repos/{repo}/commits/{sha}/check-runs?filter=latest&per_page=100": {
            "total_count": 8,
            "check_runs": [
                {"name": name, "app": {"id": 15368}, "conclusion": "success",
                 "status": "completed", "head_sha": sha}
                for name in checks
            ],
        },
    }


def _execute_source_gate(monkeypatch, tmp_path, *, mutate_rest=None):
    import json
    import subprocess
    from pathlib import Path
    from types import SimpleNamespace

    sha, repo, run_id, documents = _source_gate_documents()
    if mutate_rest is not None:
        mutate_rest(documents[f"repos/{repo}/actions/runs/{run_id}"])
    # Deliberately omit webhook path, name, head_repository, and workflow_id:
    # those fields are taken from the authoritative REST run record.
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({
        "workflow_run": {"id": run_id, "head_sha": sha},
        "repository": {"id": 7654321, "owner": {"id": 1234567}},
    }), encoding="utf-8")
    output_path = tmp_path / "output.txt"
    for name, value in {
        "EVENT_PATH": str(event_path), "REPOSITORY": repo,
        "REPOSITORY_ID": "7654321", "REPOSITORY_OWNER_ID": "1234567",
        "WORKFLOW_RUN_ID": str(run_id), "DEFAULT_SHA": sha,
        "GITHUB_OUTPUT": str(output_path),
    }.items():
        monkeypatch.setenv(name, value)
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args[-1])
        payload = documents.get(args[-1])
        return SimpleNamespace(returncode=0 if payload is not None else 1,
                               stdout=json.dumps(payload) if payload is not None else "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    exec(compile(_source_gate_script(), "cd-release-source-gate", "exec"), {})
    return calls, output_path.read_text(encoding="utf-8")


def test_source_gate_uses_rest_run_when_webhook_omits_optional_metadata(monkeypatch, tmp_path):
    calls, output = _execute_source_gate(monkeypatch, tmp_path)
    assert calls[0] == "repos/herrerogusano/honda-mapit-mcp/actions/runs/37357964963"
    assert output == "source_sha=" + "a" * 40 + "\n"


@pytest.mark.parametrize("mutate", [
    lambda run: run.update(id=37357964964),
    lambda run: run.update(head_sha="b" * 40),
    lambda run: run["head_repository"].update(id=99999999),
])
def test_source_gate_fails_closed_on_rest_run_id_sha_or_repository_mismatch(monkeypatch, tmp_path, mutate):
    with pytest.raises(SystemExit):
        _execute_source_gate(monkeypatch, tmp_path, mutate_rest=mutate)
