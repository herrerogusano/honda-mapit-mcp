from __future__ import annotations

import hashlib
import base64
import json
import io
from pathlib import Path
import zipfile
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from scripts import run_dev_multiuser_runtime_update as runtime
from tests.test_run_dev_multiuser_closed_update import BINDINGS


APP_STACK = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
CALLER = "arn:aws:iam::123456789012:user/synthetic-operator"
SUBJECTS = (
    "11111111-2222-4333-8444-555555555555",
    "22222222-3333-4444-8555-666666666666",
)
TENANT_KEYS = ("tenant-" + "a" * 64, "tenant-" + "b" * 64)


def _receipt():
    return runtime.MultiuserBuildReceipt(
        source_sha="1" * 40, api_id="a1b2c3d4e5", user_pool_id="eu-west-1_ABCDEFGHI",
        client_id="client123", jwks_sha256="2" * 64, manifest_sha256="3" * 64,
        zip_sha256="4" * 64, archive_path=Path("synthetic.zip"),
        execution_start_epoch=1_900_000_000, execution_end_epoch=1_900_000_300,
    )


def test_v2_update_requires_exact_clients_and_rejects_invalid_step():
    result = runtime.run_multiuser_update_step(
        {"s3": object()}, _Journal(), step="check-update", account_id="123456789012",
        stack_arn=APP_STACK, caller_arn=CALLER,
        cfn_role_arn="arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update",
        source_sha="1" * 40, run_token="dev-multiuser-" + "a" * 32, receipt=_receipt(),
        callback_url="http://localhost:39031/callback", subjects=SUBJECTS,
        tenant_keys=TENANT_KEYS, bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        authorized_from_epoch=1_900_000_000, authorized_until_epoch=1_900_000_300,
    )
    assert result == {"success": False, "category": "clients_invalid"}


def test_recurrent_iam_is_separate_and_returns_only_safe_digest():
    pool = "eu-west-1_ABCDEFGHI"
    result = runtime.recurrent_iam_summary(BINDINGS, observed_user_pool_id=pool)
    assert result["success"] is True
    assert result["category"] == "recurrent_roles_ready"
    assert result["resource_count"] == 4
    assert pool not in repr(result)
    assert runtime.recurrent_iam_summary(BINDINGS, observed_user_pool_id="foreign") == {
        "success": False, "category": "bindings_invalid"
    }


def test_publish_candidate_rejects_legacy_receipts_before_any_client_call():
    result = runtime.publish_candidate(
        object(), object(), bucket="private-bucket", expected_owner="123456789012",
        run_id="private-run", archive_path="private-path", build_receipt=object(),
        authorized_from_epoch=1, authorized_until_epoch=300,
        wall_clock=lambda: 2, monotonic=lambda: 1,
    )
    assert result == {"success": False, "category": "v2_receipt_required"}


def test_publish_candidate_rejects_malformed_core_result(monkeypatch):
    result = runtime.publish_candidate(
        object(), object(), bucket="b", expected_owner="123456789012", run_id="r",
        archive_path="p", build_receipt=object(), authorized_from_epoch=1,
        authorized_until_epoch=2, wall_clock=lambda: 1, monotonic=lambda: 1,
    )
    assert result == {"success": False, "category": "v2_receipt_required"}


def test_v2_candidate_is_exact_19_resource_factory_output():
    receipt = _receipt()
    template = runtime.build_multiuser_candidate_template(
        receipt, account_id="123456789012",
        bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        callback_url="http://localhost:39031/callback", subjects=SUBJECTS,
        tenant_keys=TENANT_KEYS,
    )
    assert len(template["Resources"]) == 19
    assert template["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] == "runtime/" + "4" * 64 + ".zip"
    assert template["Metadata"]["ManifestSha256"] == "3" * 64


class _Journal:
    def __init__(self):
        self.state = None

    class _Lock:
        def __enter__(self): return self
        def __exit__(self, *args): return False

    def locked(self): return self._Lock()
    def load(self): return self.state
    def save(self, value): self.state = value


class _Cfn:
    def __init__(self, body): self.body = body
    def describe_stacks(self, **kwargs):
        return {"Stacks": [{"StackId": APP_STACK, "StackName": "honda-mapit-mcp-dev-retained", "StackStatus": "CREATE_COMPLETE", "RoleARN": None, "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}]}]}
    def describe_stack_resources(self, **kwargs):
        return {"StackResources": [{"LogicalResourceId": "McpApi", "ResourceType": "AWS::ApiGatewayV2::Api", "PhysicalResourceId": "a1b2c3d4e5"}]}
    def get_template(self, **kwargs): return {"TemplateBody": self.body}


class _Sts:
    def get_caller_identity(self): return {"Account": "123456789012", "Arn": CALLER}


class _Lambda:
    def get_function_concurrency(self, **kwargs): return {"ReservedConcurrentExecutions": 0}


class _Api:
    def get_api(self, **kwargs): return {"ApiId": "a1b2c3d4e5", "DisableExecuteApiEndpoint": True}


def test_v2_update_uses_real_closed_core_for_setup_to_runtime_preflight(monkeypatch):
    receipt = _receipt()
    monkeypatch.setattr(runtime, "_read_multiuser_archive", lambda *_a, **_k: (b"zip", {
        "tenants": [{"key": TENANT_KEYS[0], "subject": SUBJECTS[0], "label": "synthetic-A"},
                    {"key": TENANT_KEYS[1], "subject": SUBJECTS[1], "label": "synthetic-B"}],
    }))
    prior = runtime.build_retained_dev_multiuser_setup(api_id=receipt.api_id, callback_url="http://localhost:39031/callback")
    clients = {"sts": _Sts(), "cloudformation": _Cfn(prior), "lambda": _Lambda(), "apigatewayv2": _Api()}
    result = runtime.run_multiuser_update_step(
        clients, _Journal(), step="preflight", account_id="123456789012", stack_arn=APP_STACK,
        caller_arn=CALLER, cfn_role_arn="arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update",
        source_sha=receipt.source_sha, run_token="dev-multiuser-" + "a" * 32,
        receipt=receipt, callback_url="http://localhost:39031/callback", subjects=SUBJECTS,
        tenant_keys=TENANT_KEYS, bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        authorized_from_epoch=1_899_999_000, authorized_until_epoch=1_900_002_000,
        clock=lambda: receipt.execution_start_epoch + 1,
    )
    assert result == {"success": True, "category": "preflight_verified"}


def test_v2_publication_validates_generated_manifest_jwks_and_uses_one_conditional_put(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    b64 = lambda value: base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode("ascii")
    jwks = json.dumps({"keys": [{"kty": "RSA", "kid": "dev-key", "use": "sig", "alg": "RS256", "n": b64(key.n), "e": b64(key.e)}]}, separators=(",", ":")).encode()
    manifest = {
        "schema": 1, "builder": "build_retained_dev_multiuser_archive", "environment": "dev", "synthetic": True,
        "source_sha": "1" * 40, "api_id": "a1b2c3d4e5", "user_pool_id": "eu-west-1_ABCDEFGHI", "client_id": "client123",
        "jwks_sha256": hashlib.sha256(jwks).hexdigest(), "table_arn": "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants",
        "tenants": [{"key": TENANT_KEYS[0], "subject": SUBJECTS[0], "label": "synthetic-A"}, {"key": TENANT_KEYS[1], "subject": SUBJECTS[1], "label": "synthetic-B"}],
    }
    manifest_raw = json.dumps(manifest, separators=(",", ":")).encode()
    archive_path = tmp_path / "runtime.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("mapit/dev-multiuser.manifest.json", manifest_raw)
        archive.writestr("mapit/dev-multiuser.jwks.json", jwks)
    receipt = runtime.MultiuserBuildReceipt(
        source_sha=manifest["source_sha"], api_id=manifest["api_id"], user_pool_id=manifest["user_pool_id"],
        client_id=manifest["client_id"], jwks_sha256=manifest["jwks_sha256"], manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        zip_sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(), archive_path=archive_path,
        execution_start_epoch=1_900_000_000, execution_end_epoch=1_900_000_300,
    )
    class PublicationJournal(_Journal):
        revision = None
        def compare_and_set(self, expected, value):
            if expected != self.revision:
                return False
            self.state = value
            self.revision = value["revision"]
            return True
    class S3:
        def __init__(self): self.puts = 0; self.body = archive_path.read_bytes()
        def put_object(self, **kwargs): self.puts += 1; return {"ResponseMetadata": {"HTTPStatusCode": 200}}
        def head_object(self, **kwargs):
            return {"ContentLength": len(self.body), "ChecksumSHA256": base64.b64encode(bytes.fromhex(receipt.zip_sha256)).decode(), "ServerSideEncryption": "AES256", "ContentType": "application/zip"}
    clock = lambda: receipt.execution_start_epoch + 1
    result = runtime.publish_multiuser_candidate(
        S3(), PublicationJournal(), receipt, account_id="123456789012",
        bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1", run_id="11111111-2222-4333-8444-555555555555",
        authorized_from_epoch=receipt.execution_start_epoch, authorized_until_epoch=receipt.execution_end_epoch,
        wall_clock=clock, monotonic=lambda: 1.0,
        archive_acl_checker=lambda _path: True,
    )
    assert result["success"] is True and result["category"] == "artifact_uploaded_verified" and result["head_verified"] is True


def test_publication_preflight_is_read_only(monkeypatch):
    receipt = _receipt()
    body = b"synthetic-archive"
    manifest = {"tenants": [{"key": TENANT_KEYS[0], "subject": SUBJECTS[0], "label": "synthetic-A"},
                              {"key": TENANT_KEYS[1], "subject": SUBJECTS[1], "label": "synthetic-B"}]}
    monkeypatch.setattr(runtime, "_read_multiuser_archive", lambda *_a, **_k: (body, manifest))

    class S3:
        def __init__(self): self.puts = 0
        def put_object(self, **_kwargs): self.puts += 1; raise AssertionError("preflight write")
        def head_object(self, **_kwargs): raise AssertionError("unexpected head")

    s3 = S3()
    result = runtime.publish_multiuser_candidate(
        s3, _Journal(), receipt, account_id="123456789012",
        bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        run_id="11111111-2222-4333-8444-555555555555",
        authorized_from_epoch=receipt.execution_start_epoch,
        authorized_until_epoch=receipt.execution_end_epoch,
        wall_clock=lambda: receipt.execution_start_epoch + 1,
        monotonic=lambda: 1.0,
        step="preflight",
    )
    assert result == {"success": True, "category": "artifact_preflight_verified", "calls": 0, "head_verified": False}
    assert s3.puts == 0


def test_v2_update_rejects_manifest_tenant_binding_before_core(monkeypatch):
    receipt = _receipt()
    monkeypatch.setattr(runtime, "_read_multiuser_archive", lambda *_a, **_k: (b"zip", {
        "tenants": [{"key": "wrong", "subject": SUBJECTS[0], "label": "synthetic-A"},
                    {"key": TENANT_KEYS[1], "subject": SUBJECTS[1], "label": "synthetic-B"}],
    }))
    result = runtime.run_multiuser_update_step(
        {"sts": object(), "cloudformation": object(), "lambda": object(), "apigatewayv2": object()},
        _Journal(), step="preflight", account_id="123456789012", stack_arn=APP_STACK,
        caller_arn=CALLER,
        cfn_role_arn="arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update",
        source_sha=receipt.source_sha, run_token="dev-multiuser-" + "a" * 32,
        receipt=receipt, callback_url="http://localhost:39031/callback", subjects=SUBJECTS,
        tenant_keys=TENANT_KEYS, bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        authorized_from_epoch=1_899_999_000, authorized_until_epoch=1_900_002_000,
        clock=lambda: receipt.execution_start_epoch + 1,
    )
    assert result == {"success": False, "category": "manifest_binding_invalid"}


def test_cli_caller_identity_requires_integer_http_status():
    class FloatStatus:
        def get_caller_identity(self):
            return {
                "Account": "123456789012",
                "Arn": CALLER,
                "ResponseMetadata": {"HTTPStatusCode": 200.0},
            }

    with pytest.raises(runtime.RuntimeUpdateError) as error:
        runtime._verify_caller_identity(
            FloatStatus(), account_id="123456789012", caller_arn=CALLER,
        )
    assert error.value.category == "identity_mismatch"
