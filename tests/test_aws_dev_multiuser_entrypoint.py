from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import aws_dev_multiuser_entrypoint as entrypoint
from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantRecord
from mapit.tenant_router import tenant_key
from scripts import build_aws_dev_runtime, build_aws_prod_runtime

from test_aws_durable_tenants import MemoryClient, TABLE
from test_invited_dev_lambda import DEV_A, DEV_B, KEY_A, KEY_B, _call, _token


ACCOUNT = "123456789012"
SUBJECT_A = DEV_A.owner_subject
SUBJECT_B = DEV_B.owner_subject


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _bundle(private) -> tuple[bytes, bytes, str]:
    numbers = private.public_key().public_numbers()
    jwks = json.dumps({"keys": [{
        "kty": "RSA", "kid": "dev-key", "use": "sig", "alg": "RS256",
        "n": _b64u(numbers.n), "e": _b64u(numbers.e),
    }]}, separators=(",", ":")).encode("ascii")
    manifest = {
        "schema": 1,
        "builder": "build_retained_dev_multiuser_archive",
        "environment": "dev",
        "synthetic": True,
        "source_sha": "1" * 40,
        "api_id": DEV_A.api_id,
        "user_pool_id": DEV_A.user_pool_id,
        "client_id": DEV_A.client_id,
        "jwks_sha256": hashlib.sha256(jwks).hexdigest(),
        "table_arn": TABLE,
        "tenants": [
            {"key": KEY_A, "subject": SUBJECT_A, "label": "synthetic-A"},
            {"key": KEY_B, "subject": SUBJECT_B, "label": "synthetic-B"},
        ],
    }
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    return raw, jwks, hashlib.sha256(raw).hexdigest()


def _valid_handler_environment(monkeypatch, *, now: int | None = None):
    now = int(time.time()) if now is None else now
    values = {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_DEV_MULTIUSER_MODE": "synthetic",
        "AWS_REGION": entrypoint.REGION,
        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": "a" * 64,
        "MAPIT_DEV_EXPECTED_ACCOUNT_ID": ACCOUNT,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(now - 1),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(now + 299),
        "MAPIT_SOURCE_SHA256": "b" * 40,
        "MAPIT_COGNITO_JWKS_SHA256": "c" * 64,
        "MAPIT_COGNITO_USER_POOL_ID": DEV_A.user_pool_id,
        "MAPIT_COGNITO_CLIENT_ID": DEV_A.client_id,
        "MAPIT_OBSERVED_API_ID": DEV_A.api_id,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    return tuple(values[name] for name in (
        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256", "MAPIT_DEV_EXPECTED_ACCOUNT_ID",
        "MAPIT_DEV_EXECUTION_START_EPOCH", "MAPIT_DEV_EXECUTION_END_EPOCH",
        "MAPIT_SOURCE_SHA256", "MAPIT_COGNITO_JWKS_SHA256",
        "MAPIT_COGNITO_USER_POOL_ID", "MAPIT_COGNITO_CLIENT_ID", "MAPIT_OBSERVED_API_ID",
    ))


def test_parse_manifest_is_bounded_duplicate_rejecting_and_exact():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw, _jwks, digest = _bundle(private)
    parsed = entrypoint.parse_manifest(raw, expected_digest=digest, account_id=ACCOUNT)
    assert parsed["environment"] == "dev"
    assert [item["label"] for item in parsed["tenants"]] == ["synthetic-A", "synthetic-B"]

    duplicate = raw.replace(b'"schema":1,', b'"schema":1,"schema":1,', 1)
    with pytest.raises(ValueError, match="^manifest_invalid$"):
        entrypoint.parse_manifest(duplicate, expected_digest=hashlib.sha256(duplicate).hexdigest(), account_id=ACCOUNT)


def test_composed_entrypoint_routes_a_b_and_rechecks_shared_revocation():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    manifest, jwks, digest = _bundle(private)
    client = MemoryClient()
    operator = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B), writer=client)
    assert operator.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    assert operator.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
    runtime = entrypoint.compose_runtime(
        manifest, jwks, manifest_digest=digest, account_id=ACCOUNT,
        dynamodb_reader=client,
    )

    result_a = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
    result_b = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_B)))
    assert not result_a.is_error and not result_b.is_error
    assert result_a.structured_content["status"] == "synthetic-A"
    assert result_b.structured_content["status"] == "synthetic-B"

    assert operator.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
    denied = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
    assert denied.is_error
    assert all(request["ConsistentRead"] is True for method, request in client.calls if method == "get")


def test_runtime_store_key_shape_matches_the_multiuser_template():
    from scripts import build_aws_retained_dev_multiuser as builder

    template = builder.build_retained_dev_multiuser_template(
        api_id=DEV_A.api_id, bucket="honda-runtime-artifact-test-bucket",
        zip_sha256="1" * 64, source_sha256="2" * 40,
        jwks_sha256="3" * 64, manifest_sha256="4" * 64,
        account_id=ACCOUNT, execution_start_epoch=1_900_000_000,
        execution_end_epoch=1_900_000_300, callback_url="http://localhost:39031/callback",
        subjects=(SUBJECT_A, SUBJECT_B),
        tenant_keys=(KEY_A, KEY_B),
    )
    table = template["Resources"]["McpTenantsTable"]["Properties"]
    template_keys = {item["AttributeName"] for item in table["AttributeDefinitions"]}
    # The runtime store sends a single `key` DynamoDB primary-key member. This
    # invariant intentionally catches drift before any cloud deployment.
    assert template_keys == {"key"}


def test_handler_binds_all_runtime_metadata_before_using_a_cached_runtime(monkeypatch):
    fake_result = {"statusCode": 200, "headers": {}, "body": "{}", "isBase64Encoded": False}

    class FakeRuntime:
        def __init__(self):
            self.calls = 0

        def handler(self, _event, _context):
            self.calls += 1
            return fake_result

    runtime = FakeRuntime()
    monkeypatch.setattr(entrypoint, "_CACHED", runtime)
    monkeypatch.setattr(entrypoint, "_BINDING", None)
    monkeypatch.setattr(entrypoint, "_LAST_WALL", None)
    _valid_handler_environment(monkeypatch)

    result = entrypoint.handler({}, type("Context", (), {
        "get_remaining_time_in_millis": lambda self: 30_000,
    })())
    assert result == entrypoint._unavailable()
    assert runtime.calls == 0


@pytest.mark.parametrize("field", [
    "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256", "MAPIT_DEV_EXPECTED_ACCOUNT_ID",
    "MAPIT_DEV_EXECUTION_START_EPOCH", "MAPIT_DEV_EXECUTION_END_EPOCH",
    "MAPIT_SOURCE_SHA256", "MAPIT_COGNITO_JWKS_SHA256",
    "MAPIT_COGNITO_USER_POOL_ID", "MAPIT_COGNITO_CLIENT_ID", "MAPIT_OBSERVED_API_ID",
])
def test_each_bound_metadata_mutation_is_rejected_after_valid_cache(monkeypatch, field):
    runtime = type("Runtime", (), {"calls": 0, "handler": lambda self, *_: setattr(self, "calls", self.calls + 1) or {"statusCode": 200, "headers": {}, "body": "{}", "isBase64Encoded": False}})()
    binding = _valid_handler_environment(monkeypatch)
    monkeypatch.setattr(entrypoint, "_CACHED", runtime)
    monkeypatch.setattr(entrypoint, "_BINDING", binding)
    monkeypatch.setattr(entrypoint, "_LAST_WALL", None)
    monkeypatch.setenv(field, "9" * len(binding[0]) if field.endswith("SHA256") else "different")
    result = entrypoint.handler({}, type("Context", (), {"get_remaining_time_in_millis": lambda self: 30_000})())
    assert result == entrypoint._unavailable()
    assert runtime.calls == 0


def test_cold_handler_requires_manifest_to_match_all_bound_metadata(monkeypatch):
    runtime = type("Runtime", (), {"calls": 0, "handler": lambda self, *_: setattr(self, "calls", self.calls + 1) or {"statusCode": 200, "headers": {}, "body": "{}", "isBase64Encoded": False}})()
    binding = _valid_handler_environment(monkeypatch)
    monkeypatch.setattr(entrypoint, "_CACHED", None)
    monkeypatch.setattr(entrypoint, "_BINDING", None)
    monkeypatch.setattr(entrypoint, "_LAST_WALL", None)
    manifest = {
        "source_sha": binding[4], "jwks_sha256": binding[5],
        "user_pool_id": binding[6], "client_id": binding[7], "api_id": binding[8],
    }
    monkeypatch.setattr(entrypoint, "_bounded_read", lambda name, _ceiling: b"raw" if "manifest" in name else b"jwks")
    monkeypatch.setattr(entrypoint, "parse_manifest", lambda *args, **kwargs: manifest | {"source_sha": "0" * 40})
    monkeypatch.setattr(entrypoint, "compose_runtime", lambda *args, **kwargs: runtime)
    result = entrypoint.handler({}, type("Context", (), {"get_remaining_time_in_millis": lambda self: 30_000})())
    assert result == entrypoint._unavailable()
    assert runtime.calls == 0
    assert entrypoint._CACHED is None


def test_handler_rejects_nan_final_clock_and_short_context_budget(monkeypatch):
    runtime = type("Runtime", (), {"calls": 0, "handler": lambda self, *_: setattr(self, "calls", self.calls + 1) or {"statusCode": 200, "headers": {}, "body": "{}", "isBase64Encoded": False}})()
    _valid_handler_environment(monkeypatch)
    monkeypatch.setattr(entrypoint, "_CACHED", runtime)
    monkeypatch.setattr(entrypoint, "_BINDING", _valid_handler_environment(monkeypatch))
    monkeypatch.setattr(entrypoint, "_LAST_WALL", None)
    real_time = entrypoint.time.time
    values = iter([real_time(), float("nan")])
    monkeypatch.setattr(entrypoint.time, "time", lambda: next(values))
    result = entrypoint.handler({}, type("Context", (), {"get_remaining_time_in_millis": lambda self: 30_000})())
    assert result == entrypoint._unavailable()
    assert runtime.calls == 1

    monkeypatch.setattr(entrypoint, "_LAST_WALL", None)
    monkeypatch.setattr(entrypoint.time, "time", real_time)
    result = entrypoint.handler({}, type("Context", (), {"get_remaining_time_in_millis": lambda self: 1000})())
    assert result == entrypoint._unavailable()


def test_dynamodb_client_is_lazy_and_reused_only_after_first_read(monkeypatch):
    created = []

    class Client:
        def get_item(self, **request):
            return {"request": request}

    client = Client()
    monkeypatch.setattr(entrypoint, "_make_client", lambda: created.append(client) or client)
    reader = entrypoint._LazyReader()
    assert created == []
    first = reader.get_item(TableName="synthetic")
    second = reader.get_item(TableName="synthetic-2")
    assert first["request"]["TableName"] == "synthetic"
    assert second["request"]["TableName"] == "synthetic-2"
    assert created == [client]


@pytest.mark.parametrize("module_list", [build_aws_dev_runtime.SOURCE_MODULES, build_aws_prod_runtime.PROD_SOURCE_MODULES])
def test_legacy_auth_import_does_not_require_opt_in_identity_module(tmp_path: Path, module_list):
    package = tmp_path / "mapit"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    source_root = Path(__file__).parents[1] / "src" / "mapit"
    for name in ("auth.py", "config.py", "http_transport.py"):
        (package / name).write_bytes((source_root / name).read_bytes())
    # Legacy auth is independently importable even when a full runtime profile
    # also bundles identity verification for cloud_provider's optional API.
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-c", "import mapit.auth"],
        cwd=tmp_path, env=environment, capture_output=True, text=True,
        timeout=10, check=False,
    )
    assert completed.returncode == 0, completed.stderr
