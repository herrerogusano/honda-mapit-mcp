from __future__ import annotations

import hashlib
import json
import sys
import types

import pytest

from mapit import aws_prod_entrypoint as entry
from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.config import MapitConfig

POLICY = {
    "user_pool_id": "eu-west-1_A1b2C3d4E",
    "api_id": "a1b2c3d4e5",
    "client_id": "ProdClient123456",
    "owner_subject": "18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
}
CONFIG = {
    "region": "eu-west-1",
    "user_pool_id": "eu-west-1_A1b2C3d4E",
    "user_pool_client_id": "MapitClient123456",
    "identity_pool_id": "eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
    "core_api_url": "https://core.prod.mapit.me",
    "geo_api_url": "https://geo.prod.mapit.me",
    "frontend_url": "https://app.mapit.me/",
    "discovery_enabled": False,
    "http_timeout": 2.0,
}
JWKS = b'{"keys":[]}'


def manifest_obj(**overrides):
    value = {
        "environment": "prod", "region": "eu-west-1", "account_id": "123456789012",
        "parameter_version": 1, "parameter_tier": "Standard", **POLICY,
        "jwks_sha256": hashlib.sha256(JWKS).hexdigest(),
        "mapit_config": {key: CONFIG[key] for key in (
            "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
            "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
        )},
    }
    value.update(overrides)
    return value


def manifest_bytes(value=None):
    return json.dumps(manifest_obj() if value is None else value, separators=(",", ":")).encode()


def test_manifest_has_exact_schema_and_builds_only_prod_policy():
    parsed = entry._parse_manifest(manifest_bytes())
    assert type(parsed["_validated_policy"]) is CognitoProdPolicy
    assert parsed["_validated_policy"].environment == "prod"
    assert type(parsed["_validated_config"]) is MapitConfig
    assert parsed["_validated_config"].discovery_enabled is False


@pytest.mark.parametrize("raw", [
    b'{"environment":"prod","environment":"dev"}',
    b'{"environment":"prod","unexpected":true}',
    b'{"environment":"prod","x":NaN}',
    b'[]',
    b" ",
])
def test_manifest_duplicate_extra_invalid_json_and_nonobject_rejected(raw):
    with pytest.raises(entry._EntryError):
        entry._parse_manifest(raw)


@pytest.mark.parametrize("field,value", [
    ("environment", "dev"), ("region", "us-east-1"), ("account_id", "000000000000"),
    ("parameter_version", True), ("parameter_version", 2), ("parameter_tier", "Advanced"),
    ("api_id", "UPPERCASE00"), ("jwks_sha256", "A" * 64),
])
def test_manifest_rejects_identity_region_version_or_jwks_mutation(field, value):
    data = manifest_obj()
    data[field] = value
    with pytest.raises(entry._EntryError):
        entry._parse_manifest(manifest_bytes(data))


@pytest.mark.parametrize("change", [
    {"email": "person@example.invalid"},
    {"password": "never-allowed"},
    {"discovery_enabled": True},
    {"core_api_url": "https://example.invalid"},
    {"http_timeout": 3.0},
    {"http_timeout": True},
    {"extra": "value"},
])
def test_manifest_rejects_unpinned_mapit_configuration(change):
    data = manifest_obj()
    config = dict(data["mapit_config"])
    config.update(change)
    data["mapit_config"] = config
    with pytest.raises(entry._EntryError):
        entry._parse_manifest(manifest_bytes(data))


def test_manifest_size_is_bounded():
    with pytest.raises(entry._EntryError):
        entry._parse_manifest(b" " * (entry.MAX_MANIFEST_BYTES + 1))


def test_geographic_manifest_accepts_only_explicit_true():
    parsed = entry._parse_manifest(manifest_bytes(manifest_obj(geographic_queries=True)))
    assert parsed["geographic_queries"] is True
    assert "geographic_queries" not in entry._parse_manifest(manifest_bytes())


@pytest.mark.parametrize("value", [False, 1, 0, "true", None, {}, []])
def test_geographic_manifest_rejects_coerced_or_false_flag(value):
    with pytest.raises(entry._EntryError, match="manifest_invalid"):
        entry._parse_manifest(manifest_bytes(manifest_obj(geographic_queries=value)))


def test_geographic_manifest_passes_bound_opt_in_to_runtime(monkeypatch):
    _reset_cache(monkeypatch)
    raw = manifest_bytes(manifest_obj(geographic_queries=True))
    digest = hashlib.sha256(raw).hexdigest()
    seen = []
    def create(policy, jwks, *, provider_builder, geographic_queries):
        seen.append(geographic_queries)
        return object()
    monkeypatch.setattr(entry, "create_aws_prod_runtime", create)
    monkeypatch.setattr(entry, "_ssm_client_factory", lambda: pytest.fail("SSM touched"))
    assert entry._load_runtime(raw, JWKS, digest) is not None
    assert seen == [True]


def test_environment_must_be_exact_before_artifact_or_sdk_access(monkeypatch):
    monkeypatch.setattr(entry, "_read_sibling", lambda *_: pytest.fail("artifact read before env gate"))
    monkeypatch.setattr(entry, "_ssm_client_factory", lambda: pytest.fail("SDK before env gate"))
    monkeypatch.setenv(entry.ENV_FUNCTION, "wrong-handler")
    monkeypatch.setenv(entry.ENV_REGION, "eu-west-1")
    monkeypatch.setenv(entry.ENV_ENVIRONMENT, "prod")
    monkeypatch.setenv(entry.ENV_MANIFEST_SHA256, "0" * 64)
    assert entry.handler({}, object())["statusCode"] == 503


class _FakeRuntime:
    def __init__(self, builder):
        self.builder = builder
        self.providers = []

    def lambda_handler(self, _event, _context):
        deadline = 100.0
        self.providers.append(self.builder(deadline))
        return {"statusCode": 200, "body": "ok"}


def _reset_cache(monkeypatch):
    monkeypatch.setattr(entry, "_CACHED_RUNTIME", None)
    monkeypatch.setattr(entry, "_CACHED_MANIFEST_SHA256", None)
    monkeypatch.setattr(entry, "_CACHED_SSM_CLIENT", None)


def test_warm_invocations_cache_only_runtime_and_ssm_client(monkeypatch):
    _reset_cache(monkeypatch)
    raw_manifest = manifest_bytes()
    expected_sha = hashlib.sha256(raw_manifest).hexdigest()
    monkeypatch.setenv(entry.ENV_FUNCTION, entry.FUNCTION_NAME)
    monkeypatch.setenv(entry.ENV_REGION, "eu-west-1")
    monkeypatch.setenv(entry.ENV_ENVIRONMENT, "prod")
    monkeypatch.setenv(entry.ENV_MANIFEST_SHA256, expected_sha)
    monkeypatch.setattr(entry, "_read_sibling", lambda name, _limit: raw_manifest if name == entry.MANIFEST_FILENAME else JWKS)
    ssm_calls = []
    client_creations = []
    class SSM:
        def get_parameter(self, **kwargs):
            ssm_calls.append(kwargs)
            return {}
    ssm = SSM()
    monkeypatch.setattr(entry, "_ssm_client_factory", lambda: client_creations.append(True) or ssm)
    readers = []
    transports = []
    providers = []

    class Reader:
        def __init__(self, client, **kwargs):
            self.client = client
            assert kwargs["account_id"] == "123456789012"
            assert kwargs["version"] == 1 and kwargs["tier"] == "Standard"
            readers.append(self)
        def read_refresh_token(self, *, deadline):
            assert deadline == 100.0
            return self.client.get_parameter(Name="fixed", WithDecryption=True)

    class Transport:
        def __init__(self, config, *, deadline):
            assert config.discovery_enabled is False and deadline == 100.0
            transports.append(self)
        def cognito_json(self, *args): pass
        def mapit_request(self, *args): pass

    class Provider:
        def __init__(self, config, reader, auth, mapit, *, deadline):
            providers.append(self)
            assert reader is readers[-1] and deadline == 100.0
            assert callable(auth) and callable(mapit)

    monkeypatch.setattr(entry, "AwsSessionReader", Reader)
    monkeypatch.setattr(entry, "CloudDirectTransport", Transport)
    monkeypatch.setattr(entry, "CloudServicesProvider", Provider)
    made = []
    def create(policy, jwks, *, provider_builder):
        assert type(policy) is CognitoProdPolicy and jwks == JWKS
        runtime = _FakeRuntime(provider_builder)
        made.append(runtime)
        return runtime
    monkeypatch.setattr(entry, "create_aws_prod_runtime", create)
    assert entry.handler({}, object())["statusCode"] == 200
    assert entry.handler({}, object())["statusCode"] == 200
    assert len(made) == 1 and not ssm_calls and not client_creations
    assert len(readers) == len(transports) == len(providers) == 2
    assert readers[0] is not readers[1] and providers[0] is not providers[1]
    readers[0].read_refresh_token(deadline=100.0)
    readers[1].read_refresh_token(deadline=100.0)
    assert len(ssm_calls) == 2 and len(client_creations) == 1


def test_manifest_jwks_mismatch_fails_before_runtime_or_ssm(monkeypatch):
    _reset_cache(monkeypatch)
    raw_manifest = manifest_bytes()
    monkeypatch.setenv(entry.ENV_FUNCTION, entry.FUNCTION_NAME)
    monkeypatch.setenv(entry.ENV_REGION, "eu-west-1")
    monkeypatch.setenv(entry.ENV_ENVIRONMENT, "prod")
    monkeypatch.setenv(entry.ENV_MANIFEST_SHA256, hashlib.sha256(raw_manifest).hexdigest())
    monkeypatch.setattr(entry, "_read_sibling", lambda name, _limit: raw_manifest if name == entry.MANIFEST_FILENAME else b"different")
    monkeypatch.setattr(entry, "create_aws_prod_runtime", lambda *_a, **_k: pytest.fail("runtime built"))
    monkeypatch.setattr(entry, "_ssm_client_factory", lambda: pytest.fail("SSM initialized"))
    assert entry.handler({}, object())["statusCode"] == 503


def test_default_ssm_client_uses_fixed_no_proxy_single_attempt_config(monkeypatch):
    captured = {}
    class Config:
        def __init__(self, **kwargs): captured["config_kwargs"] = kwargs; captured["config"] = self
    class Boto3:
        @staticmethod
        def client(service, **kwargs):
            captured["service"] = service
            captured.update(kwargs)
            return object()
    botocore = types.ModuleType("botocore.config")
    botocore.Config = Config
    boto3 = types.ModuleType("boto3")
    boto3.client = Boto3.client
    monkeypatch.setitem(sys.modules, "botocore.config", botocore)
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret-key")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "synthetic-session-token")
    monkeypatch.setattr(entry, "_CACHED_SSM_CLIENT", None)
    client = entry._make_ssm_client()
    assert client is not None
    assert captured["service"] == "ssm" and captured["region_name"] == "eu-west-1"
    assert captured["config_kwargs"] == {
        "retries": {"mode": "standard", "total_max_attempts": 1},
        "connect_timeout": 1, "read_timeout": 1, "proxies": {},
    }
    assert captured["aws_access_key_id"] == "synthetic-access-key"
    assert captured["aws_secret_access_key"] == "synthetic-secret-key"
    assert captured["aws_session_token"] == "synthetic-session-token"


def test_missing_lambda_role_credentials_fail_before_sdk_import(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    with pytest.raises(entry._EntryError, match="runtime_unavailable"):
        entry._make_ssm_client()
