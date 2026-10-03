from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.config import MapitConfig
from scripts import build_aws_dev_runtime as dev_builder
from scripts import build_aws_prod_runtime as builder

POLICY = CognitoProdPolicy(
    user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
    client_id="ProdClient123456", owner_subject="18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
)
CONFIG = MapitConfig(
    region="eu-west-1", user_pool_id="eu-west-1_A1b2C3d4E",
    user_pool_client_id="MapitClient123456",
    identity_pool_id="eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
    discovery_enabled=False, http_timeout=2,
)


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "fixture-repo"
    source = repo / "src" / "mapit"
    source.mkdir(parents=True)
    for name in builder.PROD_SOURCE_MODULES:
        (source / name).write_text(f"# fixture source: {name}\n", encoding="utf-8")
    (repo / "infra" / "aws").mkdir(parents=True)
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    jwks = tmp_path / "public-jwks.json"
    public = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    jwks_bytes = json.dumps({"keys": [{
        "kty": "RSA", "kid": "prod-fixture", "use": "sig", "alg": "RS256",
        "n": _b64u(public.n), "e": _b64u(public.e),
    }]}, separators=(",", ":")).encode("ascii")
    jwks.write_bytes(jwks_bytes)
    output = tmp_path / "prod-runtime.zip"
    monkeypatch.setattr(dev_builder, "_repo_root", lambda: repo)
    # Wheel validation/unpacking has its own accepted, hash-locked dev suite.
    # Here the prod test verifies that this builder selects only prod sources
    # and writes the exact same vetted wheel entries into a deterministic ZIP.
    monkeypatch.setattr(dev_builder, "_read_lock", lambda _repo: {"fixture": ("1.0", "0" * 64)})
    monkeypatch.setattr(dev_builder, "_wheel_file_inventory", lambda _root, _lock: [("fixture-1.0-py3-none-any.whl", b"locked-wheel")])
    monkeypatch.setattr(dev_builder, "_unpack_wheels", lambda _wheels, _lock: [("fixture_pkg/__init__.py", b"FIXTURE = True\n")])
    return repo, wheels, jwks, output, jwks_bytes


def build(inputs, **overrides):
    _repo, wheels, jwks, output, _raw = inputs
    args = {
        "policy": POLICY, "mapit_config": CONFIG, "account_id": "123456789012",
        "parameter_version": 1, "parameter_tier": "Standard",
    }
    args.update(overrides)
    return builder.build_prod_runtime_archive(wheels, jwks, output, **args)


def test_build_is_deterministic_prod_only_and_manifest_has_no_secrets(inputs):
    first = build(inputs)
    first_bytes = inputs[3].read_bytes()
    inputs[3].unlink()
    second = build(inputs)
    assert first == second
    assert first.sha256 == hashlib.sha256(first_bytes).hexdigest()
    assert first.zip_bytes == len(first_bytes)
    assert first.source_modules == len(builder.PROD_SOURCE_MODULES)
    assert first.public_key_count == 1 and first.manifest_valid
    with zipfile.ZipFile(inputs[3]) as archive:
        names = set(archive.namelist())
        assert "mapit/__init__.py" in names and archive.read("mapit/__init__.py") == b""
        assert "mapit/aws_prod_entrypoint.py" in names
        assert "mapit/cloud_provider.py" in names and "mapit/cloud_transport.py" in names
        assert "mapit/aws_session_reader.py" in names
        assert "mapit/aws_dev_entrypoint.py" not in names
        assert names == {"fixture_pkg/__init__.py", "mapit/__init__.py"} | {
            f"mapit/{name}" for name in builder.PROD_SOURCE_MODULES
        } | {f"mapit/{builder.JWKS_FILENAME}", f"mapit/{builder.MANIFEST_FILENAME}"}
        manifest = json.loads(archive.read(f"mapit/{builder.MANIFEST_FILENAME}"))
        assert set(manifest) == {
            "environment", "region", "account_id", "parameter_version", "parameter_tier",
            "user_pool_id", "api_id", "client_id", "owner_subject", "jwks_sha256", "mapit_config",
        }
        assert manifest["environment"] == "prod" and manifest["region"] == "eu-west-1"
        assert manifest["parameter_version"] == 1 and manifest["parameter_tier"] == "Standard"
        assert manifest["jwks_sha256"] == hashlib.sha256(inputs[4]).hexdigest()
        assert "email" not in manifest["mapit_config"] and "password" not in manifest["mapit_config"]
        assert "aws_dev_entrypoint" not in " ".join(names)


@pytest.mark.parametrize("overrides", [
    {"account_id": "bad"}, {"account_id": "000000000000"},
    {"parameter_version": True}, {"parameter_version": 2},
    {"parameter_tier": "Advanced"},
])
def test_invalid_prod_binding_fails_before_output(inputs, overrides):
    with pytest.raises(builder.ProdBuildError):
        build(inputs, **overrides)
    assert not inputs[3].exists()


def test_dev_policy_or_credentialed_config_rejected(inputs):
    from mapit.aws_dev_runtime import cognito_dev_policy
    dev_policy = cognito_dev_policy(
        user_pool_id=POLICY.user_pool_id, api_id=POLICY.api_id,
        client_id=POLICY.client_id, owner_subject=POLICY.owner_subject,
    )
    with pytest.raises(builder.ProdBuildError, match="production_policy_invalid"):
        build(inputs, policy=dev_policy)
    credentialed = MapitConfig(
        user_pool_id=CONFIG.user_pool_id, user_pool_client_id=CONFIG.user_pool_client_id,
        identity_pool_id=CONFIG.identity_pool_id, discovery_enabled=False,
        http_timeout=2, email="private@example.invalid",
    )
    with pytest.raises(builder.ProdBuildError, match="mapit_configuration_invalid"):
        build(inputs, mapit_config=credentialed)
    assert not inputs[3].exists()


def test_manifested_production_deadline_must_match_fixed_fourteen_seconds(inputs):
    variable_deadline = CognitoProdPolicy(
        user_pool_id=POLICY.user_pool_id, api_id=POLICY.api_id,
        client_id=POLICY.client_id, owner_subject=POLICY.owner_subject,
        request_deadline_seconds=13.5,
    )
    with pytest.raises(builder.ProdBuildError, match="production_policy_invalid"):
        build(inputs, policy=variable_deadline)
    assert not inputs[3].exists()


def test_mutated_prod_policy_and_missing_prod_source_are_rejected(inputs, monkeypatch):
    object.__setattr__(POLICY, "api_id", "invalid")
    with pytest.raises(builder.ProdBuildError, match="production_policy_invalid"):
        build(inputs)
    object.__setattr__(POLICY, "api_id", "a1b2c3d4e5")
    (inputs[0] / "src" / "mapit" / builder.PROD_SOURCE_MODULES[0]).unlink()
    with pytest.raises(builder.ProdBuildError, match="runtime_source_invalid"):
        build(inputs)
