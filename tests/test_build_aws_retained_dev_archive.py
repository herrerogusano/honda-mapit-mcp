from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts import build_aws_dev_runtime as historical
from scripts import build_aws_retained_dev_archive as builder
from scripts.aws_retained_dev_delivery_artifact import publish_retained_dev_runtime
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest


SOURCE = "a" * 40
API = "a1b2c3d4e5"


def _b64u(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "fixture-repository"
    (repo / "infra" / "aws").mkdir(parents=True)
    source = repo / "src" / "mapit"
    source.mkdir(parents=True)
    for module in historical.SOURCE_MODULES:
        (source / module).write_text(f"# synthetic retained source: {module}\n", encoding="utf-8")
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    lock = []
    for name in sorted(historical.EXPECTED_DISTRIBUTIONS):
        version = "1.0.0"
        dist = f"{name.replace('-', '_')}-{version}.dist-info"
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        path = wheels / filename
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"fixture_{name.replace('-', '_')}/__init__.py", b"VALUE = 1\n")
            archive.writestr(f"{dist}/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode())
            archive.writestr(f"{dist}/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            archive.writestr(f"{dist}/RECORD", b"")
        lock.append(f"{name}=={version} --hash=sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}")
    (repo / "infra" / "aws" / "runtime-requirements.txt").write_text("# fixture\n" + "\n".join(lock) + "\n", encoding="utf-8")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    jwks = json.dumps({"keys": [{"kty": "RSA", "kid": "fixture-key", "use": "sig", "alg": "RS256", "n": _b64u(key.n), "e": _b64u(key.e)}]}, separators=(",", ":")).encode("ascii")
    jwks_path = tmp_path / "public-jwks.json"
    jwks_path.write_bytes(jwks)
    output = tmp_path / "retained-runtime.zip"
    monkeypatch.setattr(builder, "_repo_root", lambda: repo)
    return repo, wheels, jwks_path, output, hashlib.sha256(jwks).hexdigest()


def test_deterministic_retained_archive_contains_builder_manifests(inputs):
    _, wheels, jwks, output, jwks_sha = inputs
    first = builder.build_retained_dev_archive(wheels, jwks, output, source_sha=SOURCE, api_id=API, jwks_sha256=jwks_sha)
    first_bytes = output.read_bytes()
    output.unlink()
    second = builder.build_retained_dev_archive(wheels, jwks, output, source_sha=SOURCE, api_id=API, jwks_sha256=jwks_sha)
    assert first == second and first.sha256 == hashlib.sha256(first_bytes).hexdigest()
    assert first.dependencies_valid and first.source_allowlist_valid and first.lock_valid and first.manifest_valid
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert "mapit/cognito-public-jwks.json" in names
        assert "mapit/cognito-public-jwks.manifest.json" in names
        manifest_path = "mapit/retained-dev.manifest.json"
        expected = build_retained_dev_manifest(SOURCE, API, jwks_sha)
        assert json.loads(archive.read(manifest_path)) == expected
        assert archive.read("mapit/cognito-public-jwks.json") == jwks.read_bytes()


def test_explicit_jwks_digest_and_identity_inputs_are_required(inputs):
    _, wheels, jwks, output, jwks_sha = inputs
    with pytest.raises(builder.RetainedDevArchiveError, match="public_jwks_digest_mismatch"):
        builder.build_retained_dev_archive(wheels, jwks, output, source_sha=SOURCE, api_id=API, jwks_sha256="b" * 64)
    with pytest.raises(builder.RetainedDevArchiveError, match="runtime_identity_invalid"):
        builder.build_retained_dev_archive(wheels, jwks, output, source_sha="bad", api_id=API, jwks_sha256=jwks_sha)
    with pytest.raises(builder.RetainedDevArchiveError, match="runtime_identity_invalid"):
        builder.build_retained_dev_archive(wheels, jwks, output, source_sha=SOURCE, api_id="bad", jwks_sha256=jwks_sha)


def test_output_is_create_only(inputs):
    _, wheels, jwks, output, jwks_sha = inputs
    output.write_bytes(b"existing")
    with pytest.raises(builder.RetainedDevArchiveError, match="output_path_invalid"):
        builder.build_retained_dev_archive(wheels, jwks, output, source_sha=SOURCE, api_id=API, jwks_sha256=jwks_sha)


class _PublisherJournal:
    def __init__(self):
        self.state = None

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return self.state

    def compare_and_set(self, expected, value):
        current = self.state.get("revision") if isinstance(self.state, dict) else None
        if current != expected:
            return False
        self.state = dict(value)
        return True


class _PublisherS3:
    def __init__(self):
        self.body = None

    def put_object(self, **kwargs):
        self.body = kwargs["Body"]
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def head_object(self, **kwargs):
        return {
            "ContentLength": len(self.body),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(self.body).digest()).decode("ascii"),
            "ServerSideEncryption": "AES256",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


def test_actual_builder_receipt_is_required_by_publisher(inputs):
    _, wheels, jwks, output, jwks_sha = inputs
    summary = builder.build_retained_dev_archive(
        wheels, jwks, output, source_sha=SOURCE, api_id=API, jwks_sha256=jwks_sha,
    )
    assert summary.receipt.validate()
    with pytest.raises(AttributeError):
        summary.receipt.source_sha = "b" * 40
    s3 = _PublisherS3()
    result = publish_retained_dev_runtime(
        s3, _PublisherJournal(), bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        expected_owner="123456789012", run_id="12345678-1234-4234-8234-123456789abc",
        archive_path=output, build_receipt=summary.receipt,
        authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000,
        wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0,
    )
    assert result.success and result.head_verified

    counterfeit = output.with_name("counterfeit-retained-runtime.zip")
    with zipfile.ZipFile(output, "r") as source, zipfile.ZipFile(counterfeit, "w") as target:
        for info in source.infolist():
            data = source.read(info)
            if info.filename == "mapit/aws_dev_entrypoint.py":
                data += b"\n# counterfeit\n"
            target.writestr(info.filename, data)
    rejected_s3 = _PublisherS3()
    rejected = publish_retained_dev_runtime(
        rejected_s3, _PublisherJournal(), bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        expected_owner="123456789012", run_id="12345678-1234-4234-8234-123456789abc",
        archive_path=counterfeit, build_receipt=summary.receipt,
        authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000,
        wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0,
    )
    assert rejected.category == "artifact_hash_mismatch" and rejected_s3.body is None
