from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import cognito_dev_policy
from scripts import build_aws_dev_runtime as builder


def _b64u(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture(scope="module")
def public_jwks() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
    document = {"keys": [{
        "kty": "RSA", "kid": "fixture-key", "use": "sig", "alg": "RS256",
        "n": _b64u(key.n), "e": _b64u(key.e),
    }]}
    return json.dumps(document, separators=(",", ":")).encode("ascii")


@pytest.fixture
def build_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, public_jwks: bytes):
    repo = tmp_path / "fixture-repository"
    (repo / "infra" / "aws").mkdir(parents=True)
    source_root = repo / "src" / "mapit"
    source_root.mkdir(parents=True)
    for module in builder.SOURCE_MODULES:
        (source_root / module).write_text(f"# fixed fixture source: {module}\n", encoding="utf-8")

    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    lock_lines: list[str] = []
    for name in sorted(builder.EXPECTED_DISTRIBUTIONS):
        version = "1.0.0"
        dist_dir = f"{name.replace('-', '_')}-{version}.dist-info"
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        wheel_path = wheel_dir / filename
        with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"fixture_{name.replace('-', '_')}/__init__.py", b"VALUE = 1\n")
            archive.writestr(
                f"{dist_dir}/METADATA",
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n".encode(),
            )
            archive.writestr(f"{dist_dir}/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
            archive.writestr(f"{dist_dir}/RECORD", b"")
        digest = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
        lock_lines.append(f"{name}=={version} --hash=sha256:{digest}")
    (repo / "infra" / "aws" / "runtime-requirements.txt").write_text(
        "# synthetic fixture lock\n" + "\n".join(lock_lines) + "\n", encoding="utf-8"
    )
    jwks_path = tmp_path / "public-jwks.json"
    jwks_path.write_bytes(public_jwks)
    output_path = tmp_path / "runtime.zip"
    monkeypatch.setattr(builder, "_repo_root", lambda: repo)
    policy = cognito_dev_policy(
        user_pool_id="eu-west-1_abcdefghijk",
        api_id="a1b2c3d4e5",
        client_id="publicclient123",
        owner_subject="12345678-1234-4234-8234-123456789abc",
    )
    return repo, wheel_dir, jwks_path, output_path, policy


def test_tracked_runtime_lock_has_exact_expected_inventory() -> None:
    lock = builder._read_lock(builder._repo_root())
    assert len(lock) == 28
    assert set(lock) == set(builder.EXPECTED_DISTRIBUTIONS)
    assert all(len(digest) == 64 for _, digest in lock.values())


def test_valid_fixture_build_is_deterministic_fixed_allowlist_and_safe_manifest(build_inputs, public_jwks: bytes) -> None:
    _, wheel_dir, jwks_path, output_path, policy = build_inputs
    first = builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    first_bytes = output_path.read_bytes()
    output_path.unlink()
    second = builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    assert first == second
    assert first.zip_bytes == len(first_bytes)
    assert first.sha256 == hashlib.sha256(first_bytes).hexdigest()
    assert (first.wheel_count, first.source_modules, first.public_key_count) == (28, 14, 1)
    assert first.dependencies_valid and first.source_allowlist_valid and first.lock_valid and first.manifest_valid
    with zipfile.ZipFile(output_path) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert "mapit/__init__.py" in names
        assert archive.read("mapit/__init__.py") == b""
        assert {f"mapit/{name}" for name in builder.SOURCE_MODULES} <= set(names)
        snapshot_path = f"mapit/{builder.JWKS_SNAPSHOT_FILENAME}"
        manifest_path = f"mapit/{builder.JWKS_MANIFEST_FILENAME}"
        assert snapshot_path in names
        assert manifest_path in names
        assert archive.read(snapshot_path) == public_jwks
        manifest = json.loads(archive.read(manifest_path))
        assert set(manifest) == {"issuer", "jwks_uri", "sha256"}
        assert manifest["issuer"] == policy.issuer_url
        assert manifest["jwks_uri"] == f"{policy.issuer_url}/.well-known/jwks.json"
        assert manifest["sha256"] == hashlib.sha256(public_jwks).hexdigest()
        assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)


def test_extra_or_missing_wheel_is_rejected(build_inputs) -> None:
    _, wheel_dir, jwks_path, output_path, policy = build_inputs
    extra = wheel_dir / "unexpected-1.0.0-py3-none-any.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(builder.BuildError, match="wheel_inventory_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    extra.unlink()
    first = next(wheel_dir.glob("*.whl"))
    first.unlink()
    with pytest.raises(builder.BuildError, match="wheel_inventory_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)


def test_wheel_digest_must_match_the_pinned_lock(build_inputs) -> None:
    _, wheel_dir, jwks_path, output_path, policy = build_inputs
    first = next(wheel_dir.glob("*.whl"))
    first.write_bytes(first.read_bytes() + b"tamper")
    with pytest.raises(builder.BuildError, match="wheel_hash_mismatch"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)


@pytest.mark.parametrize("bad_path", ["pkg/../escape.py", "pkg\\escape.py", "pkg/module.pth", "pkg/.data/x.py", "mapit/forged.py"])
def test_wheel_unsafe_paths_are_rejected(build_inputs, bad_path: str) -> None:
    repo, wheel_dir, jwks_path, output_path, policy = build_inputs
    first = next(wheel_dir.glob("*.whl"))
    with zipfile.ZipFile(first) as current:
        original = current.namelist()
    with zipfile.ZipFile(first, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in original:
            archive.writestr(name, b"x" if name.endswith("__init__.py") else b"")
        archive.writestr(bad_path, b"bad")
    lock_path = repo / "infra" / "aws" / "runtime-requirements.txt"
    lines = lock_path.read_text(encoding="utf-8").splitlines()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    filename_name = builder._canonical_dist_name(first.name.split("-", 1)[0])
    lock_lines = []
    for line in lines:
        if line.startswith(filename_name + "=="):
            lock_lines.append(f"{filename_name}==1.0.0 --hash=sha256:{digest}")
        else:
            lock_lines.append(line)
    lock_path.write_text("\n".join(lock_lines) + "\n", encoding="utf-8")
    with pytest.raises(builder.BuildError):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)


def test_wheel_test_and_cache_entries_are_omitted_from_archive(build_inputs) -> None:
    repo, wheel_dir, jwks_path, output_path, policy = build_inputs
    first = next(wheel_dir.glob("*.whl"))
    with zipfile.ZipFile(first) as current:
        old_entries = [(item.filename, current.read(item)) for item in current.infolist()]
    with zipfile.ZipFile(first, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in old_entries:
            archive.writestr(name, data)
        archive.writestr("fixture_pkg/tests/test_runtime.py", b"not packaged")
        archive.writestr("fixture_pkg/__pycache__/runtime.pyc", b"not packaged")
    lock_path = repo / "infra" / "aws" / "runtime-requirements.txt"
    lines = lock_path.read_text(encoding="utf-8").splitlines()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    filename_name = builder._canonical_dist_name(first.name.split("-", 1)[0])
    lock_path.write_text("\n".join(
        f"{filename_name}==1.0.0 --hash=sha256:{digest}" if line.startswith(filename_name + "==") else line
        for line in lines
    ) + "\n", encoding="utf-8")
    builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    with zipfile.ZipFile(output_path) as archive:
        assert not any("/tests/" in f"/{name}" or "__pycache__" in name or name.endswith(".pyc") for name in archive.namelist())


def test_bad_public_jwks_and_mutated_policy_fail_closed(build_inputs) -> None:
    _, wheel_dir, jwks_path, output_path, policy = build_inputs
    jwks_path.write_bytes(b'{"keys":[]}')
    with pytest.raises(builder.BuildError, match="public_jwks_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    object.__setattr__(policy, "api_id", "invalid-id")
    with pytest.raises(builder.BuildError, match="runtime_identity_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)


def test_existing_or_repository_output_is_rejected(build_inputs) -> None:
    repo, wheel_dir, jwks_path, output_path, policy = build_inputs
    output_path.write_bytes(b"existing")
    with pytest.raises(builder.BuildError, match="output_path_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    output_path.unlink()
    with pytest.raises(builder.BuildError, match="output_path_invalid"):
        builder.build_runtime_archive(wheel_dir, jwks_path, repo / "inside.zip", policy)


def test_bounded_file_read_rejects_oversize_using_precheck(tmp_path: Path) -> None:
    source = tmp_path / "oversized.bin"
    source.write_bytes(b"12345")
    with pytest.raises(builder.BuildError, match="bounded_test"):
        builder._read_bounded(source, 4, "bounded_test")


def test_wheel_entry_size_is_rejected_before_decompression(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoReadArchive:
        def open(self, *_args, **_kwargs):
            raise AssertionError("oversized member must be rejected before opening")

    member = zipfile.ZipInfo("pkg/big.bin")
    member.file_size = 5
    monkeypatch.setattr(builder, "MAX_ENTRY_BYTES", 4)
    with pytest.raises(builder.BuildError, match="wheel_uncompressed_size_exceeded"):
        builder._wheel_entry_bytes(NoReadArchive(), member, 0)  # type: ignore[arg-type]
