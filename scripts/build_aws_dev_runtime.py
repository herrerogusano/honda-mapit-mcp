"""Build a deterministic, offline ZIP for the synthetic dev Lambda runtime.

The builder consumes only locally supplied, hash-locked wheels, fixed source
modules and a validated public Cognito JWKS snapshot. It never invokes pip,
network, AWS, a credential provider, or a runtime session loader.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from mapit.aws_dev_runtime import CognitoDevPolicy, cognito_dev_policy, parse_cognito_jwks

MAX_INPUT_BYTES = 100 * 1024 * 1024
MAX_ENTRY_BYTES = 50 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_FILE_COUNT = 20_000
MAX_LOCK_BYTES = 16 * 1024
MAX_JWKS_BYTES = 32 * 1024
MAX_MANIFEST_BYTES = 2 * 1024
MAX_BINDING_BYTES = 4 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

EXPECTED_DISTRIBUTIONS = frozenset({
    "annotated-types", "anyio", "attrs", "cffi", "click", "cryptography", "h11", "httpcore2",
    "httpx2", "idna", "jsonschema-specifications", "jsonschema", "mcp-types", "mcp",
    "opentelemetry-api", "pycparser", "pydantic-core", "pydantic", "pyjwt", "python-multipart",
    "referencing", "rpds-py", "sse-starlette", "starlette", "truststore", "typing-extensions",
    "typing-inspection", "uvicorn",
})

SOURCE_MODULES = (
    "aws_dev_entrypoint.py",
    "aws_dev_runtime.py",
    "lambda_adapter.py",
    "remote_http.py",
    "mcp_server.py",
    "services.py",
    "analytics.py",
    "distance_units.py",
    "client.py",
    "session.py",
    "auth.py",
    "config.py",
    "http_transport.py",
    "signing.py",
)
JWKS_SNAPSHOT_FILENAME = "cognito-public-jwks.json"
JWKS_MANIFEST_FILENAME = "cognito-public-jwks.manifest.json"
_LOCK_LINE = re.compile(
    r"^([a-z0-9]+(?:-[a-z0-9]+)*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*) --hash=sha256:([0-9a-f]{64})$"
)
_WHEEL_NAME = re.compile(r"^([A-Za-z0-9_]+)-([A-Za-z0-9.+!]+)-([^-]+)-([^-]+)-([^-]+)\.whl$")
_PRIVATE_NAMES = frozenset({
    "credentials", "credentials.json", "aws_credentials", "id_rsa", "id_ed25519",
    "private.pem", "private.key", "token", "token.json", ".env", ".ssh",
})
_TEST_DIRS = frozenset({"test", "tests", "testing", "__pycache__"})


class BuildError(ValueError):
    """Fixed-category local build error without source values or paths."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Argparse variant that never echoes caller-supplied argument values."""

    def error(self, message: str) -> None:
        raise BuildError("runtime_binding_source_invalid")


@dataclass(frozen=True)
class BuildSummary:
    zip_bytes: int
    sha256: str
    wheel_count: int
    archive_entries: int
    source_modules: int
    public_key_count: int
    dependencies_valid: bool
    source_allowlist_valid: bool
    lock_valid: bool
    manifest_valid: bool


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _canonical_dist_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        raise BuildError("input_invalid") from None
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _has_symlink_or_reparse_ancestor(path: Path) -> bool:
    current = path.absolute()
    while True:
        try:
            if _is_reparse_or_symlink(current):
                return True
        except BuildError:
            return True
        if current.parent == current:
            return False
        current = current.parent


def _outside_repo_and_onedrive(path: Path, repo: Path, category: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        repo_resolved = repo.resolve(strict=True)
    except OSError:
        raise BuildError(category) from None
    if _inside(resolved, repo_resolved) or any(_is_onedrive_component(part) for part in resolved.parts):
        raise BuildError(category)
    return resolved


def _is_onedrive_component(part: str) -> bool:
    folded = part.casefold()
    return folded == "onedrive" or folded.startswith("onedrive - ")


def _read_bounded(path: Path, limit: int, category: str) -> bytes:
    try:
        size = path.stat().st_size
        if size > limit:
            raise BuildError(category)
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except BuildError:
        raise
    except OSError:
        raise BuildError(category) from None
    if len(data) > limit or len(data) != size:
        raise BuildError(category)
    return data


def _read_lock(repo: Path) -> dict[str, tuple[str, str]]:
    lock_path = repo / "infra" / "aws" / "runtime-requirements.txt"
    if _has_symlink_or_reparse_ancestor(lock_path) or not lock_path.is_file():
        raise BuildError("runtime_lock_invalid")
    raw = _read_bounded(lock_path, MAX_LOCK_BYTES, "runtime_lock_invalid")
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        raise BuildError("runtime_lock_invalid") from None
    result: dict[str, tuple[str, str]] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        match = _LOCK_LINE.fullmatch(line)
        if match is None:
            raise BuildError("runtime_lock_invalid")
        name, version, digest = match.groups()
        if name in result:
            raise BuildError("runtime_lock_invalid")
        result[name] = (version, digest)
    if len(result) != 28 or frozenset(result) != EXPECTED_DISTRIBUTIONS:
        raise BuildError("runtime_lock_invalid")
    return result


def _validate_external_wheel_dir(path: Path, repo: Path) -> Path:
    if _has_symlink_or_reparse_ancestor(path) or not path.is_dir():
        raise BuildError("wheel_directory_invalid")
    resolved = _outside_repo_and_onedrive(path, repo, "wheel_directory_invalid")
    return resolved


def _wheel_file_inventory(wheel_dir: Path, locked: dict[str, tuple[str, str]]) -> list[tuple[str, bytes]]:
    try:
        children = list(wheel_dir.iterdir())
    except OSError:
        raise BuildError("wheel_directory_invalid") from None
    if len(children) != len(locked):
        raise BuildError("wheel_inventory_invalid")
    seen: set[str] = set()
    total_input = 0
    wheels: list[tuple[str, bytes]] = []
    for child in sorted(children, key=lambda p: p.name.casefold()):
        if _is_reparse_or_symlink(child) or not child.is_file() or child.suffix != ".whl":
            raise BuildError("wheel_inventory_invalid")
        match = _WHEEL_NAME.fullmatch(child.name)
        if match is None:
            raise BuildError("wheel_name_invalid")
        distribution = _canonical_dist_name(match.group(1))
        version = match.group(2).replace("_", ".")
        if distribution not in locked or locked[distribution][0] != version or distribution in seen:
            raise BuildError("wheel_name_invalid")
        try:
            size = child.stat().st_size
        except OSError:
            raise BuildError("wheel_file_invalid") from None
        if size > MAX_INPUT_BYTES or total_input + size > MAX_INPUT_BYTES:
            raise BuildError("wheel_input_size_exceeded")
        data = _read_bounded(child, MAX_INPUT_BYTES, "wheel_file_invalid")
        if hashlib.sha256(data).hexdigest() != locked[distribution][1]:
            raise BuildError("wheel_hash_mismatch")
        seen.add(distribution)
        total_input += len(data)
        wheels.append((child.name, data))
    if seen != set(locked):
        raise BuildError("wheel_inventory_invalid")
    return wheels


def _safe_wheel_entry_name(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise BuildError("wheel_path_invalid")
    candidate = name[:-1] if name.endswith("/") else name
    parts = candidate.split("/")
    if not candidate or any(part in ("", ".", "..") for part in parts):
        raise BuildError("wheel_path_invalid")
    lowered = [part.casefold() for part in parts]
    if any(part == ".data" or part.endswith(".data") for part in lowered):
        raise BuildError("wheel_data_path_unsupported")
    for part in lowered:
        if (
            part in _PRIVATE_NAMES
            or part.startswith(".env.")
            or part.endswith((".pth", ".p12", ".pfx", ".key"))
        ):
            raise BuildError("wheel_private_or_runtime_path_rejected")
    if lowered[0] == "mapit":
        raise BuildError("wheel_test_or_reserved_source_path_rejected")
    return candidate


def _exclude_wheel_entry(path: str) -> bool:
    lowered = path.casefold().split("/")
    basename = lowered[-1]
    return (
        any(part in _TEST_DIRS for part in lowered)
        or basename.endswith(".pyc")
        or basename.startswith("test_")
        or basename.endswith("_test.py")
    )


def _validate_zip_entry_type(info: zipfile.ZipInfo) -> None:
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR) or (info.is_dir() and kind == stat.S_IFREG):
        raise BuildError("wheel_archive_special_file_rejected")
    if not info.is_dir() and kind == stat.S_IFDIR:
        raise BuildError("wheel_archive_special_file_rejected")


def _wheel_entry_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo, total: int) -> bytes:
    if info.file_size < 0 or info.file_size > MAX_ENTRY_BYTES or total + info.file_size > MAX_TOTAL_BYTES:
        raise BuildError("wheel_uncompressed_size_exceeded")
    if info.flag_bits & 0x1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise BuildError("wheel_archive_format_invalid")
    _validate_zip_entry_type(info)
    try:
        with archive.open(info, "r") as stream:
            data = stream.read(MAX_ENTRY_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
        raise BuildError("wheel_archive_invalid") from None
    if len(data) > MAX_ENTRY_BYTES or len(data) != info.file_size:
        raise BuildError("wheel_entry_size_invalid")
    return data


def _validate_wheel_filename_and_metadata(filename: str, entries: list[tuple[str, bytes]], locked: dict[str, tuple[str, str]]) -> None:
    match = _WHEEL_NAME.fullmatch(filename)
    if match is None:
        raise BuildError("wheel_name_invalid")
    name = _canonical_dist_name(match.group(1))
    version = match.group(2).replace("_", ".")
    metadata_entries = [(path, data) for path, data in entries if path.endswith(".dist-info/METADATA")]
    if len(metadata_entries) != 1:
        raise BuildError("wheel_metadata_invalid")
    metadata_path, metadata = metadata_entries[0]
    expected_dist_info = f"{match.group(1)}-{match.group(2)}.dist-info"
    dist_info_roots = {path.split("/", 1)[0] for path, _ in entries if ".dist-info/" in path}
    if dist_info_roots != {expected_dist_info}:
        raise BuildError("wheel_metadata_mismatch")
    try:
        text = metadata.decode("utf-8", errors="strict")
    except UnicodeError:
        raise BuildError("wheel_metadata_invalid") from None
    names = [line[6:] for line in text.splitlines() if line.startswith("Name: ")]
    versions = [line[9:] for line in text.splitlines() if line.startswith("Version: ")]
    if len(names) != 1 or len(versions) != 1:
        raise BuildError("wheel_metadata_invalid")
    if (
        _canonical_dist_name(names[0]) != name
        or versions[0] != version
        or locked.get(name, (None, None))[0] != version
        or metadata_path.split("/", 1)[0] != expected_dist_info
    ):
        raise BuildError("wheel_metadata_mismatch")


def _unpack_wheels(wheels: list[tuple[str, bytes]], locked: dict[str, tuple[str, str]]) -> list[tuple[str, bytes]]:
    result: list[tuple[str, bytes]] = []
    seen_paths: set[str] = set()
    count = 0
    total_uncompressed = 0
    for filename, raw in wheels:
        try:
            with zipfile.ZipFile(__import__("io").BytesIO(raw), "r") as archive:
                infos = archive.infolist()
                if not infos or len(infos) > MAX_FILE_COUNT:
                    raise BuildError("wheel_file_count_invalid")
                names: set[str] = set()
                current_entries: list[tuple[str, bytes]] = []
                for info in infos:
                    count += 1
                    if count > MAX_FILE_COUNT:
                        raise BuildError("archive_file_count_exceeded")
                    path = _safe_wheel_entry_name(info.filename)
                    _validate_zip_entry_type(info)
                    folded = path.casefold()
                    if folded in names:
                        raise BuildError("wheel_duplicate_path")
                    names.add(folded)
                    if (
                        info.file_size < 0
                        or info.file_size > MAX_ENTRY_BYTES
                        or total_uncompressed + info.file_size > MAX_TOTAL_BYTES
                    ):
                        raise BuildError("wheel_uncompressed_size_exceeded")
                    previous_total = total_uncompressed
                    total_uncompressed += info.file_size
                    if info.is_dir():
                        continue
                    if _exclude_wheel_entry(path):
                        continue
                    data = _wheel_entry_bytes(archive, info, previous_total)
                    if folded in seen_paths:
                        raise BuildError("archive_path_collision")
                    seen_paths.add(folded)
                    current_entries.append((path, data))
                _validate_wheel_filename_and_metadata(filename, current_entries, locked)
                result.extend(current_entries)
        except BuildError:
            raise
        except (OSError, RuntimeError, zipfile.BadZipFile, EOFError):
            raise BuildError("wheel_archive_invalid") from None
    return result


def _validate_policy(policy: CognitoDevPolicy) -> CognitoDevPolicy:
    if type(policy) is not CognitoDevPolicy:
        raise BuildError("runtime_identity_invalid")
    try:
        return cognito_dev_policy(
            user_pool_id=policy.user_pool_id,
            api_id=policy.api_id,
            client_id=policy.client_id,
            owner_subject=policy.owner_subject,
        )
    except (AttributeError, TypeError, ValueError):
        raise BuildError("runtime_identity_invalid") from None


def _reject_duplicate_binding_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BuildError("runtime_binding_invalid")
        result[key] = value
    return result


def _read_binding_file(path: Path, repo: Path) -> CognitoDevPolicy:
    """Load a tiny exact-field binding from an operator-protected external file.

    The builder checks location and bounded syntax, not filesystem ACLs. The
    caller must create the file outside the checkout/OneDrive with a private
    ACL verified for the operator before use.
    """
    if _has_symlink_or_reparse_ancestor(path) or not path.is_file():
        raise BuildError("runtime_binding_file_invalid")
    resolved = _outside_repo_and_onedrive(path, repo, "runtime_binding_file_invalid")
    try:
        if resolved.stat().st_size > MAX_BINDING_BYTES:
            raise BuildError("runtime_binding_file_invalid")
    except BuildError:
        raise
    except OSError:
        raise BuildError("runtime_binding_file_invalid") from None
    raw = _read_bounded(resolved, MAX_BINDING_BYTES, "runtime_binding_file_invalid")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_binding_keys,
        )
    except BuildError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise BuildError("runtime_binding_invalid") from None
    required = {"user_pool_id", "api_id", "client_id", "owner_subject"}
    if not isinstance(value, dict) or set(value) != required or any(type(value[key]) is not str for key in required):
        raise BuildError("runtime_binding_invalid")
    try:
        policy = cognito_dev_policy(
            user_pool_id=value["user_pool_id"],
            api_id=value["api_id"],
            client_id=value["client_id"],
            owner_subject=value["owner_subject"],
        )
    except (AttributeError, TypeError, ValueError):
        raise BuildError("runtime_binding_invalid") from None
    return _validate_policy(policy)


def _snapshot_file(path: Path, repo: Path) -> bytes:
    if _has_symlink_or_reparse_ancestor(path) or not path.is_file():
        raise BuildError("public_jwks_file_invalid")
    _outside_repo_and_onedrive(path, repo, "public_jwks_file_invalid")
    return _read_bounded(path, MAX_JWKS_BYTES, "public_jwks_invalid")


def _source_entries(repo: Path) -> list[tuple[str, bytes]]:
    source_root = repo / "src" / "mapit"
    if _has_symlink_or_reparse_ancestor(source_root) or not source_root.is_dir():
        raise BuildError("runtime_source_invalid")
    result = [("mapit/__init__.py", b"")]
    for module in SOURCE_MODULES:
        path = source_root / module
        if _has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise BuildError("runtime_source_invalid")
        data = _read_bounded(path, MAX_SOURCE_BYTES, "runtime_source_invalid")
        result.append((f"mapit/{module}", data))
    return result


def _output_path(path: Path, repo: Path, wheel_dir: Path, jwks_path: Path) -> Path:
    if path.exists() or path.is_symlink() or _has_symlink_or_reparse_ancestor(path.parent):
        raise BuildError("output_path_invalid")
    try:
        resolved = path.resolve(strict=False)
        repo_real = repo.resolve(strict=True)
        wheel_real = wheel_dir.resolve(strict=True)
        jwks_real = jwks_path.resolve(strict=True)
    except OSError:
        raise BuildError("output_path_invalid") from None
    if (
        _inside(resolved, repo_real)
        or _inside(resolved, wheel_real)
        or resolved == jwks_real
        or any(_is_onedrive_component(part) for part in resolved.parts)
        or not resolved.parent.is_dir()
    ):
        raise BuildError("output_path_invalid")
    return resolved


def build_runtime_archive(
    wheel_dir: Path,
    public_jwks_path: Path,
    output_path: Path,
    policy: CognitoDevPolicy,
) -> BuildSummary:
    """Build the fixed dev Lambda ZIP from exact local inputs, without network."""
    repo = _repo_root()
    if _is_reparse_or_symlink(repo) or not repo.is_dir():
        raise BuildError("repository_invalid")
    lock = _read_lock(repo)
    wheel_root = _validate_external_wheel_dir(Path(wheel_dir), repo)
    jwks_file = Path(public_jwks_path)
    jwks_bytes = _snapshot_file(jwks_file, repo)
    target = _output_path(Path(output_path), repo, wheel_root, jwks_file)
    validated_policy = _validate_policy(policy)
    try:
        public_keys = parse_cognito_jwks(jwks_bytes)
    except (TypeError, ValueError):
        raise BuildError("public_jwks_invalid") from None
    if not public_keys:
        raise BuildError("public_jwks_invalid")

    wheel_files = _wheel_file_inventory(wheel_root, lock)
    wheel_entries = _unpack_wheels(wheel_files, lock)
    source_entries = _source_entries(repo)
    manifest_bytes = json.dumps(
        {
            "issuer": validated_policy.issuer_url,
            "jwks_uri": f"{validated_policy.issuer_url}/.well-known/jwks.json",
            "sha256": hashlib.sha256(jwks_bytes).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BuildError("public_jwks_manifest_oversized")
    fixed_entries = [
        *wheel_entries,
        *source_entries,
        (f"mapit/{JWKS_SNAPSHOT_FILENAME}", jwks_bytes),
        (f"mapit/{JWKS_MANIFEST_FILENAME}", manifest_bytes),
    ]
    seen: set[str] = set()
    total_bytes = 0
    for name, data in fixed_entries:
        folded = name.casefold()
        if folded in seen:
            raise BuildError("archive_path_collision")
        seen.add(folded)
        if len(data) > MAX_ENTRY_BYTES or total_bytes + len(data) > MAX_TOTAL_BYTES:
            raise BuildError("archive_content_too_large")
        total_bytes += len(data)
    if len(fixed_entries) > MAX_FILE_COUNT:
        raise BuildError("archive_file_count_exceeded")

    import io

    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(
            buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True
        ) as archive:
            for name, data in sorted(fixed_entries, key=lambda item: item[0]):
                info = zipfile.ZipInfo(name, date_time=ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        zip_bytes = buffer.getvalue()
        if len(zip_bytes) > MAX_ARCHIVE_BYTES:
            raise BuildError("archive_compressed_size_exceeded")
        with target.open("xb") as output:
            output.write(zip_bytes)
    except BuildError:
        raise
    except OSError:
        raise BuildError("archive_write_failed") from None
    return BuildSummary(
        zip_bytes=len(zip_bytes),
        sha256=hashlib.sha256(zip_bytes).hexdigest(),
        wheel_count=len(wheel_files),
        archive_entries=len(fixed_entries),
        source_modules=len(SOURCE_MODULES),
        public_key_count=len(public_keys),
        dependencies_valid=True,
        source_allowlist_valid=True,
        lock_valid=True,
        manifest_valid=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _SafeArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--public-jwks", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    try:
        parser.add_argument("--binding-file", type=Path)
        parser.add_argument("--user-pool-id")
        parser.add_argument("--api-id")
        parser.add_argument("--client-id")
        parser.add_argument("--owner-subject")
        args = parser.parse_args(argv)
        legacy_values = (args.user_pool_id, args.api_id, args.client_id, args.owner_subject)
        if args.binding_file is not None:
            if any(value is not None for value in legacy_values):
                raise BuildError("runtime_binding_source_invalid")
            policy = _read_binding_file(args.binding_file, _repo_root())
        elif all(value is not None for value in legacy_values):
            policy = cognito_dev_policy(
                user_pool_id=args.user_pool_id,
                api_id=args.api_id,
                client_id=args.client_id,
                owner_subject=args.owner_subject,
            )
        else:
            raise BuildError("runtime_binding_source_invalid")
        summary = build_runtime_archive(args.wheel_dir, args.public_jwks, args.output, policy)
    except SystemExit as exc:
        return 0 if exc.code == 0 else 1
    except Exception:
        print(json.dumps({"success": False, "category": "runtime_package_build_failed"}))
        return 1
    print(json.dumps({
        "success": True,
        "category": "runtime_package_built",
        "zip_bytes": summary.zip_bytes,
        "sha256": summary.sha256,
        "wheel_count": summary.wheel_count,
        "archive_entries": summary.archive_entries,
        "source_modules": summary.source_modules,
        "public_key_count": summary.public_key_count,
        "dependencies_valid": summary.dependencies_valid,
        "source_allowlist_valid": summary.source_allowlist_valid,
        "lock_valid": summary.lock_valid,
        "manifest_valid": summary.manifest_valid,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
