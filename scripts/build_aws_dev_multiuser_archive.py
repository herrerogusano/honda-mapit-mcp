"""Offline, deterministic packaging of the explicitly synthetic two-user DEV runtime.

Private identity bindings stay in an external input and output, never in a
GitHub artifact. Dependencies reuse the existing reviewed, hash-locked ARM
wheel parser. This factory does not fetch wheels, keys or credentials.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import zipfile

from mapit.aws_dev_multiuser_entrypoint import (
    JWKS_FILENAME, MANIFEST_FILENAME, MAX_MANIFEST_BYTES, parse_manifest,
)
from mapit.aws_dev_runtime import parse_cognito_jwks
from scripts import build_aws_dev_runtime as base

SOURCE_MODULES = tuple(name for name in base.SOURCE_MODULES if name != "aws_dev_entrypoint.py") + (
    "aws_dev_multiuser_entrypoint.py", "aws_durable_tenants.py", "durable_tenants.py",
    "invited_lambda.py", "invited_mcp.py", "tenant_router.py", "aws_prod_runtime.py",
    "cloud_provider.py", "cloud_transport.py",
)


def build_dev_multiuser_archive(wheel_dir: Path, manifest_path: Path, jwks_path: Path,
                                output_path: Path, *, account_id: str) -> base.BuildSummary:
    repo = base._repo_root()
    lock = base._read_lock(repo)
    wheel_root = base._validate_external_wheel_dir(Path(wheel_dir), repo)
    for path in (Path(manifest_path), Path(jwks_path)):
        if base._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise base.BuildError("runtime_binding_file_invalid")
        base._outside_repo_and_onedrive(path, repo, "runtime_binding_file_invalid")
    raw = base._read_bounded(Path(manifest_path), MAX_MANIFEST_BYTES, "runtime_binding_invalid")
    digest = hashlib.sha256(raw).hexdigest()
    value = parse_manifest(raw, expected_digest=digest, account_id=account_id)
    jwks = base._snapshot_file(Path(jwks_path), repo)
    keys = parse_cognito_jwks(jwks)
    if hashlib.sha256(jwks).hexdigest() != value["jwks_sha256"]:
        raise base.BuildError("public_jwks_invalid")
    target = base._output_path(Path(output_path), repo, wheel_root, Path(jwks_path))
    if target == Path(manifest_path).resolve():
        raise base.BuildError("output_path_invalid")
    wheels = base._wheel_file_inventory(wheel_root, lock)
    entries = base._unpack_wheels(wheels, lock)
    entries.append(("mapit/__init__.py", b""))
    source_root = repo / "src" / "mapit"
    for name in SOURCE_MODULES:
        path = source_root / name
        if base._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise base.BuildError("runtime_source_invalid")
        entries.append((f"mapit/{name}", base._read_bounded(path, base.MAX_SOURCE_BYTES, "runtime_source_invalid")))
    entries.extend(((f"mapit/{MANIFEST_FILENAME}", raw), (f"mapit/{JWKS_FILENAME}", jwks)))
    seen, total = set(), 0
    for name, data in entries:
        if name.casefold() in seen:
            raise base.BuildError("archive_path_collision")
        seen.add(name.casefold())
        total += len(data)
        if len(data) > base.MAX_ENTRY_BYTES or total > base.MAX_TOTAL_BYTES:
            raise base.BuildError("archive_content_too_large")
    if len(entries) > base.MAX_FILE_COUNT:
        raise base.BuildError("archive_file_count_exceeded")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=base.ZIP_TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    result = buffer.getvalue()
    if len(result) > base.MAX_ARCHIVE_BYTES:
        raise base.BuildError("archive_compressed_size_exceeded")
    try:
        with target.open("xb") as output:
            output.write(result)
    except OSError:
        raise base.BuildError("archive_write_failed") from None
    return base.BuildSummary(len(result), hashlib.sha256(result).hexdigest(), len(wheels),
                             len(entries), len(SOURCE_MODULES), len(keys), True, True, True, True)
