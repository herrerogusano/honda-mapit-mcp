"""Offline deterministic packaging for the opt-in enrolled DEV runtime.

The private manifest and public verification keys are explicit local inputs;
no credentials, MAPIT sessions, AWS clients, or network access are used. Output
artifacts must remain outside the repository and OneDrive.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import zipfile

from mapit.aws_dev_runtime import parse_cognito_jwks
from mapit.dev_enrolled_manifest import (
    INVITATION_JWKS_FILENAME,
    MANIFEST_FILENAME,
    MAPIT_JWKS_FILENAME,
    MAX_MANIFEST_BYTES,
    parse_enrolled_dev_manifest,
)
from scripts import build_aws_dev_multiuser_archive as multi
from scripts import build_aws_dev_runtime as base


SOURCE_MODULES = tuple(dict.fromkeys(multi.SOURCE_MODULES + (
    "aws_dev_enrolled_entrypoint.py",
    "dev_enrolled_manifest.py",
    "dev_enrolled_runtime.py",
    "aws_binding_keys.py",
    "aws_enrollment_clients.py",
    "aws_identity_binding.py",
    "aws_identity_binding_publisher.py",
    "identity_binding.py",
    "mapit_identity.py",
    "enrolled_provider.py",
    "aws_tenant_session_reader.py",
    "aws_session_reader.py",
)))


def build_dev_enrolled_archive(wheel_dir: Path, manifest_path: Path,
                               invitation_jwks_path: Path, mapit_jwks_path: Path,
                               output_path: Path, *, account_id: str) -> base.BuildSummary:
    """Build the fixed enrolled DEV archive from explicit local inputs only."""
    repo = base._repo_root()
    if base._is_reparse_or_symlink(repo) or not repo.is_dir():
        raise base.BuildError("repository_invalid")
    lock = base._read_lock(repo)
    wheel_root = base._validate_external_wheel_dir(Path(wheel_dir), repo)
    input_paths = (Path(manifest_path), Path(invitation_jwks_path), Path(mapit_jwks_path))
    for path, category in zip(input_paths, ("runtime_binding_file_invalid",
                                            "public_jwks_file_invalid", "public_jwks_file_invalid")):
        if base._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise base.BuildError(category)
        base._outside_repo_and_onedrive(path, repo, category)

    raw = base._read_bounded(input_paths[0], MAX_MANIFEST_BYTES, "runtime_binding_invalid")
    invitation = base._snapshot_file(input_paths[1], repo)
    mapit = base._snapshot_file(input_paths[2], repo)
    digest = hashlib.sha256(raw).hexdigest()
    try:
        parsed = parse_enrolled_dev_manifest(raw, invitation, mapit,
            expected_digest=digest, account_id=account_id)
    except Exception:
        raise base.BuildError("runtime_binding_invalid") from None
    try:
        invitation_keys = parse_cognito_jwks(invitation)
        mapit_keys = parse_cognito_jwks(mapit)
    except Exception:
        raise base.BuildError("public_jwks_invalid") from None
    if (len(invitation_keys) != len(parsed.invitation_keys)
            or len(mapit_keys) != len(parsed.mapit_keys)):
        raise base.BuildError("public_jwks_invalid")

    target = base._output_path(Path(output_path), repo, wheel_root, input_paths[1])
    if target in {path.resolve() for path in input_paths}:
        raise base.BuildError("output_path_invalid")
    wheels = base._wheel_file_inventory(wheel_root, lock)
    entries = base._unpack_wheels(wheels, lock)
    entries.append(("mapit/__init__.py", b""))
    source_root = repo / "src" / "mapit"
    for name in SOURCE_MODULES:
        path = source_root / name
        if base._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise base.BuildError("runtime_source_invalid")
        entries.append((f"mapit/{name}", base._read_bounded(path, base.MAX_SOURCE_BYTES,
                                                            "runtime_source_invalid")))
    entries.extend(((f"mapit/{MANIFEST_FILENAME}", raw),
                    (f"mapit/{INVITATION_JWKS_FILENAME}", invitation),
                    (f"mapit/{MAPIT_JWKS_FILENAME}", mapit)))

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
        len(entries), len(SOURCE_MODULES), len(invitation_keys) + len(mapit_keys),
        True, True, True, True)


__all__ = ["SOURCE_MODULES", "build_dev_enrolled_archive"]
