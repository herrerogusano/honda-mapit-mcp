"""Build the deterministic synthetic retained-dev Lambda ZIP offline.

This builder is separate from the historical dev archive builder.  It reuses
only its pure wheel/source/ZIP validation helpers, never discovers network or
credentials, and contains no account operation.  The archive is synthetic and
closed until a later independently approved deployment gate.
"""

from __future__ import annotations

import hashlib
import json
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import zipfile

from mapit.aws_dev_runtime import cognito_dev_policy, parse_cognito_jwks
from scripts import build_aws_dev_runtime as historical
from scripts.build_aws_retained_dev_runtime import (
    RETAINED_DEV_MANIFEST_FILENAME,
    SYNTHETIC_CLIENT_ID,
    SYNTHETIC_EXECUTION_END,
    SYNTHETIC_EXECUTION_START,
    SYNTHETIC_OWNER_SUBJECT,
    SYNTHETIC_USER_POOL_ID,
    RetainedDevRuntimeTemplateError,
    build_retained_dev_manifest,
)

MAX_ARCHIVE_BYTES = historical.MAX_ARCHIVE_BYTES
MAX_ENTRY_BYTES = historical.MAX_ENTRY_BYTES
MAX_TOTAL_BYTES = historical.MAX_TOTAL_BYTES
MAX_FILE_COUNT = historical.MAX_FILE_COUNT
MAX_MANIFEST_BYTES = historical.MAX_MANIFEST_BYTES
JWKS_SNAPSHOT_FILENAME = historical.JWKS_SNAPSHOT_FILENAME
JWKS_MANIFEST_FILENAME = historical.JWKS_MANIFEST_FILENAME
ZIP_TIMESTAMP = historical.ZIP_TIMESTAMP


class RetainedDevArchiveError(ValueError):
    """Stable local category without paths, identifiers, or provider text."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


_RECEIPT_TOKEN = object()
_RECEIPT_FIELDS = (
    "_receipt_seal", "source_sha", "api_id", "jwks_sha256",
    "execution_start_epoch", "execution_end_epoch", "zip_sha256",
    "manifest_sha256", "source_allowlist_sha256", "source_proof_sha256",
    "wheel_lock_sha256", "wheel_proof_sha256", "archive_entries",
    "wheel_count", "source_modules", "public_key_count",
)


class RetainedDevBuildReceipt:
    """Opaque output of the validated retained-dev archive builder.

    The publisher accepts this type, not caller-provided source/manifest
    mappings.  The private constructor token and self-seal make accidental
    construction or mutation fail closed; this is an integrity boundary for
    the injected offline pipeline, not a cryptographic trust boundary.
    """

    __slots__ = (*_RECEIPT_FIELDS, "_sealed")

    def __init__(self, token: object, *, _receipt_seal: str, **values: Any) -> None:
        if token is not _RECEIPT_TOKEN or set(values) != set(_RECEIPT_FIELDS) - {"_receipt_seal"}:
            raise TypeError("retained-dev-receipt-private")
        for name, value in values.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_receipt_seal", _receipt_seal)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("retained-dev-receipt-immutable")
        object.__setattr__(self, name, value)

    def __repr__(self) -> str:
        return "<RetainedDevBuildReceipt sealed>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, RetainedDevBuildReceipt) and self._receipt_seal == other._receipt_seal and _receipt_payload(self) == _receipt_payload(other)

    def validate(self) -> bool:
        expected = _receipt_payload(self)
        return self._receipt_seal == hashlib.sha256(_canonical_receipt(expected)).hexdigest()


@dataclass(frozen=True)
class RetainedDevArchiveSummary:
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
    jwks_digest_matches: bool
    receipt: RetainedDevBuildReceipt


def _canonical_receipt(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _receipt_payload(receipt: RetainedDevBuildReceipt) -> dict[str, Any]:
    return {
        "schema": 1,
        "builder": "build_aws_retained_dev_archive",
        "source_sha": receipt.source_sha,
        "api_id": receipt.api_id,
        "jwks_sha256": receipt.jwks_sha256,
        "execution_start_epoch": receipt.execution_start_epoch,
        "execution_end_epoch": receipt.execution_end_epoch,
        "zip_sha256": receipt.zip_sha256,
        "manifest_sha256": receipt.manifest_sha256,
        "source_allowlist_sha256": receipt.source_allowlist_sha256,
        "source_proof_sha256": receipt.source_proof_sha256,
        "wheel_lock_sha256": receipt.wheel_lock_sha256,
        "wheel_proof_sha256": receipt.wheel_proof_sha256,
        "archive_entries": receipt.archive_entries,
        "wheel_count": receipt.wheel_count,
        "source_modules": receipt.source_modules,
        "public_key_count": receipt.public_key_count,
    }


def _make_receipt(**values: Any) -> RetainedDevBuildReceipt:
    payload = {"schema": 1, "builder": "build_aws_retained_dev_archive", **values}
    seal = hashlib.sha256(_canonical_receipt(payload)).hexdigest()
    return RetainedDevBuildReceipt(_RECEIPT_TOKEN, _receipt_seal=seal, **values)


def _repo_root() -> Path:
    return historical._repo_root()


def _build_public_jwks_manifest(policy: Any, jwks_sha256: str) -> bytes:
    value = {
        "issuer": policy.issuer_url,
        "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json",
        "sha256": jwks_sha256,
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RetainedDevArchiveError("public_jwks_manifest_oversized")
    return raw


def build_retained_dev_archive(
    wheel_dir: Path,
    public_jwks_path: Path,
    output_path: Path,
    *,
    source_sha: str,
    api_id: str,
    jwks_sha256: str,
    execution_start_epoch: int = SYNTHETIC_EXECUTION_START,
    execution_end_epoch: int = SYNTHETIC_EXECUTION_END,
) -> RetainedDevArchiveSummary:
    """Build a deterministic retained-dev archive from explicit local inputs."""
    repo = _repo_root()
    if historical._is_reparse_or_symlink(repo) or not repo.is_dir():
        raise RetainedDevArchiveError("repository_invalid")
    try:
        policy = cognito_dev_policy(
            user_pool_id=SYNTHETIC_USER_POOL_ID,
            api_id=api_id,
            client_id=SYNTHETIC_CLIENT_ID,
            owner_subject=SYNTHETIC_OWNER_SUBJECT,
        )
        retained_manifest = build_retained_dev_manifest(
            source_sha, api_id, jwks_sha256, execution_start_epoch, execution_end_epoch,
        )
    except (RetainedDevRuntimeTemplateError, TypeError, ValueError):
        raise RetainedDevArchiveError("runtime_identity_invalid") from None
    try:
        lock = historical._read_lock(repo)
        wheel_root = historical._validate_external_wheel_dir(Path(wheel_dir), repo)
        jwks_file = Path(public_jwks_path)
        jwks_bytes = historical._snapshot_file(jwks_file, repo)
        target = historical._output_path(Path(output_path), repo, wheel_root, jwks_file)
        if hashlib.sha256(jwks_bytes).hexdigest() != jwks_sha256:
            raise RetainedDevArchiveError("public_jwks_digest_mismatch")
        public_keys = parse_cognito_jwks(jwks_bytes)
        if not public_keys:
            raise RetainedDevArchiveError("public_jwks_invalid")
        wheel_files = historical._wheel_file_inventory(wheel_root, lock)
        wheel_entries = historical._unpack_wheels(wheel_files, lock)
        source_entries = historical._source_entries(repo)
        source_allowlist_sha256 = hashlib.sha256(
            _canonical_receipt(list(historical.SOURCE_MODULES))
        ).hexdigest()
        source_proof_sha256 = hashlib.sha256(
            _canonical_receipt([
                {"name": name, "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in source_entries
            ])
        ).hexdigest()
        wheel_lock_sha256 = hashlib.sha256(
            _canonical_receipt({name: list(value) for name, value in sorted(lock.items())})
        ).hexdigest()
        wheel_proof_sha256 = hashlib.sha256(
            _canonical_receipt([
                {"name": name, "sha256": hashlib.sha256(data).hexdigest()}
                for name, data in wheel_files
            ])
        ).hexdigest()
        jwks_manifest = _build_public_jwks_manifest(policy, jwks_sha256)
        retained_manifest_bytes = json.dumps(
            retained_manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        fixed_entries = [
            *wheel_entries,
            *source_entries,
            (f"mapit/{JWKS_SNAPSHOT_FILENAME}", jwks_bytes),
            (f"mapit/{JWKS_MANIFEST_FILENAME}", jwks_manifest),
            (f"mapit/{RETAINED_DEV_MANIFEST_FILENAME}", retained_manifest_bytes),
        ]
        seen: set[str] = set()
        total_bytes = 0
        for name, data in fixed_entries:
            folded = name.casefold()
            if folded in seen:
                raise RetainedDevArchiveError("archive_path_collision")
            seen.add(folded)
            if len(data) > MAX_ENTRY_BYTES or total_bytes + len(data) > MAX_TOTAL_BYTES:
                raise RetainedDevArchiveError("archive_content_too_large")
            total_bytes += len(data)
        if len(fixed_entries) > MAX_FILE_COUNT:
            raise RetainedDevArchiveError("archive_file_count_exceeded")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, strict_timestamps=True) as archive:
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
            raise RetainedDevArchiveError("archive_compressed_size_exceeded")
        zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        manifest_sha256 = hashlib.sha256(retained_manifest_bytes).hexdigest()
        receipt = _make_receipt(
            source_sha=source_sha,
            api_id=api_id,
            jwks_sha256=jwks_sha256,
            execution_start_epoch=execution_start_epoch,
            execution_end_epoch=execution_end_epoch,
            zip_sha256=zip_sha256,
            manifest_sha256=manifest_sha256,
            source_allowlist_sha256=source_allowlist_sha256,
            source_proof_sha256=source_proof_sha256,
            wheel_lock_sha256=wheel_lock_sha256,
            wheel_proof_sha256=wheel_proof_sha256,
            archive_entries=len(fixed_entries),
            wheel_count=len(wheel_files),
            source_modules=len(historical.SOURCE_MODULES),
            public_key_count=len(public_keys),
        )
        with target.open("xb") as output:
            output.write(zip_bytes)
        return RetainedDevArchiveSummary(
            zip_bytes=len(zip_bytes), sha256=zip_sha256,
            wheel_count=len(wheel_files), archive_entries=len(fixed_entries),
            source_modules=len(historical.SOURCE_MODULES), public_key_count=len(public_keys),
            dependencies_valid=True, source_allowlist_valid=True, lock_valid=True,
            manifest_valid=True, jwks_digest_matches=True, receipt=receipt,
        )
    except RetainedDevArchiveError:
        raise
    except historical.BuildError as exc:
        raise RetainedDevArchiveError(str(exc)) from None
    except (OSError, zipfile.BadZipFile, ValueError, TypeError):
        raise RetainedDevArchiveError("archive_build_failed") from None


__all__ = [
    "RetainedDevArchiveError", "RetainedDevArchiveSummary", "RetainedDevBuildReceipt",
    "build_retained_dev_archive",
]
