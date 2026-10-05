"""Build the fixed, deterministic production Lambda ZIP without network/AWS.

Inputs are hash-locked wheels, a public JWKS snapshot and explicit validated
production bindings. The output contains no credentials or local session data.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mapit.aws_dev_runtime import parse_cognito_jwks
from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.cloud_transport import validate_cloud_config
from mapit.config import MapitConfig

from scripts import build_aws_dev_runtime as dev_builder

MAX_MANIFEST_BYTES = 8 * 1024
MAX_JWKS_BYTES = 32 * 1024
MAX_ARCHIVE_BYTES = dev_builder.MAX_ARCHIVE_BYTES
MANIFEST_FILENAME = "mapit-prod.manifest.json"
JWKS_FILENAME = "cognito-public-jwks.json"
GEOGRAPHY_SOURCE_MODULES = ("geography_engine.py", "geographic_tools.py")
GEOGRAPHY_ASSET = "data/menorca-ign-20261003.geojson"
GEOGRAPHY_ASSET_SHA256 = "1e75a0c988fe13c2917487bf6b9834bd6aa4f48af5117b6ed216901be09b33cd"
GEOGRAPHY_AMB_ASSET = "data/amb-ign-20261003.geojson"
GEOGRAPHY_AMB_ASSET_SHA256 = "13a14638f0dbe45b4c34a2b5bdea9923da4bb2a174e79697d65ae157b7caed3a"
PROD_SOURCE_MODULES = (
    "aws_dev_runtime.py",  # Shared fixed Cognito/JWKS validators only.
    "aws_prod_runtime.py",
    "aws_prod_entrypoint.py",
    "aws_session_reader.py",
    "cloud_provider.py",
    "cloud_transport.py",
    "lambda_adapter.py",
    "remote_http.py",
    "mcp_server.py",
    "services.py",
    "analytics.py",
    "geography.py",
    "distance_units.py",
    "client.py",
    "session.py",
    "auth.py",
    "config.py",
    "http_transport.py",
    "signing.py",
)


class ProdBuildError(ValueError):
    """Closed build failure without paths, bindings or provider output."""


@dataclass(frozen=True)
class ProdBuildSummary:
    zip_bytes: int
    sha256: str
    wheel_count: int
    archive_entries: int
    source_modules: int
    public_key_count: int
    manifest_valid: bool


def _validated_policy(value: CognitoProdPolicy) -> CognitoProdPolicy:
    if (
        type(value) is not CognitoProdPolicy
        or type(value.request_deadline_seconds) not in (int, float)
        or isinstance(value.request_deadline_seconds, bool)
        or value.request_deadline_seconds != 14.0
    ):
        raise ProdBuildError("production_policy_invalid")
    try:
        result = CognitoProdPolicy(
            user_pool_id=value.user_pool_id,
            api_id=value.api_id,
            client_id=value.client_id,
            owner_subject=value.owner_subject,
            request_deadline_seconds=value.request_deadline_seconds,
        )
    except Exception:
        raise ProdBuildError("production_policy_invalid") from None
    if result != value:
        raise ProdBuildError("production_policy_invalid")
    return result


def _validated_config(value: MapitConfig) -> MapitConfig:
    if type(value) is not MapitConfig:
        raise ProdBuildError("mapit_configuration_invalid")
    try:
        validate_cloud_config(value)
    except Exception:
        raise ProdBuildError("mapit_configuration_invalid") from None
    if value.email is not None or value.password is not None or value.discovery_enabled is not False:
        raise ProdBuildError("mapit_configuration_invalid")
    return value


def _source_entries(repo: Path, *, geography_enabled: bool = False) -> list[tuple[str, bytes]]:
    source_root = repo / "src" / "mapit"
    if dev_builder._has_symlink_or_reparse_ancestor(source_root) or not source_root.is_dir():
        raise ProdBuildError("runtime_source_invalid")
    result = [("mapit/__init__.py", b"")]
    for module in (*PROD_SOURCE_MODULES, *(GEOGRAPHY_SOURCE_MODULES if geography_enabled else ())):
        path = source_root / module
        if dev_builder._has_symlink_or_reparse_ancestor(path) or not path.is_file():
            raise ProdBuildError("runtime_source_invalid")
        try:
            raw = dev_builder._read_bounded(path, dev_builder.MAX_SOURCE_BYTES, "runtime_source_invalid")
        except Exception:
            raise ProdBuildError("runtime_source_invalid") from None
        result.append((f"mapit/{module}", raw))
    if geography_enabled:
        for asset_name, expected_sha256 in (
            (GEOGRAPHY_ASSET, GEOGRAPHY_ASSET_SHA256),
            (GEOGRAPHY_AMB_ASSET, GEOGRAPHY_AMB_ASSET_SHA256),
        ):
            asset = source_root / asset_name
            if dev_builder._has_symlink_or_reparse_ancestor(asset) or not asset.is_file():
                raise ProdBuildError("geography_asset_invalid")
            raw = dev_builder._read_bounded(asset, 1024 * 1024, "geography_asset_invalid")
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise ProdBuildError("geography_asset_invalid")
            result.append((f"mapit/{asset_name}", raw))
    return result


def _geography_lock(repo: Path) -> dict[str, tuple[str, str]]:
    path = repo / "infra" / "aws" / "geography-runtime-requirements.txt"
    if dev_builder._has_symlink_or_reparse_ancestor(path) or not path.is_file():
        raise ProdBuildError("geography_lock_invalid")
    raw = dev_builder._read_bounded(path, dev_builder.MAX_LOCK_BYTES, "geography_lock_invalid")
    result: dict[str, tuple[str, str]] = {}
    try:
        for line in raw.decode("utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = dev_builder._LOCK_LINE.fullmatch(line)
            if match is None or match.group(1) in result:
                raise ProdBuildError("geography_lock_invalid")
            result[match.group(1)] = (match.group(2), match.group(3))
    except UnicodeError:
        raise ProdBuildError("geography_lock_invalid") from None
    if set(result) != {"numpy", "shapely"} or result["numpy"][0] != "2.4.3" or result["shapely"][0] != "2.1.2":
        raise ProdBuildError("geography_lock_invalid")
    return result


def _manifest(
    policy: CognitoProdPolicy,
    config: MapitConfig,
    account_id: str,
    parameter_version: int,
    parameter_tier: str,
    jwks_sha256: str,
) -> bytes:
    if (
        type(account_id) is not str
        or not re.fullmatch(r"[0-9]{12}", account_id)
        or account_id == "000000000000"
        or type(parameter_version) is not int
        or parameter_version != 1
        or type(parameter_tier) is not str
        or parameter_tier != "Standard"
        or type(jwks_sha256) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", jwks_sha256)
    ):
        raise ProdBuildError("production_binding_invalid")
    config_record = {
        "region": config.region,
        "user_pool_id": config.user_pool_id,
        "user_pool_client_id": config.user_pool_client_id,
        "identity_pool_id": config.identity_pool_id,
        "core_api_url": config.core_api_url,
        "geo_api_url": config.geo_api_url,
        "discovery_enabled": config.discovery_enabled,
        "http_timeout": config.http_timeout,
    }
    record = {
        "environment": "prod",
        "region": "eu-west-1",
        "account_id": account_id,
        "parameter_version": parameter_version,
        "parameter_tier": parameter_tier,
        "user_pool_id": policy.user_pool_id,
        "api_id": policy.api_id,
        "client_id": policy.client_id,
        "owner_subject": policy.owner_subject,
        "jwks_sha256": jwks_sha256,
        "mapit_config": config_record,
    }
    try:
        encoded = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    except Exception:
        raise ProdBuildError("production_manifest_invalid") from None
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ProdBuildError("production_manifest_oversized")
    return encoded


def build_prod_runtime_archive(
    wheel_dir: Path,
    public_jwks_path: Path,
    output_path: Path,
    *,
    policy: CognitoProdPolicy,
    mapit_config: MapitConfig,
    account_id: str,
    parameter_version: int,
    parameter_tier: str,
    geography_wheel_dir: Path | None = None,
    source_sha: str | None = None,
) -> ProdBuildSummary:
    """Create a production-only ZIP. This performs no credential/AWS reads."""
    repo = dev_builder._repo_root()
    if source_sha is not None and (
        type(source_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or source_sha == "0" * 40
    ):
        raise ProdBuildError("production_source_invalid")
    if dev_builder._is_reparse_or_symlink(repo) or not repo.is_dir():
        raise ProdBuildError("repository_invalid")
    policy = _validated_policy(policy)
    config = _validated_config(mapit_config)
    wheel_root = dev_builder._validate_external_wheel_dir(Path(wheel_dir), repo)
    jwks_file = Path(public_jwks_path)
    try:
        jwks_bytes = dev_builder._snapshot_file(jwks_file, repo)
        if len(jwks_bytes) > MAX_JWKS_BYTES:
            raise ProdBuildError("public_jwks_invalid")
        public_keys = parse_cognito_jwks(jwks_bytes)
    except ProdBuildError:
        raise
    except Exception:
        raise ProdBuildError("public_jwks_invalid") from None
    if not public_keys:
        raise ProdBuildError("public_jwks_invalid")
    target = dev_builder._output_path(Path(output_path), repo, wheel_root, jwks_file)
    lock = dev_builder._read_lock(repo)
    wheel_files = dev_builder._wheel_file_inventory(wheel_root, lock)
    geography_enabled = geography_wheel_dir is not None
    if geography_enabled:
        extra_root = dev_builder._validate_external_wheel_dir(Path(geography_wheel_dir), repo)
        if dev_builder._inside(target, extra_root):
            raise ProdBuildError("archive_output_invalid")
        extra_lock = _geography_lock(repo)
        extra_files = dev_builder._wheel_file_inventory(extra_root, extra_lock)
        lock = {**lock, **extra_lock}
        wheel_files = [*wheel_files, *extra_files]
        if sum(len(data) for _, data in wheel_files) > dev_builder.MAX_INPUT_BYTES:
            raise ProdBuildError("wheel_input_size_exceeded")
    wheel_entries = dev_builder._unpack_wheels(wheel_files, lock)
    source_entries = _source_entries(repo, geography_enabled=geography_enabled)
    manifest = _manifest(
        policy, config, account_id, parameter_version, parameter_tier,
        hashlib.sha256(jwks_bytes).hexdigest(),
    )
    if geography_enabled:
        manifest_value = json.loads(manifest)
        manifest_value["geographic_queries"] = True
        manifest = json.dumps(manifest_value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(manifest) > MAX_MANIFEST_BYTES:
            raise ProdBuildError("production_binding_invalid")
    entries = [*wheel_entries, *source_entries,
               (f"mapit/{JWKS_FILENAME}", jwks_bytes),
               (f"mapit/{MANIFEST_FILENAME}", manifest)]
    if source_sha is not None:
        entries.append(("mapit/source-provenance.json", json.dumps(
            {"schema": 1, "source_sha": source_sha},
            sort_keys=True, separators=(",", ":"),
        ).encode("ascii")))
    seen: set[str] = set()
    total_bytes = 0
    for name, data in entries:
        folded = name.casefold()
        if folded in seen:
            raise ProdBuildError("archive_path_collision")
        seen.add(folded)
        if len(data) > dev_builder.MAX_ENTRY_BYTES or total_bytes + len(data) > dev_builder.MAX_TOTAL_BYTES:
            raise ProdBuildError("archive_content_too_large")
        total_bytes += len(data)
    if len(entries) > dev_builder.MAX_FILE_COUNT:
        raise ProdBuildError("archive_file_count_exceeded")
    import io

    buffer = io.BytesIO()
    try:
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9, strict_timestamps=True) as archive:
            for name, data in sorted(entries, key=lambda item: item[0]):
                info = zipfile.ZipInfo(name, date_time=dev_builder.ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.extra = b""
                info.comment = b""
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        archive_bytes = buffer.getvalue()
        if len(archive_bytes) > MAX_ARCHIVE_BYTES:
            raise ProdBuildError("archive_compressed_size_exceeded")
        with target.open("xb") as output:
            output.write(archive_bytes)
    except ProdBuildError:
        raise
    except Exception:
        raise ProdBuildError("archive_write_failed") from None
    return ProdBuildSummary(
        zip_bytes=len(archive_bytes), sha256=hashlib.sha256(archive_bytes).hexdigest(),
        wheel_count=len(wheel_files), archive_entries=len(entries),
        source_modules=len(PROD_SOURCE_MODULES) + (len(GEOGRAPHY_SOURCE_MODULES) if geography_enabled else 0), public_key_count=len(public_keys),
        manifest_valid=True,
    )


__all__ = ["MANIFEST_FILENAME", "JWKS_FILENAME", "PROD_SOURCE_MODULES", "ProdBuildError",
           "ProdBuildSummary", "build_prod_runtime_archive"]
