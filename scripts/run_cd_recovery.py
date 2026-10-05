"""Operator-triggered rollback to one explicitly retained production ZIP.

The dispatcher is deliberately separate from the ordinary source build. It
never publishes or guesses a target: a protected manual dispatch must supply
the exact retained ZIP and manifest digests. The production upgrade core still
owns closure, one update write and exact readbacks; reopening is a distinct job.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import zipfile
from collections.abc import Mapping
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from mapit.aws_cd_journal import S3DeliveryJournal
from scripts.build_aws_prod_runtime import (
    MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES, MANIFEST_FILENAME, JWKS_FILENAME,
    _manifest as expected_manifest,
)
from scripts import build_aws_dev_runtime as dev_builder
from scripts.probe_cd_candidate import probe_candidate
from scripts.github_oidc_claims import validate_oidc_claims, request_runner_oidc_token
from scripts import run_cd_release as ordinary

_TERMINAL = frozenset({"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"})


def _digest(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _read_zip_body(response: Any, *, expected_sha: str, expected_size: Any) -> bytes:
    if (
        not isinstance(response, Mapping) or not ordinary._http_200(response)
        or type(expected_size) is not int or not 1 <= expected_size <= MAX_ARCHIVE_BYTES
        or response.get("ContentLength") != expected_size
        or type(response.get("ContentLength")) is not int
        or response.get("ServerSideEncryption") != "AES256"
        or response.get("ChecksumSHA256") != base64.b64encode(bytes.fromhex(expected_sha)).decode("ascii")
    ):
        raise ordinary.ReleaseError("artifact_binding_invalid")
    body = response.get("Body")
    read = getattr(body, "read", None)
    if not callable(read):
        raise ordinary.ReleaseError("artifact_binding_invalid")
    try:
        data = read(MAX_ARCHIVE_BYTES + 1)
    except Exception:
        raise ordinary.ReleaseError("artifact_binding_invalid") from None
    finally:
        close = getattr(body, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
    if type(data) is not bytes or len(data) != expected_size or len(data) > MAX_ARCHIVE_BYTES:
        raise ordinary.ReleaseError("artifact_binding_invalid")
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ordinary.ReleaseError("artifact_binding_invalid")
    return data


def _validate_retained_zip(raw: bytes, bindings: Mapping[str, Any], *, expected_manifest_sha: str) -> int:
    """Validate archive structure and its exact current public bindings."""
    try:
        current_jwks = ordinary._canonical(bindings["jwks"])
        from mapit.aws_dev_runtime import parse_cognito_jwks
        parsed_current = json.loads(current_jwks, object_pairs_hook=ordinary._pairs)
        parse_cognito_jwks(current_jwks)
        with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= dev_builder.MAX_FILE_COUNT:
                raise ValueError
            names: set[str] = set()
            total = 0
            for info in infos:
                path = info.filename
                parts = path.split("/")
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    type(path) is not str or not path or path.startswith("/") or "\\" in path
                    or any(part in {"", ".", ".."} for part in parts)
                    or info.is_dir() or (mode & 0o170000) not in (0, 0o100000)
                    or path.casefold() in names or info.file_size < 0
                    or info.file_size > dev_builder.MAX_ENTRY_BYTES
                ):
                    raise ValueError
                names.add(path.casefold())
                total += info.file_size
                if total > dev_builder.MAX_TOTAL_BYTES:
                    raise ValueError
            manifest_path = "mapit/" + MANIFEST_FILENAME
            jwks_path = "mapit/" + JWKS_FILENAME
            manifest_info = archive.getinfo(manifest_path)
            jwks_info = archive.getinfo(jwks_path)
            if manifest_info.file_size > MAX_MANIFEST_BYTES or jwks_info.file_size > 32 * 1024:
                raise ValueError
            manifest_bytes = archive.read(manifest_info)
            jwks_bytes = archive.read(jwks_info)
            retained_jwks = json.loads(jwks_bytes, object_pairs_hook=ordinary._pairs)
            if retained_jwks != parsed_current:
                raise ValueError
            parse_cognito_jwks(jwks_bytes)
            jwks_sha = hashlib.sha256(jwks_bytes).hexdigest()
            expected = expected_manifest(
                bindings["_validated_policy"], bindings["_validated_mapit_config"],
                bindings["account_id"], bindings["parameter_version"], bindings["parameter_tier"], jwks_sha,
            )
            expected_doc = json.loads(expected, object_pairs_hook=ordinary._pairs)
            expected_doc["geographic_queries"] = True
            expected = json.dumps(expected_doc, sort_keys=True, separators=(",", ":")).encode("ascii")
            if manifest_bytes != expected or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha:
                raise ValueError
            # Provenance is optional for legacy retained packages, but if
            # present it must be a bounded, exact schema with a real commit id.
            if "mapit/source-provenance.json" in names:
                provenance = archive.read("mapit/source-provenance.json")
                if len(provenance) > 256:
                    raise ValueError
                record = json.loads(provenance, object_pairs_hook=ordinary._pairs)
                if type(record) is not dict or set(record) != {"schema", "source_sha"}:
                    raise ValueError
                if type(record["schema"]) is not int or record["schema"] != 1:
                    raise ValueError
                if type(record["source_sha"]) is not str or re.fullmatch(r"[0-9a-f]{40}", record["source_sha"]) is None:
                    raise ValueError
            return len(raw)
    except ordinary.ReleaseError:
        raise
    except Exception:
        raise ordinary.ReleaseError("artifact_binding_invalid") from None


def _download_retained(s3: Any, bindings: Mapping[str, Any], sha: str, size: int) -> bytes:
    if not _digest(sha) or type(size) is not int or not 1 <= size <= MAX_ARCHIVE_BYTES:
        raise ordinary.ReleaseError("artifact_binding_invalid")
    key = f"runtime/{sha}.zip"
    try:
        response = s3.get_object(
            Bucket=bindings["artifact_bucket"], Key=key,
            ExpectedBucketOwner=bindings["account_id"], ChecksumMode="ENABLED",
        )
    except Exception:
        raise ordinary.ReleaseError("artifact_binding_invalid") from None
    return _read_zip_body(response, expected_sha=sha, expected_size=size)


class CDRecoveryRunner(ordinary.CDReleaseRunner):
    """Single-step manual retained-artifact rollback adapter."""

    def run(self, phase: str) -> dict[str, Any]:
        if type(phase) is not str or phase not in {"rollback-update", "reopen", "recover-close"}:
            return {"status": "failed", "phase": "unknown", "category": "unknown_phase"}
        clients: list[Any] = []
        try:
            ordinary._reject_ambient_aws(self.environ)
            source_sha, run_id = ordinary._source_context(self.environ)
            self._source_sha = source_sha
            bindings = ordinary._parse_bindings(self.environ.get("MAPIT_CD_BINDING_JSON"))
            if phase == "rollback-update":
                if not _digest(self.environ.get("ROLLBACK_ARTIFACT_SHA256")) or not _digest(
                    self.environ.get("ROLLBACK_MANIFEST_SHA256")
                ):
                    raise ordinary.ReleaseError("artifact_binding_invalid")
            elif phase == "reopen":
                for key in ("AUTHORIZATION_START", "AUTHORIZATION_UNTIL"):
                    value = self.environ.get(key)
                    if type(value) is not str or re.fullmatch(r"[1-9][0-9]{0,12}", value) is None:
                        raise ordinary.ReleaseError("journal_unavailable")
                for key in ("ARTIFACT_SHA256", "MANIFEST_SHA256"):
                    if not _digest(self.environ.get(key)):
                        raise ordinary.ReleaseError("journal_unavailable")
            services, clients = ordinary._assume_executor(
                bindings, source_sha, self.environ, opener=self.opener, client_factory=self.client_factory,
            )
            journal = S3DeliveryJournal(
                services["s3"], bucket=bindings["artifact_bucket"], account_id=bindings["account_id"],
                run_id=run_id, source_sha=source_sha,
            )
            if phase == "rollback-update":
                return self._rollback_update(bindings, services, journal, run_id, source_sha)
            if phase == "reopen":
                return self._reopen_or_close(
                    "reopen", bindings, services, journal, run_id, source_sha, retained_recovery=True,
                )
            return self._reopen_or_close(
                "recover-close", bindings, services, journal, run_id, source_sha, retained_recovery=True,
            )
        except ordinary.ReleaseError as exc:
            return {"status": "failed", "phase": phase, "category": exc.category}
        except Exception:
            return {"status": "failed", "phase": phase, "category": "release_internal_error"}
        finally:
            for client in clients:
                try:
                    client.close()
                except Exception:
                    pass

    def _rollback_update(self, bindings: Mapping[str, Any], services: Mapping[str, Any], journal: S3DeliveryJournal,
                         run_id: str, source_sha: str) -> dict[str, Any]:
        target_sha = self.environ.get("ROLLBACK_ARTIFACT_SHA256")
        target_manifest = self.environ.get("ROLLBACK_MANIFEST_SHA256")
        if not _digest(target_sha) or not _digest(target_manifest):
            raise ordinary.ReleaseError("artifact_binding_invalid")
        if not ordinary._verify_private_artifact_bucket(
            services["s3"], bindings["artifact_bucket"], bindings["account_id"],
            tag_fingerprint=bindings["artifact_tags_sha256"],
        ):
            raise ordinary.ReleaseError("candidate_publish_failed")
        try:
            old_sha, old_manifest = ordinary._old_artifact_binding(services, bindings["stack_arn"])
            head = services["s3"].head_object(
                Bucket=bindings["artifact_bucket"], Key=f"runtime/{target_sha}.zip",
                ExpectedBucketOwner=bindings["account_id"], ChecksumMode="ENABLED",
            )
            if not ordinary._http_200(head):
                raise ValueError
            target_size = head.get("ContentLength")
            if type(target_size) is not int or not 1 <= target_size <= MAX_ARCHIVE_BYTES:
                raise ValueError
            if head.get("ChecksumSHA256") != base64.b64encode(bytes.fromhex(target_sha)).decode("ascii"):
                raise ValueError
            if head.get("ServerSideEncryption") != "AES256":
                raise ValueError
            raw = _download_retained(services["s3"], bindings, target_sha, target_size)
            _validate_retained_zip(raw, bindings, expected_manifest_sha=target_manifest)
            with tempfile.TemporaryDirectory(prefix="mapit-cd-rollback-") as scratch:
                archive_path = Path(scratch) / "retained-runtime.zip"
                with archive_path.open("xb") as handle:
                    handle.write(raw)
                if not probe_candidate(
                    archive_path, zip_sha256=target_sha, manifest_sha256=target_manifest, source_sha=None,
                ):
                    raise ValueError
            now = ordinary._utc_epoch(self.clock)
            cutoff = now + ordinary._MAX_AUTHORIZATION_SECONDS
            core = ordinary._core(
                bindings, services, journal, run_id=run_id, source_sha=source_sha,
                old_zip=old_sha, old_manifest=old_manifest, new_zip=target_sha,
                new_manifest=target_manifest, authorized_from=now, authorized_until=cutoff,
                wall_clock=self.clock, retained_recovery=True,
            )
            preflight = core.run_step("preflight")
            if preflight.get("category") != "preflight_verified":
                raise ordinary.ReleaseError("core_preflight_failed")
        except ordinary.ReleaseError:
            raise
        except Exception:
            raise ordinary.ReleaseError("artifact_binding_invalid") from None
        close = core.run_step("close")
        if close.get("category") != "close_pending":
            raise ordinary.ReleaseError("close_failed")
        state = None
        for attempt in range(ordinary._MAX_CLOSE_POLLS):
            result = core.run_step("check-close")
            if result.get("verified") is True:
                state = ordinary._journal_state(journal)
                break
            if result.get("category") != "close_pending":
                raise ordinary.ReleaseError("close_failed")
            if attempt + 1 < ordinary._MAX_CLOSE_POLLS:
                time.sleep(2)
        if state is None or not ordinary._close_age(services, state, now=self.clock):
            raise ordinary.ReleaseError("close_window_expired")
        update = core.run_step("request-update")
        if update.get("category") not in {"update_pending", "update_skipped_same_artifact"}:
            raise ordinary.ReleaseError("update_failed")
        for attempt in range(ordinary._MAX_UPDATE_POLLS):
            if not ordinary._close_age(services, state, now=self.clock):
                raise ordinary.ReleaseError("close_window_expired")
            result = core.run_step("check-update")
            if result.get("verified") is True:
                return {"status": "awaiting_approval", "phase": "update_verified",
                        "category": "release_ready_for_reopen", "source_sha": source_sha,
                        "artifact_sha256": target_sha, "manifest_sha256": target_manifest,
                        "authorization_start": now, "authorization_until": cutoff}
            if result.get("category") != "update_pending":
                raise ordinary.ReleaseError("update_failed")
            if attempt + 1 < ordinary._MAX_UPDATE_POLLS:
                time.sleep(2)
        return {"status": "pending", "phase": "check-update", "category": "update_pending",
                "source_sha": source_sha, "artifact_sha256": target_sha,
                "manifest_sha256": target_manifest, "authorization_start": now,
                "authorization_until": cutoff}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One protected retained-runtime recovery step.")
    parser.add_argument("phase", choices=("rollback-update", "reopen", "recover-close"))
    args = parser.parse_args(argv)
    runner = CDRecoveryRunner()
    result = runner.run(args.phase)
    try:
        ordinary._emit_outputs(result, os.environ)
        print(json.dumps(result, separators=(",", ":"), allow_nan=False))
    except Exception:
        print('{"status":"failed","phase":"unknown","category":"release_internal_error"}')
        return 1
    return 0 if result.get("status") in {"verified", "awaiting_approval", "pending"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
