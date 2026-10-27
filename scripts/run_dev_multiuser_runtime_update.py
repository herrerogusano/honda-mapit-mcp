"""Offline/injected coordinator for the retained-dev multi-user runtime.

This module is deliberately an operator seam, not an AWS client factory.  It
accepts already constructed, explicitly scoped clients and the private build
receipts produced by the reviewed archive/artifact pipeline.  Publication and
CloudFormation update steps are delegated to their closed cores; this module
only returns their allowlisted status projection.  No credentials, payloads,
resource identifiers, or provider exception text are printed or journaled.
"""
from __future__ import annotations

from collections.abc import Mapping
import base64
import hashlib
import io
import json
import os
import re
import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
import zipfile

from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_template, build_retained_dev_multiuser_setup
from scripts import build_aws_dev_runtime as _archive_base
from mapit.aws_dev_multiuser_entrypoint import MAX_JWKS_BYTES, MAX_MANIFEST_BYTES, MANIFEST_FILENAME, JWKS_FILENAME, parse_manifest
from mapit.aws_dev_runtime import parse_cognito_jwks

REGION = "eu-west-1"
MAX_CLIENT_KEYS = frozenset({"sts", "cloudformation", "lambda", "apigatewayv2"})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RuntimeUpdateError(ValueError):
    """Stable local error category; provider/path text never escapes."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class CasFileJournal:
    """CAS adapter over the reviewed private FileJournal.

    FileJournal provides the private lock and atomic replace but intentionally
    has no CAS method.  This adapter performs the revision check while the
    caller holds that lock; it never broadens the file format or location
    policy.
    """

    def __init__(self, state_dir: Path):
        from scripts.dev_multiuser_journal import PlainFileJournal
        self._journal = PlainFileJournal(state_dir)

    def locked(self):
        return self._journal.locked()

    def load(self):
        return self._journal.load()

    def save(self, value):
        """Compatibility write for ClosedDevUpdate's locked intent journal.

        Artifact publication uses ``compare_and_set``; the CloudFormation
        core has its own binding and writes an intent while holding this same
        private lock.  Keeping this adapter explicit avoids silently falling
        back to an unguarded ambient journal.
        """
        return self._journal.save(value)

    def compare_and_set(self, expected_revision, replacement):
        current = self._journal.load()
        actual = None if current is None else current.get("revision")
        if actual != expected_revision:
            return False
        self._journal.save(replacement)
        return True


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise RuntimeUpdateError("template_invalid") from None


def _safe_core_result(value: Any, *, fallback: str = "runtime_update_failed") -> dict[str, Any]:
    """Project a core result without copying identifiers or exception text."""
    if not isinstance(value, Mapping) or type(value.get("ok")) is not bool:
        return {"success": False, "category": fallback}
    category = value.get("category")
    if category is None:
        category = {
            "ready": "preflight_verified", "acknowledged": "update_acknowledged",
            "pending": "update_pending", "accepted": "readback_verified",
        }.get(value.get("phase"))
    if type(category) is not str or not re.fullmatch(r"[a-z][a-z0-9_-]{2,63}\Z", category):
        category = fallback
    allowed = {
        "preflight_verified", "preflight_required", "preflight_conflict",
        "request-update", "update_acknowledged", "update_outcome_unknown",
        "check-update", "update_pending", "readback_verified",
        "update_reconciled_without_ack", "preflight_mismatch", "update_failed",
        "artifact_head_mismatch", "artifact_head_failed", "artifact_readback_mismatch",
        "journal_invalid", "journal_conflict", "journal_failed", "window_expired",
        "call_budget_exhausted", "binding_invalid", "build_receipt_invalid",
        "candidate_invalid", "prior_recovery_unavailable", "coordinator_internal_error",
    }
    if category not in allowed:
        category = fallback
    return {"success": value["ok"], "category": category}


def build_recurrent_iam_template(bindings: Mapping[str, Any], *, observed_user_pool_id: str) -> dict[str, Any]:
    """Build the exact V2 recurrent IAM narrowing, without AWS/IAM calls."""
    if not isinstance(bindings, Mapping):
        raise RuntimeUpdateError("bindings_invalid")
    required = {
        "account_id", "provider_arn", "owner_id", "repository_id",
        "observed_dev_subject_format", "observed_dev_subject_sha256",
        "stack_arn", "artifact_stack_arn", "handler_arn", "api_arn",
        "shutdown_state_machine_arn", "artifact_bucket_arn", "execution_role_arn",
    }
    if set(bindings) != required or type(observed_user_pool_id) is not str or _POOL.fullmatch(observed_user_pool_id) is None:
        raise RuntimeUpdateError("bindings_invalid")
    try:
        template = build_cd_retained_dev_multiuser_roles(
            **dict(bindings), observed_user_pool_id=observed_user_pool_id,
        )
    except Exception:
        raise RuntimeUpdateError("recurrent_roles_invalid") from None
    resources = template.get("Resources") if isinstance(template, Mapping) else None
    metadata = template.get("Metadata") if isinstance(template, Mapping) else None
    if not isinstance(resources, Mapping) or len(resources) != 4 or not isinstance(metadata, Mapping) or metadata.get("MultiuserSetupPhase") != "recurrent" or metadata.get("ObservedUserPoolIdBound") is not True:
        raise RuntimeUpdateError("recurrent_roles_invalid")
    return template


def recurrent_iam_summary(bindings: Mapping[str, Any], *, observed_user_pool_id: str) -> dict[str, Any]:
    """Return only safe metadata for the separate recurrent-role operation."""
    try:
        template = build_recurrent_iam_template(bindings, observed_user_pool_id=observed_user_pool_id)
        return {
            "success": True,
            "category": "recurrent_roles_ready",
            "resource_count": len(template["Resources"]),
            "template_sha256": hashlib.sha256(_canonical(template["Resources"])).hexdigest(),
        }
    except RuntimeUpdateError as exc:
        return {"success": False, "category": exc.category}
    except Exception:
        return {"success": False, "category": "recurrent_roles_invalid"}


def publish_candidate(
    s3_client: Any,
    journal: Any,
    *,
    bucket: str,
    expected_owner: str,
    run_id: str,
    archive_path: Any,
    build_receipt: Any,
    authorized_from_epoch: int,
    authorized_until_epoch: int,
    wall_clock: Callable[[], float],
    monotonic: Callable[[], float],
) -> dict[str, Any]:
    """Compatibility name that accepts only the V2 receipt, never the old core."""
    if not isinstance(build_receipt, MultiuserBuildReceipt):
        return {"success": False, "category": "v2_receipt_required"}
    return publish_multiuser_candidate(
        s3_client, journal, build_receipt, account_id=expected_owner, bucket=bucket,
        run_id=run_id, authorized_from_epoch=authorized_from_epoch,
        authorized_until_epoch=authorized_until_epoch, wall_clock=wall_clock,
        monotonic=monotonic,
    )


@dataclass(frozen=True)
class MultiuserBuildReceipt:
    """Private, hash-only binding emitted by the V2 archive pipeline."""

    source_sha: str
    api_id: str
    user_pool_id: str
    client_id: str
    jwks_sha256: str
    manifest_sha256: str
    zip_sha256: str
    archive_path: Path
    execution_start_epoch: int
    execution_end_epoch: int

    def validate(self, *, account_id: str) -> bool:
        return (
            type(account_id) is str and _ACCOUNT.fullmatch(account_id) is not None and account_id != "0" * 12
            and type(self.source_sha) is str and re.fullmatch(r"[0-9a-f]{40}\Z", self.source_sha) is not None and self.source_sha != "0" * 40
            and type(self.api_id) is str and re.fullmatch(r"[a-z0-9]{10}\Z", self.api_id) is not None
            and type(self.user_pool_id) is str and _POOL.fullmatch(self.user_pool_id) is not None
            and type(self.client_id) is str and 1 <= len(self.client_id) <= 128 and re.fullmatch(r"[A-Za-z0-9]+\Z", self.client_id) is not None
            and _SHA256.fullmatch(self.jwks_sha256) is not None
            and _SHA256.fullmatch(self.manifest_sha256) is not None
            and _SHA256.fullmatch(self.zip_sha256) is not None
            and isinstance(self.archive_path, Path)
            and type(self.execution_start_epoch) is int and type(self.execution_end_epoch) is int
            and not isinstance(self.execution_start_epoch, bool) and not isinstance(self.execution_end_epoch, bool)
            and 0 < self.execution_end_epoch - self.execution_start_epoch <= 300
        )


def _read_multiuser_archive(
    receipt: MultiuserBuildReceipt,
    *,
    account_id: str,
    acl_checker: Callable[[Path], bool] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    if not receipt.validate(account_id=account_id):
        raise RuntimeUpdateError("build_receipt_invalid")
    try:
        from scripts.run_aws_retained_dev_bootstrap import validate_private_location
        path = validate_private_location(receipt.archive_path, acl_checker=acl_checker)
    except Exception:
        raise RuntimeUpdateError("artifact_source_invalid") from None
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0 or path.stat().st_size > _archive_base.MAX_ARCHIVE_BYTES:
        raise RuntimeUpdateError("artifact_source_invalid")
    with path.open("rb") as stream:
        body = stream.read(_archive_base.MAX_ARCHIVE_BYTES + 1)
    if len(body) > _archive_base.MAX_ARCHIVE_BYTES or hashlib.sha256(body).hexdigest() != receipt.zip_sha256:
        raise RuntimeUpdateError("artifact_hash_mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _archive_base.MAX_FILE_COUNT:
                raise ValueError
            names: set[str] = set()
            total = 0
            for info in infos:
                name = info.filename
                if (type(name) is not str or not name or name.startswith("/") or "\\" in name
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or info.is_dir() or name.casefold() in names or info.file_size < 0
                    or info.file_size > _archive_base.MAX_ENTRY_BYTES):
                    raise ValueError
                names.add(name.casefold())
                total += info.file_size
                if total > _archive_base.MAX_TOTAL_BYTES:
                    raise ValueError
            manifest_info = archive.getinfo(f"mapit/{MANIFEST_FILENAME}")
            jwks_info = archive.getinfo(f"mapit/{JWKS_FILENAME}")
            if manifest_info.file_size > MAX_MANIFEST_BYTES or jwks_info.file_size > MAX_JWKS_BYTES:
                raise ValueError
            manifest_raw = archive.read(manifest_info)
            jwks_raw = archive.read(jwks_info)
    except RuntimeUpdateError:
        raise
    except Exception:
        raise RuntimeUpdateError("artifact_invalid") from None
    if hashlib.sha256(manifest_raw).hexdigest() != receipt.manifest_sha256 or hashlib.sha256(jwks_raw).hexdigest() != receipt.jwks_sha256:
        raise RuntimeUpdateError("artifact_binding_invalid")
    try:
        manifest = parse_manifest(manifest_raw, expected_digest=receipt.manifest_sha256, account_id=account_id)
        parse_cognito_jwks(jwks_raw)
        if any(manifest.get(key) != expected for key, expected in (
            ("source_sha", receipt.source_sha), ("api_id", receipt.api_id),
            ("user_pool_id", receipt.user_pool_id), ("client_id", receipt.client_id),
            ("jwks_sha256", receipt.jwks_sha256),
        )):
            raise ValueError
    except Exception:
        raise RuntimeUpdateError("manifest_invalid") from None
    return body, manifest


def build_multiuser_candidate_template(
    receipt: MultiuserBuildReceipt, *, account_id: str, bucket: str,
    callback_url: str, subjects: tuple[str, str], tenant_keys: tuple[str, str],
) -> dict[str, Any]:
    """Construct the exact 19-resource V2 target from the validated receipt."""
    if not receipt.validate(account_id=account_id):
        raise RuntimeUpdateError("build_receipt_invalid")
    try:
        return build_retained_dev_multiuser_template(
            api_id=receipt.api_id, bucket=bucket, zip_sha256=receipt.zip_sha256,
            source_sha256=receipt.source_sha, jwks_sha256=receipt.jwks_sha256,
            manifest_sha256=receipt.manifest_sha256, account_id=account_id,
            execution_start_epoch=receipt.execution_start_epoch,
            execution_end_epoch=receipt.execution_end_epoch, callback_url=callback_url,
            subjects=subjects, tenant_keys=tenant_keys,
        )
    except Exception:
        raise RuntimeUpdateError("candidate_invalid") from None


def run_multiuser_update_step(
    clients: Mapping[str, Any], journal: Any, *, step: str, account_id: str,
    stack_arn: str, caller_arn: str, cfn_role_arn: str, source_sha: str,
    run_token: str, receipt: MultiuserBuildReceipt, callback_url: str,
    subjects: tuple[str, str], tenant_keys: tuple[str, str], bucket: str,
    authorized_from_epoch: int, authorized_until_epoch: int,
    clock: Callable[[], float] = time.time,
    archive_acl_checker: Callable[[Path], bool] | None = None,
) -> dict[str, Any]:
    """Run setup-11 to V2-runtime-19 using the real closed update core.

    The target is always reconstructed from the validated V2 receipt and the
    exact multi-user factory.  A caller cannot supply an arbitrary template or
    switch this operation to one of the historical five-resource builders.
    """
    try:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "lambda", "apigatewayv2"}:
            raise RuntimeUpdateError("clients_invalid")
        if not isinstance(receipt, MultiuserBuildReceipt) or source_sha != receipt.source_sha:
            raise RuntimeUpdateError("build_receipt_invalid")
        if (type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
            or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool)
            or not 0 < authorized_until_epoch - authorized_from_epoch <= 3600):
            raise RuntimeUpdateError("window_invalid")
        _body, manifest = _read_multiuser_archive(
            receipt, account_id=account_id, acl_checker=archive_acl_checker
        )
        expected_tenants = [
            {"key": tenant_keys[index], "subject": subjects[index], "label": f"synthetic-{chr(65 + index)}"}
            for index in range(2)
        ]
        if manifest.get("tenants") != expected_tenants:
            raise RuntimeUpdateError("manifest_binding_invalid")
        prior = build_retained_dev_multiuser_setup(api_id=receipt.api_id, callback_url=callback_url)
        target = build_multiuser_candidate_template(
            receipt, account_id=account_id, bucket=bucket, callback_url=callback_url,
            subjects=subjects, tenant_keys=tenant_keys,
        )
        if type(run_token) is not str or not re.fullmatch(r"dev-multiuser-[0-9a-f]{32}\Z", run_token):
            raise RuntimeUpdateError("binding_invalid")
        core = __import__("scripts.dev_multiuser_closed_update", fromlist=["ClosedDevUpdate"]).ClosedDevUpdate(
            clients, journal, account=account_id, caller_arn=caller_arn,
            stack_arn=stack_arn, prior_template=prior, target_template=target,
            service_role_arn=cfn_role_arn, source_sha=source_sha,
            start=authorized_from_epoch, end=authorized_until_epoch,
            token=run_token, clock=clock,
        )
        # The coordinator-facing vocabulary is deliberately different from
        # the core's internal one.  Keep the public runner steps stable while
        # translating only at this closed boundary.
        core_step = {"request-update": "update", "check-update": "readback"}.get(step, step)
        return _safe_core_result(core.run(core_step), fallback="runtime_update_failed")
    except RuntimeUpdateError as exc:
        return {"success": False, "category": exc.category}
    except Exception:
        return {"success": False, "category": "runtime_update_failed"}


def run_recurrent_iam_step(
    clients: Mapping[str, Any], journal: Any, *, step: str, account_id: str,
    stack_arn: str, caller_arn: str, source_sha: str, run_token: str,
    role_bindings: Mapping[str, Any], observed_user_pool_id: str,
    authorized_from_epoch: int, authorized_until_epoch: int,
) -> dict[str, Any]:
    """Run the separate bootstrap-V2 to recurrent IAM role update core."""
    try:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "lambda", "apigatewayv2"}:
            raise RuntimeUpdateError("clients_invalid")
        bootstrap = build_cd_retained_dev_multiuser_roles(**dict(role_bindings), observed_user_pool_id=None)
        recurrent = build_recurrent_iam_template(role_bindings, observed_user_pool_id=observed_user_pool_id)
        if type(run_token) is not str or not re.fullmatch(r"dev-multiuser-[0-9a-f]{32}\Z", run_token):
            raise RuntimeUpdateError("binding_invalid")
        from scripts.dev_multiuser_closed_update import ClosedDevUpdate
        core = ClosedDevUpdate(
            clients, journal, account=account_id, caller_arn=caller_arn,
            stack_arn=stack_arn, prior_template=bootstrap, target_template=recurrent,
            service_role_arn=None, source_sha=source_sha,
            start=authorized_from_epoch, end=authorized_until_epoch, token=run_token,
        )
        core_step = {"request-update": "update", "check-update": "readback"}.get(step, step)
        return _safe_core_result(core.run(core_step), fallback="recurrent_roles_update_failed")
    except RuntimeUpdateError as exc:
        return {"success": False, "category": exc.category}
    except Exception:
        return {"success": False, "category": "recurrent_roles_update_failed"}


def _artifact_state(*, account_id: str, bucket: str, run_id: str, receipt: MultiuserBuildReceipt,
                    key: str, size_bytes: int, start: int, end: int, status: str, revision: int,
                    last_observed_epoch: float) -> dict[str, Any]:
    return {
        "schema": 1, "kind": "retained-dev-multiuser-artifact-publication", "account_id": account_id,
        "bucket": bucket, "run_id": run_id, "source_sha": receipt.source_sha,
        "manifest_sha256": receipt.manifest_sha256, "zip_sha256": receipt.zip_sha256,
        "artifact_key": key, "size_bytes": size_bytes, "authorized_from_epoch": start,
        "authorized_until_epoch": end, "last_observed_epoch": last_observed_epoch,
        "intent": {"operation": "publish", "artifact_key": key, "zip_sha256": receipt.zip_sha256,
                   "manifest_sha256": receipt.manifest_sha256},
        "status": status, "revision": revision,
    }


def publish_multiuser_candidate(
    s3_client: Any, journal: Any, receipt: MultiuserBuildReceipt, *, account_id: str,
    bucket: str, run_id: str, authorized_from_epoch: int, authorized_until_epoch: int,
    wall_clock: Callable[[], float], monotonic: Callable[[], float],
    archive_acl_checker: Callable[[Path], bool] | None = None,
    step: str = "request-update",
) -> dict[str, Any]:
    """Publish one validated V2 ZIP with durable intent and no write replay."""
    calls = 0
    try:
        if step not in {"preflight", "request-update", "check-update"}:
            raise RuntimeUpdateError("step_invalid")
        if bucket != f"honda-mapit-mcp-dev-retained-{account_id}-eu-west-1" or type(run_id) is not str or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", run_id):
            raise RuntimeUpdateError("binding_invalid")
        journal_methods = ("load", "locked") if step == "preflight" else ("load", "compare_and_set", "locked")
        s3_methods = ("head_object",) if step != "request-update" else ("head_object", "put_object")
        if (not all(callable(getattr(journal, name, None)) for name in journal_methods)
            or not all(callable(getattr(s3_client, name, None)) for name in s3_methods)):
            raise RuntimeUpdateError("clients_invalid")
        body, _manifest = _read_multiuser_archive(
            receipt, account_id=account_id, acl_checker=archive_acl_checker
        )
        start = authorized_from_epoch; end = authorized_until_epoch
        if type(start) is not int or type(end) is not int or isinstance(start, bool) or isinstance(end, bool) or not 0 < end - start <= 3600:
            raise RuntimeUpdateError("window_invalid")
        if not callable(wall_clock) or not callable(monotonic):
            raise RuntimeUpdateError("window_invalid")
        started = monotonic(); last_mono = started; last_wall = wall_clock()
        if type(started) not in (int, float) or isinstance(started, bool) or type(last_wall) not in (int, float) or isinstance(last_wall, bool):
            raise RuntimeUpdateError("window_invalid")
        def guard() -> None:
            nonlocal last_mono, last_wall
            now_mono = monotonic(); now_wall = wall_clock()
            if (type(now_mono) not in (int, float) or type(now_wall) not in (int, float)
                or isinstance(now_mono, bool) or isinstance(now_wall, bool)
                or now_mono < last_mono or now_wall < last_wall or now_wall < start or now_wall >= end
                or now_mono - started >= 30):
                raise RuntimeUpdateError("window_expired")
            last_mono, last_wall = float(now_mono), float(now_wall)
        guard()
        key = f"runtime/{receipt.zip_sha256}.zip"
        checksum = base64.b64encode(bytes.fromhex(receipt.zip_sha256)).decode("ascii")
        expected = _artifact_state(account_id=account_id, bucket=bucket, run_id=run_id, receipt=receipt, key=key, size_bytes=len(body), start=start, end=end, status="intent", revision=1, last_observed_epoch=float(last_wall))
        with journal.locked():
            guard(); prior = journal.load(); guard()
            if prior is not None:
                if not isinstance(prior, Mapping) or set(prior) != set(expected) or any(prior.get(key_name) != value for key_name, value in expected.items() if key_name not in {"status", "revision", "last_observed_epoch"}) or prior.get("status") not in {"intent", "verified"}:
                    raise RuntimeUpdateError("journal_conflict")
                if prior.get("status") == "verified":
                    response = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=account_id); calls += 1; guard()
                    if not isinstance(response, Mapping) or response.get("ContentLength") != len(body) or response.get("ChecksumSHA256") != checksum or response.get("ServerSideEncryption") != "AES256":
                        raise RuntimeUpdateError("artifact_head_mismatch")
                    return {"success": True, "category": "artifact_already_verified", "calls": calls, "head_verified": True}
                if step in {"preflight", "check-update"}:
                    try:
                        response = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=account_id)
                        calls += 1
                        guard()
                    except Exception:
                        raise RuntimeUpdateError("artifact_head_failed") from None
                    if not isinstance(response, Mapping) or response.get("ContentLength") != len(body) or response.get("ChecksumSHA256") != checksum or response.get("ServerSideEncryption") != "AES256":
                        raise RuntimeUpdateError("artifact_pending")
                    verified = dict(prior)
                    verified["status"] = "verified"
                    verified["revision"] = 2
                    verified["last_observed_epoch"] = last_wall
                    if step == "check-update" and journal.compare_and_set(1, verified) is not True:
                        raise RuntimeUpdateError("journal_verified_failed")
                    return {"success": True, "category": "artifact_reconciled", "calls": calls, "head_verified": True}
                raise RuntimeUpdateError("intent_present")
            if step == "preflight":
                return {"success": True, "category": "artifact_preflight_verified", "calls": calls, "head_verified": False}
            if step == "check-update":
                raise RuntimeUpdateError("preflight_required")
            guard()
            if journal.compare_and_set(None, expected) is not True:
                raise RuntimeUpdateError("journal_intent_failed")
            try:
                response = s3_client.put_object(Bucket=bucket, Key=key, Body=body, IfNoneMatch="*", ExpectedBucketOwner=account_id, ServerSideEncryption="AES256", ChecksumSHA256=checksum, ContentType="application/zip"); calls += 1
            except Exception:
                raise RuntimeUpdateError("artifact_put_ambiguous") from None
            guard()
            if not isinstance(response, Mapping) or response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200:
                raise RuntimeUpdateError("artifact_put_ambiguous")
            try:
                head = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=account_id); calls += 1
            except Exception:
                raise RuntimeUpdateError("artifact_head_failed") from None
            guard()
            if not isinstance(head, Mapping) or head.get("ContentLength") != len(body) or head.get("ChecksumSHA256") != checksum or head.get("ServerSideEncryption") != "AES256" or head.get("ContentType") != "application/zip":
                raise RuntimeUpdateError("artifact_head_mismatch")
            verified = dict(expected); verified["status"] = "verified"; verified["revision"] = 2; verified["last_observed_epoch"] = last_wall
            if journal.compare_and_set(1, verified) is not True:
                raise RuntimeUpdateError("journal_verified_failed")
            guard()
            return {"success": True, "category": "artifact_uploaded_verified", "calls": calls, "head_verified": True}
    except RuntimeUpdateError as exc:
        return {"success": False, "category": exc.category, "calls": calls}
    except Exception:
        return {"success": False, "category": "artifact_publish_failed", "calls": calls}


def _load_receipt_file(path: Path, *, account_id: str, acl_checker: Callable[[Path], bool] | None = None) -> MultiuserBuildReceipt:
    """Load one bounded private V2 receipt; never print its fields."""
    try:
        from scripts.run_aws_retained_dev_bootstrap import validate_private_location, _reject_duplicates
        resolved = validate_private_location(Path(path), acl_checker=acl_checker)
        size = resolved.stat().st_size
        if not 0 < size <= 4096:
            raise ValueError
        raw = resolved.read_bytes()
        if len(raw) != size:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates)
        fields = {"source_sha", "api_id", "user_pool_id", "client_id", "jwks_sha256", "manifest_sha256", "zip_sha256", "archive_path", "execution_start_epoch", "execution_end_epoch"}
        if type(value) is not dict or set(value) != fields or type(value["archive_path"]) is not str:
            raise ValueError
        receipt = MultiuserBuildReceipt(
            source_sha=value["source_sha"], api_id=value["api_id"], user_pool_id=value["user_pool_id"],
            client_id=value["client_id"], jwks_sha256=value["jwks_sha256"], manifest_sha256=value["manifest_sha256"],
            zip_sha256=value["zip_sha256"], archive_path=Path(value["archive_path"]),
            execution_start_epoch=value["execution_start_epoch"], execution_end_epoch=value["execution_end_epoch"],
        )
        if not receipt.validate(account_id=account_id):
            raise ValueError
        return receipt
    except RuntimeUpdateError:
        raise
    except Exception:
        raise RuntimeUpdateError("receipt_invalid") from None


def _validate_journal_namespace(journal: Any, *, operation: str, account_id: str,
                                source_sha: str, run_id: str, token: str | None = None) -> None:
    """Reject a state file belonging to another operation or source before SDK use."""
    try:
        state = journal.load()
    except Exception:
        raise RuntimeUpdateError("journal_invalid") from None
    if state is None:
        return
    if operation == "publish":
        if (not isinstance(state, Mapping) or state.get("kind") != "retained-dev-multiuser-artifact-publication"
            or state.get("account_id") != account_id or state.get("source_sha") != source_sha
            or state.get("run_id") != run_id):
            raise RuntimeUpdateError("journal_conflict")
        return
    binding = state.get("binding") if isinstance(state, Mapping) else None
    expected_token = token if token is not None else run_id
    if (not isinstance(binding, Mapping) or binding.get("account") != account_id
        or binding.get("source") != source_sha or binding.get("token") != expected_token):
        raise RuntimeUpdateError("journal_conflict")


def _load_roles_binding(path: Path, *, account_id: str) -> dict[str, Any]:
    """Load only the two private identifiers needed to target the role stack."""
    try:
        from scripts.run_aws_retained_dev_bootstrap import validate_private_location, _reject_duplicates
        resolved = validate_private_location(path)
        size = resolved.stat().st_size
        if not 0 < size <= 2048:
            raise ValueError
        with resolved.open("rb") as stream:
            raw = stream.read(2049)
        if len(raw) != size or len(raw) > 2048:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates)
        fields = {"stack_arn", "original_creation_run_id"}
        if type(value) is not dict or set(value) != fields or type(value["stack_arn"]) is not str:
            raise ValueError
        stack_pattern = rf"arn:aws:cloudformation:{REGION}:{re.escape(account_id)}:stack/honda-mapit-mcp-dev-retained-cd-delivery/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}\Z"
        if re.fullmatch(stack_pattern, value["stack_arn"]) is None or type(value["original_creation_run_id"]) is not int or isinstance(value["original_creation_run_id"], bool) or value["original_creation_run_id"] <= 0:
            raise ValueError
        return value
    except Exception:
        raise RuntimeUpdateError("roles_binding_invalid") from None


def _verify_caller_identity(sts_client: Any, *, account_id: str, caller_arn: str) -> None:
    try:
        response = sts_client.get_caller_identity()
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
            or metadata.get("HTTPStatusCode") != 200
            or response.get("Account") != account_id or response.get("Arn") != caller_arn):
            raise ValueError
    except Exception:
        raise RuntimeUpdateError("identity_mismatch") from None


def _build_runtime_clients() -> dict[str, Any]:
    """Lazy-create only fixed direct TLS clients for an explicitly invoked CLI."""
    blocked = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url"}
    if any(key.casefold() in blocked for key in os.environ):
        raise RuntimeUpdateError("proxy_or_custom_endpoint_rejected")
    try:
        import logging
        import boto3
        from botocore.config import Config
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        config = Config(region_name=REGION, connect_timeout=2, read_timeout=3, retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        iam_config = Config(region_name="us-east-1", connect_timeout=2, read_timeout=3, retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "lambda": "https://lambda.eu-west-1.amazonaws.com",
            "apigatewayv2": "https://apigateway.eu-west-1.amazonaws.com",
            "s3": "https://s3.eu-west-1.amazonaws.com",
            "iam": "https://iam.amazonaws.com",
        }
        return {
            name: session.client(
                name, region_name="us-east-1" if name == "iam" else REGION,
                endpoint_url=url, config=iam_config if name == "iam" else config, verify=True,
            ) for name, url in endpoints.items()
        }
    except RuntimeUpdateError:
        raise
    except Exception:
        raise RuntimeUpdateError("client_construction_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--operation", choices=("publish", "runtime", "recurrent"), required=True)
    parser.add_argument("--step", choices=("preflight", "request-update", "check-update"), required=True)
    parser.add_argument("--roles-binding", type=Path)
    args = parser.parse_args(argv)
    try:
        from scripts.run_aws_retained_dev_bootstrap import load_authorization, validate_private_location, validate_source_and_ci
        auth = load_authorization(validate_private_location(args.authorization))
        validate_source_and_ci(auth)
        receipt = _load_receipt_file(args.receipt, account_id=auth["account"])
        if auth.get("source_sha") != receipt.source_sha:
            raise RuntimeUpdateError("source_binding_invalid")
        from scripts.run_aws_retained_dev_role_bootstrap import _load_bindings
        bindings = _load_bindings(validate_private_location(args.bindings))
        if type(bindings) is not dict or bindings.get("account_id") != auth.get("account") or not receipt.validate(account_id=auth["account"]):
            raise RuntimeUpdateError("binding_invalid")
        # Construct the exact V2 role factory before creating any SDK client.
        build_recurrent_iam_template(bindings, observed_user_pool_id=receipt.user_pool_id)
        manifest = _read_multiuser_archive(receipt, account_id=auth["account"])[1]
        subjects = tuple(row["subject"] for row in manifest["tenants"])
        tenant_keys = tuple(row["key"] for row in manifest["tenants"])
        token = "dev-multiuser-" + hashlib.sha256(f"runtime:{auth['run_id']}:{auth['source_sha']}".encode()).hexdigest()[:32]
        roles_binding = None
        if args.operation in {"runtime", "recurrent"}:
            if args.roles_binding is None:
                raise RuntimeUpdateError("roles_binding_required")
            roles_binding = _load_roles_binding(args.roles_binding, account_id=auth["account"])
        journal = CasFileJournal(validate_private_location(args.state_dir))
        _validate_journal_namespace(
            journal, operation=args.operation, account_id=auth["account"],
            source_sha=receipt.source_sha, run_id=auth["run_id"], token=token,
        )
        clients = _build_runtime_clients()
        _verify_caller_identity(clients["sts"], account_id=auth["account"], caller_arn=auth["expected_caller_arn"])
        if args.operation == "publish":
            result = publish_multiuser_candidate(
                clients["s3"], journal, receipt, account_id=auth["account"],
                bucket=f"honda-mapit-mcp-dev-retained-{auth['account']}-eu-west-1", run_id=auth["run_id"],
                authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
                wall_clock=time.time, monotonic=time.monotonic, step=args.step,
            )
        elif args.operation == "runtime":
            from scripts.dev_multiuser_readback import verify_role_pair
            recurrent_template = build_recurrent_iam_template(bindings, observed_user_pool_id=receipt.user_pool_id)
            role_readback = verify_role_pair(
                {"iam": clients["iam"]}, recurrent_template, account=auth["account"],
                roles_stack_arn=roles_binding["stack_arn"],
                original_creation_run_id=roles_binding["original_creation_run_id"],
            )
            if role_readback.get("success") is not True:
                raise RuntimeUpdateError("roles_readback_failed")
            result = run_multiuser_update_step(
                {key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")}, journal,
                step=args.step, account_id=auth["account"], stack_arn=bindings["stack_arn"],
                caller_arn=auth["expected_caller_arn"], cfn_role_arn=f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update",
                source_sha=auth["source_sha"], run_token=token, receipt=receipt,
                callback_url="http://localhost:39031/callback", subjects=subjects, tenant_keys=tenant_keys,
                bucket=f"honda-mapit-mcp-dev-retained-{auth['account']}-eu-west-1",
                authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
            )
        else:
            bootstrap_template = build_cd_retained_dev_multiuser_roles(
                **dict(bindings), observed_user_pool_id=None,
            )
            recurrent_template = build_recurrent_iam_template(bindings, observed_user_pool_id=receipt.user_pool_id)
            from scripts.dev_multiuser_readback import verify_role_pair
            if args.step in {"preflight", "request-update"}:
                role_readback = verify_role_pair(
                    {"iam": clients["iam"]}, bootstrap_template, account=auth["account"],
                    roles_stack_arn=roles_binding["stack_arn"],
                    original_creation_run_id=roles_binding["original_creation_run_id"],
                )
                if role_readback.get("success") is not True:
                    result = {"success": False, "category": "roles_readback_failed"}
                else:
                    result = run_recurrent_iam_step(
                        {key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")}, journal,
                        step=args.step, account_id=auth["account"], stack_arn=roles_binding["stack_arn"],
                        caller_arn=auth["expected_caller_arn"], source_sha=auth["source_sha"], run_token=token,
                        role_bindings=bindings, observed_user_pool_id=receipt.user_pool_id,
                        authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
                    )
            else:
                result = run_recurrent_iam_step(
                    {key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")}, journal,
                    step=args.step, account_id=auth["account"], stack_arn=roles_binding["stack_arn"],
                    caller_arn=auth["expected_caller_arn"], source_sha=auth["source_sha"], run_token=token,
                    role_bindings=bindings, observed_user_pool_id=receipt.user_pool_id,
                    authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
                )
                if result.get("success") is True and result.get("category") == "readback_verified":
                    after = verify_role_pair(
                        {"iam": clients["iam"]}, recurrent_template, account=auth["account"],
                        roles_stack_arn=roles_binding["stack_arn"],
                        original_creation_run_id=roles_binding["original_creation_run_id"],
                    )
                    if after.get("success") is not True:
                        result = {"success": False, "category": "roles_readback_failed"}
    except RuntimeUpdateError as exc:
        result = {"success": False, "category": exc.category}
    except Exception:
        result = {"success": False, "category": "runtime_update_failed"}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RuntimeUpdateError", "build_recurrent_iam_template", "recurrent_iam_summary",
    "publish_candidate", "MultiuserBuildReceipt",
    "build_multiuser_candidate_template", "publish_multiuser_candidate",
    "run_multiuser_update_step", "run_recurrent_iam_step", "CasFileJournal",
    "main",
]
