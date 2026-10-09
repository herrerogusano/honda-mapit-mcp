"""Injected, one-shot coordinator for a closed owner-enrolled DEV update.

This module constructs no SDK clients and makes no network calls itself. Its
publisher, source/protection checkers, and live-state verifier are trusted
adapters supplied by a separately reviewed operator. Hashes bind artifacts and
receipts; they are not substitutes for those adapters' fresh provider
readbacks. The coordinator never opens the API, changes concurrency, creates
users, or handles MAPIT session credentials.

The pre-update owner-login context is historical evidence. Existing assisted
login context verification also pins handler code and revision, so it must not
be reused after this update or weakened to ignore that drift. A separately
reviewed post-update identity/runtime lineage check is required before human
owner login; this coordinator does not claim login or MAPIT-session acceptance.
"""
from __future__ import annotations

import hashlib
import json
import math
import base64
import re
import time
import uuid
import io
import zipfile
from collections.abc import Mapping
from typing import Any, Callable

from scripts.build_aws_dev_runtime import BuildSummary
from mapit.dev_enrolled_manifest import MANIFEST_FILENAME, INVITATION_JWKS_FILENAME, MAPIT_JWKS_FILENAME
from scripts.dev_owner_enrolled_runtime import (
    build_owner_enrolled_dev_runtime_target,
    compare_owner_enrolled_dev_runtime_target,
)

REGION = "eu-west-1"
APP_STACK_NAME = "honda-mapit-mcp-dev-retained"
SERVICE_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
AUTHORIZATION_TABLE = "honda-mapit-mcp-dev-tenants"
MAPIT_CONFIG_PATH = "/honda-mapit-mcp/dev/mapit-identity-binding-config"
_AUTH_KIND = "dev-owner-enrolled-delivery"
_AUTH_FIELDS = frozenset({
    "schema", "kind", "account_id", "operator_arn", "source_sha", "ci_run_id",
    "run_id", "authorized_from_epoch", "authorized_until_epoch", "stack_id",
    "service_role_arn", "artifact_bucket", "owner_context_sha256", "owner_pool_id",
    "owner_client_id", "owner_resource_uri", "owner_oauth_receipt_sha256",
    "mapit_bootstrap_authority_sha256", "mapit_bootstrap_receipt_sha256",
    "mapit_table_id", "invitation_receipt_sha256", "key_publication_receipt_sha256",
    "owner_tenant_key", "mapit_config_path", "mapit_config_version",
    "runtime_evidence_sha256", "historical_tenant_keys", "github_owner_id",
    "github_repository_id", "manifest_sha256", "invitation_jwks_sha256",
    "mapit_jwks_sha256", "prior_template_sha256", "execution_start_epoch",
    "execution_end_epoch", "prior_zip_sha256",
})
_RECEIPT_FIELDS = {
    "owner_oauth": frozenset({"status", "receipt_sha256", "account_id", "pool_id", "client_id", "resource_uri", "scope"}),
    "mapit_bootstrap": frozenset({"status", "receipt_sha256", "authority_sha256", "account_id", "tenant_key", "table_id"}),
    "invitation": frozenset({"status", "receipt_sha256", "account_id", "table_name", "tenant_key", "revision"}),
    "key_publication": frozenset({"status", "receipt_sha256", "account_id", "parameter_path", "version"}),
}
_STATE_FIELDS = frozenset({
    "phase", "account_id", "caller_arn", "stack_id", "stack_status", "template_sha256",
    "resource_count", "api_disabled", "lambda_reserved_concurrency", "handler_zip_sha256",
    "owner_issuer", "owner_client_id", "owner_tenant_key", "authorization_table",
    "authorization_row_status", "authorization_row_revision", "authorization_row_key",
    "mapit_table_id", "mapit_config_path", "mapit_config_version", "mapit_parameter_version",
    "leading_keys", "owner_context_sha256", "owner_oauth_receipt_sha256",
    "mapit_bootstrap_receipt_sha256", "invitation_receipt_sha256",
    "key_publication_receipt_sha256", "runtime_evidence_sha256", "runtime_checks", "completion_event",
})
_CHECKS = frozenset({
    "stack_ownership", "resource_inventory", "api_disabled", "lambda_reserved_zero",
    "owner_oauth_current", "owner_jwt_authorizer", "handler_artifact", "authorization_row",
    "mapit_binding", "config_version_one", "role_policy_exact", "historical_synthetic_policy_preserved",
    "artifact_bucket_private",
})
_PRE_CHECKS = {
    "stack_ownership": True, "resource_inventory": True, "api_disabled": True,
    "lambda_reserved_zero": True, "owner_oauth_current": True, "owner_jwt_authorizer": False,
    "handler_artifact": False, "authorization_row": True, "mapit_binding": True,
    "config_version_one": True, "role_policy_exact": True, "historical_synthetic_policy_preserved": True,
    "artifact_bucket_private": True,
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_POOL_ID = re.compile(r"eu-west-1_[A-Za-z0-9]{9,45}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9]{8,128}\Z")
_TABLE_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_UUID = re.compile(r"[0-9a-f]{32}\Z")
_MAX_TEMPLATE_BYTES = 64 * 1024
_MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
_MAX_WINDOW_SECONDS = 600


class OwnerEnrolledDeliveryError(ValueError):
    """Safe fixed-category failure; never includes provider or identity data."""

    CATEGORIES = frozenset({
        "binding_invalid", "accepted_evidence_invalid", "template_invalid", "artifact_invalid",
        "source_ci_failed", "protection_failed", "window_closed", "journal_invalid",
        "current_state_unverified", "artifact_write_unknown", "artifact_receipt_invalid",
        "update_write_unknown", "update_receipt_invalid", "update_not_accepted", "step_invalid",
    })

    def __init__(self, category: str):
        safe = category if type(category) is str and category in self.CATEGORIES else "current_state_unverified"
        self.category = safe
        super().__init__(safe)


def _fail(category: str) -> None:
    raise OwnerEnrolledDeliveryError(category)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _valid_sha(value: Any, pattern=_SHA256) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _validate_authority(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _AUTH_FIELDS:
        _fail("binding_invalid")
    account = value["account_id"]
    start, end = value["authorized_from_epoch"], value["authorized_until_epoch"]
    if (type(value["schema"]) is not int or value["schema"] != 1
            or value["kind"] != _AUTH_KIND
            or type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "0" * 12
            or type(value["operator_arn"]) is not str
            or re.fullmatch(rf"arn:aws:iam::{account}:user/[A-Za-z0-9+=,.@_/-]+", value["operator_arn"]) is None
            or type(value["source_sha"]) is not str or _SHA40.fullmatch(value["source_sha"]) is None
            or value["source_sha"] == "0" * 40
            or type(value["ci_run_id"]) is not int or isinstance(value["ci_run_id"], bool) or value["ci_run_id"] <= 0
            or type(value["run_id"]) is not str or _UUID.fullmatch(value["run_id"]) is None
            or any(type(value[k]) is not int or isinstance(value[k], bool) or value[k] <= 0
                   for k in ("github_owner_id", "github_repository_id"))
            or type(start) is not int or isinstance(start, bool)
            or type(end) is not int or isinstance(end, bool)
            or start <= 0 or end <= start or end - start > _MAX_WINDOW_SECONDS):
        _fail("binding_invalid")
    execution_start, execution_end = value["execution_start_epoch"], value["execution_end_epoch"]
    if (type(execution_start) is not int or isinstance(execution_start, bool)
            or type(execution_end) is not int or isinstance(execution_end, bool)
            or not start <= execution_start < execution_end <= end
            or execution_end - execution_start > 300):
        _fail("binding_invalid")
    stack = value["stack_id"]
    if (type(stack) is not str or re.fullmatch(
            rf"arn:aws:cloudformation:{REGION}:{account}:stack/{APP_STACK_NAME}/[0-9a-f-]{{36}}", stack) is None
            or value["service_role_arn"] != f"arn:aws:iam::{account}:role/{SERVICE_ROLE_NAME}"):
        _fail("binding_invalid")
    for field in ("owner_context_sha256", "owner_oauth_receipt_sha256", "mapit_bootstrap_authority_sha256",
                  "mapit_bootstrap_receipt_sha256", "invitation_receipt_sha256",
                  "key_publication_receipt_sha256", "runtime_evidence_sha256", "manifest_sha256",
                  "invitation_jwks_sha256", "mapit_jwks_sha256", "prior_template_sha256",
                  "prior_zip_sha256"):
        if not _valid_sha(value[field]):
            _fail("binding_invalid")
    if (type(value["artifact_bucket"]) is not str
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value["artifact_bucket"])
            or ".." in value["artifact_bucket"]
            or type(value["owner_pool_id"]) is not str or _POOL_ID.fullmatch(value["owner_pool_id"]) is None
            or type(value["owner_client_id"]) is not str or _CLIENT_ID.fullmatch(value["owner_client_id"]) is None
            or type(value["owner_resource_uri"]) is not str
            or not re.fullmatch(rf"https://[a-z0-9]{{10}}\.execute-api\.{REGION}\.amazonaws\.com/mcp",
                                value["owner_resource_uri"])
            or type(value["owner_tenant_key"]) is not str or _TENANT_KEY.fullmatch(value["owner_tenant_key"]) is None
            or type(value["mapit_table_id"]) is not str or _TABLE_ID.fullmatch(value["mapit_table_id"]) is None
            or value["mapit_config_path"] != MAPIT_CONFIG_PATH
            or type(value["mapit_config_version"]) is not int or value["mapit_config_version"] != 1):
        _fail("binding_invalid")
    old_keys = value["historical_tenant_keys"]
    if (type(old_keys) is not list or len(old_keys) != 2
            or any(type(key) is not str or _TENANT_KEY.fullmatch(key) is None for key in old_keys)
            or len(set(old_keys)) != 2 or value["owner_tenant_key"] in old_keys):
        _fail("binding_invalid")
    return dict(value)


def _validate_accepted(value: Any, binding: Mapping[str, Any]) -> dict[str, Any]:
    names = set(_RECEIPT_FIELDS)
    if type(value) is not dict or set(value) != names:
        _fail("accepted_evidence_invalid")
    account = binding["account_id"]
    expected = {
        "owner_oauth": {"status": "accepted", "account_id": account, "pool_id": binding["owner_pool_id"],
                        "client_id": binding["owner_client_id"], "resource_uri": binding["owner_resource_uri"],
                        "scope": binding["owner_resource_uri"] + "/use"},
        "mapit_bootstrap": {"status": "accepted", "account_id": account,
                             "authority_sha256": binding["mapit_bootstrap_authority_sha256"],
                             "tenant_key": binding["owner_tenant_key"], "table_id": binding["mapit_table_id"]},
        "invitation": {"status": "accepted", "account_id": account, "table_name": AUTHORIZATION_TABLE,
                       "tenant_key": binding["owner_tenant_key"], "revision": 1},
        "key_publication": {"status": "accepted", "account_id": account,
                            "parameter_path": binding["mapit_config_path"], "version": 1},
    }
    for name, fields in _RECEIPT_FIELDS.items():
        row = value.get(name)
        if type(row) is not dict or set(row) != fields:
            _fail("accepted_evidence_invalid")
        integer_field = {"invitation": "revision", "key_publication": "version"}.get(name)
        if integer_field is not None and type(row[integer_field]) is not int:
            _fail("accepted_evidence_invalid")
        if any(row.get(key) != item for key, item in expected[name].items()):
            _fail("accepted_evidence_invalid")
        if not _valid_sha(row.get("receipt_sha256")):
            _fail("accepted_evidence_invalid")
        if row["receipt_sha256"] != binding[
            {"owner_oauth": "owner_oauth_receipt_sha256", "mapit_bootstrap": "mapit_bootstrap_receipt_sha256",
             "invitation": "invitation_receipt_sha256", "key_publication": "key_publication_receipt_sha256"}[name]
        ]:
            _fail("accepted_evidence_invalid")
    return value


def _template_sha(value: Any) -> str:
    try:
        raw = _canonical(value)
    except Exception:
        _fail("template_invalid")
    if len(raw) > _MAX_TEMPLATE_BYTES:
        _fail("template_invalid")
    return hashlib.sha256(raw).hexdigest()


def _summary_dict(summary: Any) -> dict[str, Any] | None:
    if type(summary) is BuildSummary:
        return {
            "zip_bytes": summary.zip_bytes, "sha256": summary.sha256,
            "wheel_count": summary.wheel_count, "archive_entries": summary.archive_entries,
            "source_modules": summary.source_modules, "public_key_count": summary.public_key_count,
            "dependencies_valid": summary.dependencies_valid,
            "source_allowlist_valid": summary.source_allowlist_valid,
            "lock_valid": summary.lock_valid, "manifest_valid": summary.manifest_valid,
        }
    return summary if type(summary) is dict else None


def _sdk_success_checks(summary: Any) -> bool:
    summary = _summary_dict(summary)
    if summary is None:
        return False
    return (type(summary) is dict and set(summary) == {
        "zip_bytes", "sha256", "wheel_count", "archive_entries", "source_modules",
        "public_key_count", "dependencies_valid", "source_allowlist_valid", "lock_valid", "manifest_valid",
    } and type(summary["zip_bytes"]) is int and not isinstance(summary["zip_bytes"], bool)
        and 0 < summary["zip_bytes"] <= _MAX_ARCHIVE_BYTES
        and _valid_sha(summary["sha256"]) and summary["sha256"] != "0" * 64
        and type(summary["wheel_count"]) is int and not isinstance(summary["wheel_count"], bool)
        and summary["wheel_count"] > 0
        and type(summary["archive_entries"]) is int and not isinstance(summary["archive_entries"], bool)
        and summary["archive_entries"] > 0
        and type(summary["source_modules"]) is int and not isinstance(summary["source_modules"], bool)
        and summary["source_modules"] > 0
        and type(summary["public_key_count"]) is int and not isinstance(summary["public_key_count"], bool)
        and summary["public_key_count"] >= 2
        and all(type(summary[name]) is bool and summary[name] is True for name in (
            "dependencies_valid", "source_allowlist_valid", "lock_valid", "manifest_valid")))


def _strict_state(value: Any, *, phase: str, binding: Mapping[str, Any],
                  prior_sha: str, target_sha: str, zip_sha: str, leading_keys: list[str],
                  issuer: str, pending: bool = False) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _STATE_FIELDS or value.get("phase") != phase:
        _fail("current_state_unverified")
    expected_sha = prior_sha if phase != "accepted" else target_sha
    expected_zip = binding.get("prior_zip_sha256") if phase != "accepted" else zip_sha
    expected_statuses = ({"UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"} if pending else
                         {"UPDATE_COMPLETE"})
    expected_keys = leading_keys if phase == "accepted" else binding["historical_tenant_keys"]
    if pending:
        # During an in-progress update, non-security resources may be a mix of
        # old and target values. Only acknowledge pending while ownership and
        # the externally relevant closed controls remain positively verified.
        pending_checks = value.get("runtime_checks") if type(value) is dict else None
        if (type(value) is not dict or set(value) != _STATE_FIELDS
                or value.get("phase") != "accepted"
                or value.get("account_id") != binding["account_id"]
                or value.get("caller_arn") != binding["operator_arn"]
                or value.get("stack_id") != binding["stack_id"]
                or value.get("stack_status") not in expected_statuses
                or value.get("resource_count") != 19
                or type(value.get("api_disabled")) is not bool or value["api_disabled"] is not True
                or type(value.get("lambda_reserved_concurrency")) is not int
                or isinstance(value["lambda_reserved_concurrency"], bool)
                or value["lambda_reserved_concurrency"] != 0
                or type(pending_checks) is not dict or set(pending_checks) != _CHECKS
                or any(type(v) is not bool for v in pending_checks.values())
                or any(pending_checks.get(k) is not True
                       for k in ("stack_ownership", "resource_inventory", "api_disabled", "lambda_reserved_zero"))
                or value.get("completion_event") is not None):
            _fail("current_state_unverified")
        return value
    if (value["account_id"] != binding["account_id"] or value["caller_arn"] != binding["operator_arn"]
            or value["stack_id"] != binding["stack_id"] or value["stack_status"] not in expected_statuses
            or value["template_sha256"] != expected_sha
            or type(value["resource_count"]) is not int or value["resource_count"] != 19
            or type(value["api_disabled"]) is not bool or value["api_disabled"] is not True
            or type(value["lambda_reserved_concurrency"]) is not int
            or isinstance(value["lambda_reserved_concurrency"], bool) or value["lambda_reserved_concurrency"] != 0
            or value["handler_zip_sha256"] != expected_zip
            or value["owner_issuer"] != issuer or value["owner_client_id"] != binding["owner_client_id"]
            or value["owner_tenant_key"] != binding["owner_tenant_key"]
            or (phase != "accepted" and value["owner_context_sha256"] != binding["owner_context_sha256"])
            or (phase == "accepted" and (not _valid_sha(value["owner_context_sha256"])
                or value["owner_context_sha256"] == binding["owner_context_sha256"]))
            or value["owner_oauth_receipt_sha256"] != binding["owner_oauth_receipt_sha256"]
            or value["mapit_bootstrap_receipt_sha256"] != binding["mapit_bootstrap_receipt_sha256"]
            or value["invitation_receipt_sha256"] != binding["invitation_receipt_sha256"]
            or value["key_publication_receipt_sha256"] != binding["key_publication_receipt_sha256"]
            or (phase != "accepted" and value["runtime_evidence_sha256"] != binding["runtime_evidence_sha256"])
            or (phase == "accepted" and not _valid_sha(value["runtime_evidence_sha256"]))
            or value["authorization_table"] != AUTHORIZATION_TABLE
            or value["authorization_row_status"] != "active"
            or type(value["authorization_row_revision"]) is not int or value["authorization_row_revision"] != 1
            or value["authorization_row_key"] != binding["owner_tenant_key"]
            or value["mapit_table_id"] != binding["mapit_table_id"]
            or value["mapit_config_path"] != binding["mapit_config_path"]
            or type(value["mapit_config_version"]) is not int or value["mapit_config_version"] != 1
            or type(value["mapit_parameter_version"]) is not int or value["mapit_parameter_version"] != 1
            or value["leading_keys"] != expected_keys):
        _fail("current_state_unverified")
    checks = value["runtime_checks"]
    expected_checks = {name: True for name in _CHECKS} if phase == "accepted" else _PRE_CHECKS
    if (type(checks) is not dict or set(checks) != _CHECKS
            or any(type(v) is not bool for v in checks.values()) or checks != expected_checks):
        _fail("current_state_unverified")
    event = value["completion_event"]
    if phase == "accepted":
        if (type(event) is not dict or set(event) != {
                "stack_id", "resource_type", "status", "client_request_token", "timestamp_epoch",
                "response_http_status", "matching_completion_events"}
                or event.get("stack_id") != binding["stack_id"]
                or event.get("resource_type") != "AWS::CloudFormation::Stack"
                or event.get("status") != "UPDATE_COMPLETE"
                or event.get("client_request_token") != f"owner-enrolled-{binding['run_id']}"
                or type(event.get("response_http_status")) is not int or event["response_http_status"] != 200
                or type(event.get("matching_completion_events")) is not int
                or event["matching_completion_events"] != 1
                or type(event.get("timestamp_epoch")) not in (int, float)
                or isinstance(event.get("timestamp_epoch"), bool)
                or not math.isfinite(event["timestamp_epoch"])
                or not binding["execution_start_epoch"] <= event["timestamp_epoch"] < binding["execution_end_epoch"]):
            _fail("current_state_unverified")
    elif event is not None:
        _fail("current_state_unverified")
    return value


class OwnerEnrolledClosedDelivery:
    """Fresh-window one-shot publication and closed update, all adapters injected.

    `current_state` is a trusted live verifier: its implementation must perform
    exact AWS readbacks, not merely compare supplied digests. `publish_once`
    and `update_once` must each perform one provider write at most and return the
    documented strict receipt. This class fences retries but does not itself
    prove the adapters' SDK credential provenance.
    """

    def __init__(self, *, authority: dict[str, Any], accepted: dict[str, Any],
                 prior_template: dict[str, Any], mapit_bootstrap_template: dict[str, Any],
                 manifest_raw: bytes, invitation_jwks: bytes, mapit_jwks: bytes,
                 archive_bytes: bytes, archive_summary: dict[str, Any],
                 artifact_journal: Any, update_journal: Any,
                 source_check: Callable[[dict[str, Any]], Any],
                 protection_check: Callable[[dict[str, Any]], Any],
                 current_state: Callable[[str, dict[str, Any]], Any],
                 publish_once: Callable[[dict[str, Any], bytes], Any],
                 update_once: Callable[[str, dict[str, Any], str, str], Any],
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        self.authority = _validate_authority(authority)
        self.accepted = _validate_accepted(accepted, self.authority)
        if (artifact_journal is update_journal or not callable(source_check) or not callable(protection_check)
                or not callable(current_state) or not callable(publish_once) or not callable(update_once)):
            _fail("binding_invalid")
        summary_values = _summary_dict(archive_summary)
        if (type(manifest_raw) is not bytes or not manifest_raw or len(manifest_raw) > 2048
                or type(invitation_jwks) is not bytes or not invitation_jwks
                or type(mapit_jwks) is not bytes or not mapit_jwks
                or type(archive_bytes) is not bytes or not 0 < len(archive_bytes) <= _MAX_ARCHIVE_BYTES
                or not _sdk_success_checks(archive_summary)
                or summary_values["zip_bytes"] != len(archive_bytes)
                or summary_values["sha256"] != hashlib.sha256(archive_bytes).hexdigest()):
            _fail("artifact_invalid")
        # The summary is a trusted builder adapter's metadata, not proof that
        # these security inputs actually occur in this archive. Bind their
        # exact embedded bytes independently, without extracting any paths.
        try:
            expected_inputs = {f"mapit/{MANIFEST_FILENAME}": manifest_raw,
                f"mapit/{INVITATION_JWKS_FILENAME}": invitation_jwks,
                f"mapit/{MAPIT_JWKS_FILENAME}": mapit_jwks}
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                infos = archive.infolist()
                names = [info.filename for info in infos]
                if len(names) != len(set(name.casefold() for name in names)):
                    raise ValueError
                for name, expected_bytes in expected_inputs.items():
                    info = archive.getinfo(name)
                    if info.file_size != len(expected_bytes) or archive.read(info) != expected_bytes:
                        raise ValueError
        except Exception:
            _fail("artifact_invalid")
        self.clock, self.monotonic = clock, monotonic
        start_mono = self.monotonic()
        if type(start_mono) not in (int, float) or isinstance(start_mono, bool) or not math.isfinite(start_mono):
            _fail("window_closed")
        self._last_mono = float(start_mono)
        self._started_mono = float(start_mono)
        self._source_check, self._protection_check = source_check, protection_check
        self._current_state, self._publish_once, self._update_once = current_state, publish_once, update_once
        self._artifact_journal, self._update_journal = artifact_journal, update_journal
        self.archive = archive_bytes
        self.prior = json.loads(_canonical(prior_template))
        self.bootstrap = json.loads(_canonical(mapit_bootstrap_template))
        self.prior_sha = _template_sha(self.prior)
        if self.prior_sha != self.authority["prior_template_sha256"]:
            _fail("accepted_evidence_invalid")
        try:
            prior_code = self.prior["Resources"]["McpHandler"]["Properties"]["Code"]
            prior_key = prior_code["S3Key"]
            prior_zip_match = re.fullmatch(r"runtime/([0-9a-f]{64})\.zip", prior_key)
        except Exception:
            prior_zip_match = None
        if prior_zip_match is None or prior_zip_match.group(1) != self.authority["prior_zip_sha256"]:
            _fail("accepted_evidence_invalid")
        try:
            prior_tenant_keys = [row["key"] for row in self.prior["Metadata"]["ManifestContract"]["tenants"]]
        except Exception:
            _fail("accepted_evidence_invalid")
        if prior_tenant_keys != self.authority["historical_tenant_keys"]:
            _fail("accepted_evidence_invalid")
        self.zip_sha = hashlib.sha256(archive_bytes).hexdigest()
        manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        if (manifest_sha != self.authority["manifest_sha256"]
                or hashlib.sha256(invitation_jwks).hexdigest() != self.authority["invitation_jwks_sha256"]
                or hashlib.sha256(mapit_jwks).hexdigest() != self.authority["mapit_jwks_sha256"]):
            _fail("accepted_evidence_invalid")
        try:
            self.target = build_owner_enrolled_dev_runtime_target(
                prior_template=self.prior, mapit_bootstrap_template=self.bootstrap,
                manifest_raw=manifest_raw, invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
                manifest_sha256=manifest_sha, account_id=self.authority["account_id"],
                source_sha=self.authority["source_sha"], zip_sha256=self.zip_sha,
                execution_start_epoch=self.authority["execution_start_epoch"],
                execution_end_epoch=self.authority["execution_end_epoch"],
            )
            self.target_sha = _template_sha(self.target)
            flags = compare_owner_enrolled_dev_runtime_target(
                prior_template=self.prior, target_template=self.target,
                mapit_bootstrap_template=self.bootstrap, manifest_raw=manifest_raw,
                invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
                manifest_sha256=manifest_sha, account_id=self.authority["account_id"],
                source_sha=self.authority["source_sha"], zip_sha256=self.zip_sha,
                execution_start_epoch=self.authority["execution_start_epoch"],
                execution_end_epoch=self.authority["execution_end_epoch"],
            )
        except Exception:
            _fail("template_invalid")
        if (set(flags) != {"prior_template_reconstructed", "target_matches_exact_owner_profile",
                          "resource_count_unchanged", "api_endpoint_disabled", "lambda_reserved_concurrency_zero",
                          "historical_synthetic_tenant_keys_preserved", "historical_synthetic_pool_resources_unchanged"}
                or any(type(flag) is not bool or flag is not True for flag in flags.values())):
            _fail("template_invalid")
        code = self.target["Resources"]["McpHandler"]["Properties"]["Code"]
        if code.get("S3Bucket") != self.authority["artifact_bucket"]:
            _fail("binding_invalid")
        if (self.target["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"].get(
                "MAPIT_COGNITO_CLIENT_ID") != self.authority["owner_client_id"]):
            _fail("binding_invalid")
        self.leading_keys = [*self.authority["historical_tenant_keys"], self.authority["owner_tenant_key"]]
        self.issuer = self.target["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"]
        self.binding = {
            "schema": 1, "kind": _AUTH_KIND, "authority": dict(self.authority),
            "accepted": json.loads(_canonical(self.accepted)), "prior_template_sha256": self.prior_sha,
            "target_template_sha256": self.target_sha, "artifact_sha256": self.zip_sha,
            "artifact_size": len(self.archive), "client_request_token": f"owner-enrolled-{self.authority['run_id']}",
        }
        self._window_seconds = self.authority["authorized_until_epoch"] - self.authority["authorized_from_epoch"]
        self._last_wall = None
        self._window_failed = False
        self._integrity_snapshot = {
            "authority": _canonical(self.authority), "accepted": _canonical(self.accepted),
            "prior": _canonical(self.prior), "bootstrap": _canonical(self.bootstrap),
            "target": _canonical(self.target), "binding": _canonical(self.binding),
            "leading_keys": _canonical(self.leading_keys), "issuer": self.issuer,
            "archive_sha256": hashlib.sha256(self.archive).hexdigest(),
        }

    def _window(self) -> None:
        if self._window_failed:
            _fail("window_closed")
        try:
            stable = (
                _canonical(self.authority) == self._integrity_snapshot["authority"]
                and _canonical(self.accepted) == self._integrity_snapshot["accepted"]
                and _canonical(self.prior) == self._integrity_snapshot["prior"]
                and _canonical(self.bootstrap) == self._integrity_snapshot["bootstrap"]
                and _canonical(self.target) == self._integrity_snapshot["target"]
                and _canonical(self.binding) == self._integrity_snapshot["binding"]
                and _canonical(self.leading_keys) == self._integrity_snapshot["leading_keys"]
                and self.issuer == self._integrity_snapshot["issuer"]
                and hashlib.sha256(self.archive).hexdigest() == self._integrity_snapshot["archive_sha256"]
            )
        except Exception:
            stable = False
        if not stable:
            self._window_failed = True
            _fail("binding_invalid")
        try:
            wall = self.clock()
            mono = self.monotonic()
        except Exception:
            self._window_failed = True
            _fail("window_closed")
        if (type(wall) not in (int, float) or isinstance(wall, bool) or not math.isfinite(wall)
                or type(mono) not in (int, float) or isinstance(mono, bool) or not math.isfinite(mono)
                or mono < self._last_mono or mono - self._started_mono >= self._window_seconds
                or not self.authority["authorized_from_epoch"] <= wall < self.authority["authorized_until_epoch"]
                or self._last_wall is not None and wall < self._last_wall):
            self._window_failed = True
            _fail("window_closed")
        self._last_mono, self._last_wall = float(mono), float(wall)

    def _gates(self) -> None:
        self._window()
        try:
            source = self._source_check(dict(self.authority))
        except Exception:
            _fail("source_ci_failed")
        if (type(source) is not dict or set(source) != {"source_sha", "ci_run_id", "head_sha", "checks_passed"}
                or type(source.get("source_sha")) is not str or type(source.get("head_sha")) is not str
                or type(source.get("ci_run_id")) is not int or isinstance(source.get("ci_run_id"), bool)
                or type(source.get("checks_passed")) is not bool or source != {
                "source_sha": self.authority["source_sha"], "ci_run_id": self.authority["ci_run_id"],
                "head_sha": self.authority["source_sha"], "checks_passed": True}):
            _fail("source_ci_failed")
        self._window()
        try:
            protections = self._protection_check(dict(self.authority))
        except Exception:
            _fail("protection_failed")
        if (type(protections) is not dict or set(protections) != {
                "owner_id", "repository_id", "dev_environment_protected"}
                or type(protections.get("owner_id")) is not int
                or isinstance(protections.get("owner_id"), bool)
                or type(protections.get("repository_id")) is not int
                or isinstance(protections.get("repository_id"), bool)
                or type(protections.get("dev_environment_protected")) is not bool
                or protections != {
                "owner_id": self.authority.get("github_owner_id"),
                "repository_id": self.authority.get("github_repository_id"),
                "dev_environment_protected": True}):
            _fail("protection_failed")
        self._window()

    def _read_state(self, phase: str, *, pending: bool = False) -> dict[str, Any]:
        self._window()
        try:
            value = self._current_state(phase, dict(self.binding))
        except Exception:
            _fail("current_state_unverified")
        self._window()
        return _strict_state(value, phase=phase, binding=self.authority, prior_sha=self.prior_sha,
            target_sha=self.target_sha, zip_sha=self.zip_sha, leading_keys=self.leading_keys,
            issuer=self.issuer if phase == "accepted" else self.prior["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"],
            pending=pending)

    def _locked_state(self, journal: Any) -> Any:
        try:
            state = journal.load()
        except Exception:
            _fail("journal_invalid")
        if state is None:
            return None
        if (type(state) is not dict or set(state) != {"binding", "phase", "receipt"}
                or state.get("binding") != self.binding):
            _fail("journal_invalid")
        return state

    def _expected_artifact_receipt(self) -> dict[str, Any]:
        checksum = base64.b64encode(bytes.fromhex(self.zip_sha)).decode("ascii")
        return {
            "status": "verified", "bucket": self.authority["artifact_bucket"],
            "key": f"runtime/{self.zip_sha}.zip", "sha256": self.zip_sha,
            "size_bytes": len(self.archive), "expected_bucket_owner": self.authority["account_id"],
            "server_side_encryption": "AES256", "if_none_match": "*",
            "put_http_status": 200, "head_http_status": 200,
            "head_checksum_sha256": checksum, "head_content_length": len(self.archive),
            "head_server_side_encryption": "AES256",
        }

    def preflight(self) -> dict[str, Any]:
        try:
            with self._artifact_journal.locked(), self._update_journal.locked():
                if self._locked_state(self._artifact_journal) is not None or self._locked_state(self._update_journal) is not None:
                    _fail("journal_invalid")
                self._gates()
                self._read_state("preflight")
                self._window()
                self._artifact_journal.save({"binding": self.binding, "phase": "ready", "receipt": None})
                self._window()
                self._update_journal.save({"binding": self.binding, "phase": "ready", "receipt": None})
                if (self._locked_state(self._artifact_journal) != {
                        "binding": self.binding, "phase": "ready", "receipt": None}
                        or self._locked_state(self._update_journal) != {
                            "binding": self.binding, "phase": "ready", "receipt": None}):
                    _fail("journal_invalid")
                return {"ok": True, "phase": "ready"}
        except OwnerEnrolledDeliveryError:
            raise
        except Exception:
            _fail("journal_invalid")

    def publish(self) -> dict[str, Any]:
        try:
            return self._publish()
        except OwnerEnrolledDeliveryError:
            raise
        except Exception:
            _fail("artifact_write_unknown")

    def _publish(self) -> dict[str, Any]:
        with self._artifact_journal.locked():
            state = self._locked_state(self._artifact_journal)
            if state is None or state["phase"] != "ready" or state["receipt"] is not None:
                _fail("journal_invalid")
            self._gates()
            self._read_state("pre_publish")
            self._window()
            state["phase"] = "intent"
            self._artifact_journal.save(state)
            # Intent is durable before exactly one injected publication attempt.
            self._gates()
            self._window()
            self._read_state("pre_publish")
            try:
                result = self._publish_once(dict(self.binding), self.archive)
            except Exception:
                _fail("artifact_write_unknown")
            expected = self._expected_artifact_receipt()
            if type(result) is not dict or set(result) != set(expected) or result != expected:
                _fail("artifact_receipt_invalid")
            self._window()
            state["phase"], state["receipt"] = "published", expected
            self._artifact_journal.save(state)
            return {"ok": True, "phase": "published", "artifact_sha256": self.zip_sha}

    def update(self) -> dict[str, Any]:
        try:
            return self._update()
        except OwnerEnrolledDeliveryError:
            raise
        except Exception:
            _fail("update_write_unknown")

    def _update(self) -> dict[str, Any]:
        with self._artifact_journal.locked(), self._update_journal.locked():
            state = self._locked_state(self._update_journal)
            artifact = self._locked_state(self._artifact_journal)
            if (state is None or state["phase"] != "ready" or artifact is None
                    or artifact.get("phase") != "published"
                    or artifact.get("receipt") != self._expected_artifact_receipt()):
                _fail("journal_invalid")
            self._gates()
            self._read_state("pre_update")
            self._window()
            state["phase"] = "intent"
            self._update_journal.save(state)
            self._gates()
            self._window()
            self._read_state("pre_update")
            try:
                result = self._update_once(self.authority["stack_id"], json.loads(_canonical(self.target)),
                                           self.binding["client_request_token"], self.authority["service_role_arn"])
            except Exception:
                _fail("update_write_unknown")
            expected = {"status": "acknowledged", "http_status": 200,
                        "stack_id": self.authority["stack_id"],
                        "client_request_token": self.binding["client_request_token"],
                        "target_template_sha256": self.target_sha}
            if type(result) is not dict or set(result) != set(expected) or result != expected:
                _fail("update_receipt_invalid")
            self._window()
            state["phase"], state["receipt"] = "acknowledged", expected
            self._update_journal.save(state)
            return {"ok": True, "phase": "acknowledged"}

    def readback(self) -> dict[str, Any]:
        try:
            return self._readback()
        except OwnerEnrolledDeliveryError:
            raise
        except Exception:
            _fail("current_state_unverified")

    def _readback(self) -> dict[str, Any]:
        with self._artifact_journal.locked(), self._update_journal.locked():
            state = self._locked_state(self._update_journal)
            artifact = self._locked_state(self._artifact_journal)
            if state is None or state["phase"] not in {"intent", "acknowledged", "accepted"}:
                _fail("journal_invalid")
            if artifact is None or artifact.get("phase") != "published" or artifact.get(
                    "receipt") != self._expected_artifact_receipt():
                _fail("journal_invalid")
            if state["phase"] == "accepted":
                receipt = state.get("receipt")
                if (type(receipt) is not dict or set(receipt) != {
                        "target_template_sha256", "artifact_sha256", "completion_event_token",
                        "owner_context_sha256", "runtime_evidence_sha256"}
                        or receipt["target_template_sha256"] != self.target_sha
                        or receipt["artifact_sha256"] != self.zip_sha
                        or receipt["completion_event_token"] != self.binding["client_request_token"]
                        or not _valid_sha(receipt["owner_context_sha256"])
                        or receipt["owner_context_sha256"] == self.authority["owner_context_sha256"]
                        or not _valid_sha(receipt["runtime_evidence_sha256"])):
                    _fail("journal_invalid")
            self._gates()
            # A pending stack is read-only and never causes a second UpdateStack.
            try:
                raw = self._current_state("accepted", dict(self.binding))
            except Exception:
                _fail("current_state_unverified")
            self._window()
            if type(raw) is dict and raw.get("stack_status") in {"UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}:
                # Validate the complete closed state while tolerating only the two pending statuses.
                _strict_state(raw, phase="accepted", binding=self.authority, prior_sha=self.prior_sha,
                    target_sha=self.target_sha, zip_sha=self.zip_sha, leading_keys=self.leading_keys,
                    issuer=self.issuer, pending=True)
                return {"ok": True, "phase": "pending"}
            _strict_state(raw, phase="accepted", binding=self.authority, prior_sha=self.prior_sha,
                target_sha=self.target_sha, zip_sha=self.zip_sha, leading_keys=self.leading_keys, issuer=self.issuer)
            if state["phase"] == "accepted" and any(
                    state["receipt"][key] != raw[key]
                    for key in ("owner_context_sha256", "runtime_evidence_sha256")):
                _fail("current_state_unverified")
            self._window()
            if state["phase"] != "accepted":
                state["phase"] = "accepted"
                state["receipt"] = {"target_template_sha256": self.target_sha,
                                    "artifact_sha256": self.zip_sha,
                                    "completion_event_token": self.binding["client_request_token"],
                                    "owner_context_sha256": raw["owner_context_sha256"],
                                    "runtime_evidence_sha256": raw["runtime_evidence_sha256"]}
                self._update_journal.save(state)
            return {"ok": True, "phase": "accepted", "api_disabled": True,
                    "lambda_reserved_concurrency": 0, "resource_count": 19,
                    "runtime_evidence_sha256": raw["runtime_evidence_sha256"]}


__all__ = ["OwnerEnrolledDelivery", "OwnerEnrolledDeliveryError"]
