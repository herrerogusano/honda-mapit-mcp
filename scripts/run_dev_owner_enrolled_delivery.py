"""One-process, one-shot closed delivery for the opted-in owner DEV runtime.

This runner composes already reviewed parsers, the enrolled archive builder,
the fixed ARM readiness probe, the registered explicit-credential SDK bundle,
and the strict delivery/readback cores. It is not a resumable operator: any
interruption after a durable intent leaves the private run root consumed for
manual review. It never opens the API or handles MAPIT session credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import uuid
from collections.abc import Mapping
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT, ROOT / "src"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from scripts.build_aws_dev_enrolled_archive import build_dev_enrolled_archive
from scripts.dev_mapit_runtime_evidence import (
    _load_bundle as _load_runtime_bundle,
    _validate_bundle as _validate_runtime_bundle,
    runtime_evidence_digest,
)
from scripts.dev_owner_enrolled_delivery import (
    OwnerEnrolledClosedDelivery,
    OwnerEnrolledDeliveryError,
    _canonical,
    _summary_dict,
    _template_sha,
)
from scripts.dev_owner_enrolled_delivery_sdk import (
    OwnerEnrolledDeliverySdk,
    OwnerEnrolledDeliverySdkError,
    build_explicit_delivery_clients,
)
from scripts.dev_owner_enrolled_inputs import build_owner_manifest
from scripts.dev_owner_enrolled_runtime import build_owner_enrolled_dev_runtime_target
from scripts.dev_owner_enrolled_runtime_readback import (
    _json_document,
    make_owner_enrolled_current_state,
)
from scripts.probe_aws_dev_enrolled_arm import run_probe as run_enrolled_arm_probe
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_owner_oauth_bootstrap import validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError,
    validate_private_location,
    validate_source_and_ci,
)
from scripts.run_dev_mapit_binding_key_setup import _load_accepted_bootstrap
from scripts.run_dev_owner_invitation import _parser_only_clients
from scripts.dev_owner_enrolled_private_inputs import (
    OwnerEnrolledPrivateInputs,
    PrivateInputsError,
    load_owner_enrolled_private_inputs,
)
from scripts.dev_owner_enrolled_runtime_readback import _load_accepted_publication
from scripts.prepare_dev_multiuser_private import _create_private_directory

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_UUID32 = re.compile(r"[0-9a-f]{32}\Z")
_STACK_NAME = "honda-mapit-mcp-dev-retained"
_SERVICE_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
_ARTIFACT_MAX_BYTES = 50 * 1024 * 1024
_AUTH_MAX_BYTES = 32 * 1024
_MAX_POLLS = 60
_POLL_INTERVAL_SECONDS = 2.0
_POLL_CATEGORIES = frozenset({
    "source_ci_failed", "github_protection_failed", "private_location_invalid",
    "private_acl_invalid", "private_acl_unverified", "client_setup_failed",
    "caller_unverified", "prior_template_unverified", "private_inputs_unverified",
    "arm_readiness_failed", "archive_build_failed", "authority_write_failed",
    "journal_setup_failed", "current_state_unverified", "artifact_write_unknown",
    "update_write_unknown", "update_not_accepted", "window_closed", "delivery_failed",
    "binding_invalid", "accepted_evidence_invalid", "template_invalid", "artifact_invalid",
    "protection_failed", "journal_invalid", "artifact_receipt_invalid",
    "update_receipt_invalid", "step_invalid", "call_budget_exhausted", "identity_unverified",
    "closed_state_unverified", "artifact_readback_unverified",
})
_PRIVATE_INPUT_FIELDS = frozenset({
    "owner_release_receipt", "owner_oauth_authorization_path", "owner_oauth_binding_path",
    "owner_oauth_state_dir", "mapit_bootstrap_authority_path", "mapit_bootstrap_state_dir",
    "mapit_publication_state_dir", "mapit_evidence_path", "synthetic_binding_path",
    "synthetic_authorization_path", "synthetic_state_dir", "invitation_authorization_path",
    "invitation_state_dir", "public_config_path",
})


class OwnerEnrolledDeliveryRunnerError(ValueError):
    def __init__(self, category: str):
        safe = category if type(category) is str and category in _POLL_CATEGORIES else "delivery_failed"
        self.category = safe
        super().__init__(safe)


class _DeliveryIntentJournal:
    """Adapt the core's exact three-field intent state to FileJournal's envelope.

    FileJournal deliberately accepts only schema-versioned documents. The
    coordinator owns ``{binding, phase, receipt}``; the adapter stores that
    payload under one fixed schema envelope without changing either contract.
    """

    _CORE_FIELDS = frozenset({"binding", "phase", "receipt"})
    _PHASES = frozenset({"ready", "intent", "published", "acknowledged", "accepted"})

    def __init__(self, state_dir: Path):
        self._journal = FileJournal(state_dir)

    def locked(self):
        return self._journal.locked()

    def load(self):
        stored = self._journal.load()
        if stored is None:
            return None
        if (type(stored) is not dict or set(stored) != {"schema", "delivery_state"}
                or type(stored.get("schema")) is not int or stored["schema"] != 1):
            raise ValueError("delivery_journal_invalid")
        state = stored.get("delivery_state")
        if (type(state) is not dict or set(state) != self._CORE_FIELDS
                or type(state.get("binding")) is not dict
                or type(state.get("phase")) is not str or state["phase"] not in self._PHASES):
            raise ValueError("delivery_journal_invalid")
        return state

    def save(self, state):
        if (type(state) is not dict or set(state) != self._CORE_FIELDS
                or type(state.get("binding")) is not dict
                or type(state.get("phase")) is not str or state["phase"] not in self._PHASES):
            raise ValueError("delivery_journal_invalid")
        self._journal.save({"schema": 1, "delivery_state": state})


def _fail(category: str) -> None:
    raise OwnerEnrolledDeliveryRunnerError(category)


def _safe_failure(exc: BaseException) -> str:
    category = getattr(exc, "category", None)
    return category if type(category) is str and category in _POLL_CATEGORIES else "delivery_failed"


def _sdk_ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


def _unpaginated_response(value: Any) -> bool:
    return (isinstance(value, Mapping)
            and not any(key in value for key in ("NextToken", "NextMarker", "Marker", "IsTruncated")))


def _write_exclusive(path: Path, payload: bytes, *, maximum: int, acl_checker=None) -> None:
    target = validate_private_location(path.parent, acl_checker=acl_checker) / path.name
    if (type(payload) is not bytes or not 0 < len(payload) <= maximum
            or target.exists() or target.is_symlink()):
        raise ValueError
    # Keep partial files on failure: the unique root is consumed and cannot be
    # retried or overwritten.
    with target.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    validate_private_location(target, acl_checker=acl_checker)
    if target.read_bytes() != payload:
        raise ValueError


def _require_disjoint_root(root: Path, historical_paths) -> Path:
    """Reject both containment directions for every historical private input."""
    resolved_root = Path(root).resolve(strict=False)
    for value in historical_paths:
        historical = Path(value).resolve(strict=False)
        if (resolved_root == historical or resolved_root in historical.parents
                or historical in resolved_root.parents):
            _fail("private_inputs_unverified")
    return resolved_root


def _source_and_protection_checks(source_sha: str, ci_run_id: int, *,
                                  source_validator, protection_reader,
                                  owner_id: int | None = None, repository_id: int | None = None):
    if type(source_sha) is not str or _SHA40.fullmatch(source_sha) is None or source_sha == "0" * 40:
        _fail("source_ci_failed")
    if type(ci_run_id) is not int or isinstance(ci_run_id, bool) or ci_run_id <= 0:
        _fail("source_ci_failed")
    hint = {"source_sha": source_sha, "ci_run_id": ci_run_id}
    try:
        source_validator(hint)
    except Exception:
        _fail("source_ci_failed")
    try:
        if owner_id is None:
            actual_owner, actual_repo = protection_reader()
        else:
            actual_owner, actual_repo = protection_reader(
                expected_owner_id=owner_id, expected_repository_id=repository_id)
    except Exception:
        _fail("github_protection_failed")
    if (type(actual_owner) is not int or isinstance(actual_owner, bool) or actual_owner <= 0
            or type(actual_repo) is not int or isinstance(actual_repo, bool) or actual_repo <= 0
            or owner_id is not None and (actual_owner != owner_id or actual_repo != repository_id)):
        _fail("github_protection_failed")
    return actual_owner, actual_repo


def _prepare_bootstrap_lineage(private_paths: Mapping[str, Any], *, acl_checker=None):
    try:
        clients = _parser_only_clients()
        authority, _source, _github, state, plan, receipt = _load_accepted_bootstrap(
            Path(private_paths["mapit_bootstrap_authority_path"]),
            Path(private_paths["mapit_bootstrap_state_dir"]), clients,
            acl_checker=acl_checker)
        bundle, _raw = _load_runtime_bundle(Path(private_paths["mapit_evidence_path"]),
            acl_checker=acl_checker)
        runtime_binding = _validate_runtime_bundle(bundle, authority, plan.template)
        if (type(runtime_binding) is not dict
                or runtime_binding.get("account_id") != authority.account_id
                or runtime_binding.get("operator_user_arn") != authority.expected_caller_arn
                or runtime_evidence_digest(bundle) != authority.runtime_evidence_sha256):
            raise ValueError
        return authority, state, plan, receipt, runtime_binding
    except Exception:
        _fail("private_inputs_unverified")


def _read_prior_template(bundle, runtime_binding: Mapping[str, Any], *, clock, monotonic):
    clients = bundle.clients
    started = monotonic()
    wall_started = clock()
    if (type(started) not in (int, float) or isinstance(started, bool) or not math.isfinite(started)
            or type(wall_started) not in (int, float) or isinstance(wall_started, bool)
            or not math.isfinite(wall_started)):
        _fail("window_closed")
    try:
        identity = clients["sts"].get_caller_identity()
        if (not _sdk_ok(identity) or identity.get("Account") != runtime_binding["account_id"]
                or identity.get("Arn") != runtime_binding["operator_user_arn"]):
            _fail("caller_unverified")
        response = clients["cloudformation"].get_template(
            StackName=runtime_binding["app_stack_arn"], TemplateStage="Original")
        now_mono, now_wall = monotonic(), clock()
        if (not _sdk_ok(response) or type(now_mono) not in (int, float) or isinstance(now_mono, bool)
                or not math.isfinite(now_mono) or now_mono < started or now_mono - started >= 14
                or type(now_wall) not in (int, float) or isinstance(now_wall, bool)
                or not math.isfinite(now_wall) or now_wall < wall_started or now_wall - wall_started >= 14):
            _fail("prior_template_unverified")
        template = _json_document(response.get("TemplateBody"))
        if (template is None or hashlib.sha256(_canonical(template)).hexdigest()
                != runtime_binding.get("template_sha256")):
            _fail("prior_template_unverified")
        return template
    except OwnerEnrolledDeliveryRunnerError:
        raise
    except Exception:
        _fail("prior_template_unverified")


def _assemble_delivery_metadata(*, private_inputs, prior_template, source_sha,
                                ci_run_id, clock, run_uuid):
    """Use the accepted shared assembler; do not duplicate receipt policy."""
    from scripts.dev_owner_enrolled_preparation import assemble_delivery_metadata

    now = clock()
    if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or now <= 0 or type(run_uuid) is not str or _UUID32.fullmatch(run_uuid) is None):
        _fail("window_closed")
    start = int(now)
    try:
        assembled = assemble_delivery_metadata(
            manifest_inputs=private_inputs.manifest_inputs,
            prior_template=prior_template,
            runtime_binding=private_inputs.runtime_binding,
            run_id=run_uuid,
            ci_run_id=ci_run_id,
            start=start,
            end=start + 600,
            execution_start=start,
            execution_end=start + 300,
        )
        return assembled
    except Exception:
        _fail("private_inputs_unverified")


def _poll_update_complete(clients, authority, *, clock, monotonic, sleep,
                          max_polls=_MAX_POLLS, interval=_POLL_INTERVAL_SECONDS):
    """Read-only, closed-control polling; never follows up with UpdateStack."""
    if (type(max_polls) is not int or isinstance(max_polls, bool) or not 1 <= max_polls <= _MAX_POLLS
            or type(interval) not in (int, float) or isinstance(interval, bool)
            or not math.isfinite(interval) or interval != _POLL_INTERVAL_SECONDS):
        _fail("current_state_unverified")
    calls = 0
    start_mono = monotonic()
    previous_mono = start_mono
    previous_wall = clock()
    if (type(start_mono) not in (int, float) or isinstance(start_mono, bool) or not math.isfinite(start_mono)
            or type(previous_wall) not in (int, float) or isinstance(previous_wall, bool)
            or not math.isfinite(previous_wall)):
        _fail("window_closed")

    def read(service, method, **kwargs):
        nonlocal calls, previous_wall, previous_mono
        wall, mono = clock(), monotonic()
        if (type(wall) not in (int, float) or isinstance(wall, bool) or not math.isfinite(wall)
                or type(mono) not in (int, float) or isinstance(mono, bool) or not math.isfinite(mono)
                or wall < previous_wall or mono < previous_mono or mono - start_mono >= 180
                or not authority["authorized_from_epoch"] <= wall < authority["authorized_until_epoch"]
                or not authority["execution_start_epoch"] <= wall < authority["execution_end_epoch"]):
            _fail("window_closed")
        previous_wall, previous_mono = wall, mono
        calls += 1
        if calls > max_polls * 4:
            _fail("current_state_unverified")
        try:
            response = getattr(clients[service], method)(**kwargs)
        except Exception:
            _fail("current_state_unverified")
        wall, mono = clock(), monotonic()
        if (not _sdk_ok(response) or not _unpaginated_response(response)
                or type(wall) not in (int, float) or isinstance(wall, bool)
                or not math.isfinite(wall) or type(mono) not in (int, float) or isinstance(mono, bool)
                or not math.isfinite(mono) or wall < previous_wall or mono < start_mono
                or mono < previous_mono or mono - start_mono >= 180
                or not authority["authorized_from_epoch"] <= wall < authority["authorized_until_epoch"]
                or not authority["execution_start_epoch"] <= wall < authority["execution_end_epoch"]):
            _fail("current_state_unverified")
        if (any(response.get(marker) not in (None, "")
                for marker in ("NextToken", "Marker", "NextMarker"))
                or ("IsTruncated" in response and response["IsTruncated"] is not False)):
            _fail("current_state_unverified")
        previous_wall, previous_mono = wall, mono
        return response

    for attempt in range(max_polls):
        identity = read("sts", "get_caller_identity")
        if identity.get("Account") != authority["account_id"] or identity.get("Arn") != authority["operator_arn"]:
            _fail("caller_unverified")
        api_id = authority["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
        api = read("apigatewayv2", "get_api", ApiId=api_id)
        reserve = read("lambda", "get_function_concurrency", FunctionName="honda-mapit-mcp-dev-retained-handler")
        if (api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
                or type(reserve.get("ReservedConcurrentExecutions")) is not int
                or reserve["ReservedConcurrentExecutions"] != 0):
            _fail("current_state_unverified")
        stack_reply = read("cloudformation", "describe_stacks", StackName=authority["stack_id"])
        stacks = stack_reply.get("Stacks")
        if (type(stacks) is not list or len(stacks) != 1
                or stacks[0].get("StackId") != authority["stack_id"]
                or stacks[0].get("StackName") != _STACK_NAME
                or stacks[0].get("RoleARN") != authority["service_role_arn"]):
            _fail("current_state_unverified")
        status = stacks[0].get("StackStatus")
        if status == "UPDATE_COMPLETE":
            return {"status": "UPDATE_COMPLETE", "polls": attempt + 1, "calls": calls}
        if status not in {"UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}:
            _fail("update_not_accepted")
        if attempt + 1 < max_polls:
            sleep(interval)
    _fail("update_not_accepted")


def _write_private_inputs(root: Path, manifest_raw: bytes, invitation_jwks: bytes,
                          mapit_jwks: bytes, *, acl_checker=None) -> tuple[Path, Path, Path]:
    inputs = root / "inputs"
    _create_private_directory(inputs, acl_checker=acl_checker)
    manifest_path, invitation_path, mapit_path = (
        inputs / "manifest.json", inputs / "invitation-jwks.json", inputs / "mapit-jwks.json")
    _write_exclusive(manifest_path, manifest_raw, maximum=16 * 1024, acl_checker=acl_checker)
    _write_exclusive(invitation_path, invitation_jwks, maximum=32 * 1024, acl_checker=acl_checker)
    _write_exclusive(mapit_path, mapit_jwks, maximum=32 * 1024, acl_checker=acl_checker)
    return manifest_path, invitation_path, mapit_path


def run_owner_enrolled_delivery_once(
    *, private_inputs: Mapping[str, Any], wheel_dir: Path, private_parent: Path,
    source_sha: str, ci_run_id: int,
    acl_checker: Callable[[Path], bool] | None = None,
    source_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci,
    protection_reader: Callable[..., tuple[int, int]] = validate_github_protections,
    bundle_factory: Callable[[], Any] = build_explicit_delivery_clients,
    archive_builder: Callable[..., Any] = build_dev_enrolled_archive,
    arm_probe: Callable[[Path], Mapping[str, Any]] = run_enrolled_arm_probe,
    private_input_loader: Callable[..., OwnerEnrolledPrivateInputs] = load_owner_enrolled_private_inputs,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    run_id_factory: Callable[[], Any] = uuid.uuid4,
) -> dict[str, Any]:
    """Execute one fresh owner-enrolled delivery without resuming any prior run.

    Test seams replace only infrastructure edges. The production defaults use
    exact source/protection checks, pinned packaging/readiness, one registered
    SDK bundle, and the full strict current-state verifier.
    """
    bundle = None
    root = None
    try:
        if (not isinstance(private_inputs, Mapping) or set(private_inputs) != _PRIVATE_INPUT_FIELDS
                or any(not isinstance(value, (str, Path)) for value in private_inputs.values())
                or not callable(source_validator)
                or not callable(protection_reader) or not callable(bundle_factory)
                or not callable(archive_builder) or not callable(arm_probe)
                or not callable(private_input_loader) or not callable(clock)
                or not callable(monotonic) or not callable(sleep)):
            _fail("private_inputs_unverified")
        github_owner_id, github_repository_id = _source_and_protection_checks(
            source_sha, ci_run_id, source_validator=source_validator,
            protection_reader=protection_reader)
        parent = validate_private_location(Path(private_parent), acl_checker=acl_checker)
        if not parent.is_dir():
            _fail("private_location_invalid")

        # The one explicit credential snapshot is shared by every client. It is
        # created only after source and protected-environment gates succeed.
        bundle = bundle_factory()
        clients = bundle.clients
        from scripts.dev_owner_enrolled_delivery_sdk import _is_registered_client_bundle
        if not _is_registered_client_bundle(bundle):
            _fail("client_setup_failed")

        bootstrap_authority, _bootstrap_state, bootstrap_plan, _bootstrap_receipt, runtime_binding = (
            _prepare_bootstrap_lineage(private_inputs, acl_checker=acl_checker))
        if (bootstrap_authority.expected_caller_arn == ""
                or bootstrap_authority.account_id != runtime_binding.get("account_id")):
            _fail("private_inputs_unverified")
        prior_template = _read_prior_template(bundle, runtime_binding, clock=clock, monotonic=monotonic)
        loaded = private_input_loader(**dict(private_inputs), prior_template=prior_template,
            source_sha=source_sha, acl_checker=acl_checker)
        if (type(loaded) is not OwnerEnrolledPrivateInputs or loaded.assert_unchanged() is not True
                or loaded.manifest_inputs.get("source_sha") != source_sha
                or loaded.manifest_inputs["context"].github_owner_id != github_owner_id
                or loaded.manifest_inputs["context"].github_repository_id != github_repository_id
                or loaded.manifest_inputs["bootstrap_authority"]._binding_sha256 != bootstrap_authority._binding_sha256):
            _fail("private_inputs_unverified")
        context = loaded.manifest_inputs["context"]
        identity = clients["sts"].get_caller_identity()
        if (not _sdk_ok(identity) or identity.get("Account") != context.account
                or identity.get("Arn") != context.operator):
            _fail("caller_unverified")

        # Readiness is source/wheel evidence, not live MAPIT acceptance. It
        # exercises a synthetic token against the pinned source and wheels;
        # the actual candidate is separately bound by exact ZIP contents.
        readiness = arm_probe(Path(wheel_dir))
        from scripts.probe_aws_dev_enrolled_arm import CHECKS as ARM_CHECKS
        if (not isinstance(readiness, Mapping) or set(readiness) != {"success", "category", "checks", "wheel_count"}
                or readiness.get("success") is not True
                or readiness.get("category") != "enrolled_arm_readiness_passed"
                or readiness.get("wheel_count") != 28
                or type(readiness.get("checks")) is not dict
                or set(readiness["checks"]) != set(ARM_CHECKS)
                or any(type(flag) is not bool or flag is not True for flag in readiness["checks"].values())):
            _fail("arm_readiness_failed")

        if loaded.assert_unchanged() is not True:
            _fail("private_inputs_unverified")
        manifest_raw = build_owner_manifest(**loaded.manifest_inputs)
        invitation_jwks = loaded.manifest_inputs["invitation_jwks"]
        mapit_jwks = loaded.manifest_inputs["mapit_jwks"]

        run_id_object = run_id_factory()
        if type(run_id_object) is not uuid.UUID:
            _fail("private_inputs_unverified")
        run_uuid = run_id_object.hex
        root_name = f"owner-enrolled-{run_uuid[:12]}"
        root = parent / root_name
        if root.resolve(strict=False).parent != parent:
            _fail("private_location_invalid")
        # The fresh journal/artifact tree must not be placed inside, contain,
        # or alias any accepted historical input. Keep the check symmetric so
        # a caller cannot relocate an immutable receipt beneath this run root.
        historical_paths = []
        for value in private_inputs.values():
            if isinstance(value, (str, Path)):
                try:
                    historical_paths.append(Path(value).resolve(strict=False))
                except Exception:
                    _fail("private_inputs_unverified")
        _require_disjoint_root(root, historical_paths)
        if root.exists() or root.is_symlink():
            _fail("private_location_invalid")
        _create_private_directory(root, acl_checker=acl_checker)
        manifest_path, invitation_path, mapit_path = _write_private_inputs(
            root, manifest_raw, invitation_jwks, mapit_jwks, acl_checker=acl_checker)
        prior_template_bytes = _canonical(prior_template)
        archive_path = root / "runtime.zip"
        try:
            summary = archive_builder(Path(wheel_dir), manifest_path, invitation_path,
                mapit_path, archive_path, account_id=context.account)
            archive_path = validate_private_location(archive_path, acl_checker=acl_checker)
            archive_stat = archive_path.stat()
            if (not stat.S_ISREG(archive_stat.st_mode) or not 0 < archive_stat.st_size <= _ARTIFACT_MAX_BYTES):
                raise ValueError
            archive_bytes = archive_path.read_bytes()
            if len(archive_bytes) != archive_stat.st_size:
                raise ValueError
        except Exception:
            _fail("archive_build_failed")
        summary_payload = _summary_dict(summary)
        if type(summary_payload) is not dict:
            _fail("archive_build_failed")
        _write_exclusive(root / "inputs" / "archive-summary.json", _canonical(summary_payload),
            maximum=8 * 1024, acl_checker=acl_checker)
        if loaded.assert_unchanged() is not True:
            _fail("private_inputs_unverified")

        owner_id, repo_id = _source_and_protection_checks(
            source_sha, ci_run_id, source_validator=source_validator,
            protection_reader=protection_reader, owner_id=github_owner_id,
            repository_id=github_repository_id)
        if owner_id != context.github_owner_id or repo_id != context.github_repository_id:
            _fail("github_protection_failed")
        assembled = _assemble_delivery_metadata(private_inputs=loaded,
            prior_template=prior_template, source_sha=source_sha,
            ci_run_id=ci_run_id, clock=clock, run_uuid=run_uuid)
        accepted, authority = assembled.get("accepted"), assembled.get("authority")
        if (type(assembled) is not dict or set(assembled) != {"accepted", "authority", "manifest_raw"}
                or assembled["manifest_raw"] != manifest_raw
                or type(accepted) is not dict or type(authority) is not dict):
            _fail("private_inputs_unverified")
        if (hashlib.sha256(prior_template_bytes).hexdigest()
                != authority.get("prior_template_sha256")):
            _fail("private_inputs_unverified")
        _write_exclusive(root / "inputs" / "prior-template.json", prior_template_bytes,
            maximum=64 * 1024, acl_checker=acl_checker)

        # Fixed one-run layout prevents relocating the accepted authority under
        # a fresh empty journal. Each intent has its own exclusive FileJournal.
        artifact_dir, update_dir = root / "artifact-intent", root / "update-intent"
        _create_private_directory(artifact_dir, acl_checker=acl_checker)
        _create_private_directory(update_dir, acl_checker=acl_checker)
        _write_exclusive(root / "authorization.json", _canonical(authority),
            maximum=_AUTH_MAX_BYTES, acl_checker=acl_checker)
        artifact_journal = _DeliveryIntentJournal(artifact_dir)
        update_journal = _DeliveryIntentJournal(update_dir)

        source_check = lambda auth: _source_check_result(auth, source_validator)
        protection_check = lambda auth: _protection_check_result(
            auth, protection_reader, github_owner_id, github_repository_id)
        current_state = make_owner_enrolled_current_state(
            client_bundle=bundle, authority=authority, accepted=accepted,
            prior_template=prior_template, manifest_raw=manifest_raw,
            invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
            archive_bytes=archive_bytes, archive_size=len(archive_bytes),
            owner_oauth_context=context,
            mapit_bootstrap_authority_path=Path(private_inputs["mapit_bootstrap_authority_path"]),
            mapit_bootstrap_state_dir=Path(private_inputs["mapit_bootstrap_state_dir"]),
            mapit_publication_state_dir=Path(private_inputs["mapit_publication_state_dir"]),
            mapit_evidence_path=Path(private_inputs["mapit_evidence_path"]),
            synthetic_binding_path=Path(private_inputs["synthetic_binding_path"]),
            synthetic_authorization_path=Path(private_inputs["synthetic_authorization_path"]),
            synthetic_state_dir=Path(private_inputs["synthetic_state_dir"]),
            acl_checker=acl_checker, clock=clock, monotonic=monotonic)
        target = build_owner_enrolled_dev_runtime_target(
            prior_template=prior_template, mapit_bootstrap_template=loaded.bootstrap_template,
            manifest_raw=manifest_raw, invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
            manifest_sha256=authority["manifest_sha256"], account_id=authority["account_id"],
            source_sha=authority["source_sha"], zip_sha256=hashlib.sha256(archive_bytes).hexdigest(),
            execution_start_epoch=authority["execution_start_epoch"],
            execution_end_epoch=authority["execution_end_epoch"])
        sdk = OwnerEnrolledDeliverySdk(client_bundle=bundle, authority=authority,
            target_template_sha256=_template_sha(target), clock=clock, monotonic=monotonic)
        capsule_path = root / "observation-capsule.json"

        def accepted_current_state(phase, binding):
            value = _verified_current_state(phase, binding, loaded, current_state)
            if phase == "accepted":
                capsule = current_state.export_accepted_observation_capsule()
                payload = _canonical(capsule)
                _write_exclusive(capsule_path, payload, maximum=32 * 1024,
                    acl_checker=acl_checker)
                # The exclusive writer includes an exact readback before this
                # callback returns, so the coordinator cannot persist accepted
                # state before the restart capsule is durable.
            return value

        coordinator = OwnerEnrolledClosedDelivery(
            authority=authority, accepted=accepted, prior_template=prior_template,
            mapit_bootstrap_template=loaded.bootstrap_template, manifest_raw=manifest_raw,
            invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
            archive_bytes=archive_bytes, archive_summary=summary,
            artifact_journal=artifact_journal, update_journal=update_journal,
            source_check=source_check, protection_check=protection_check,
            current_state=accepted_current_state,
            publish_once=sdk.publish_once, update_once=sdk.update_once,
            clock=clock, monotonic=monotonic)

        coordinator.preflight()
        if loaded.assert_unchanged() is not True:
            _fail("private_inputs_unverified")
        coordinator.publish()
        if loaded.assert_unchanged() is not True:
            _fail("private_inputs_unverified")
        coordinator.update()
        poll = _poll_update_complete(clients, authority, clock=clock, monotonic=monotonic,
            sleep=sleep)
        result = coordinator.readback()
        if loaded.assert_unchanged() is not True:
            _fail("private_inputs_unverified")
        if (result.get("ok") is not True or result.get("phase") != "accepted"
                or result.get("api_disabled") is not True
                or result.get("lambda_reserved_concurrency") != 0
                or result.get("resource_count") != 19):
            _fail("current_state_unverified")
        return {"ok": True, "category": "owner_enrolled_delivery_accepted",
                "phase": "accepted", "polls": poll["polls"], "private_root": str(root)}
    except OwnerEnrolledDeliveryRunnerError as exc:
        return {"ok": False, "category": exc.category, "phase": "stopped",
                "private_root": str(root) if root is not None else None}
    except (OwnerEnrolledDeliveryError, OwnerEnrolledDeliverySdkError, PrivateInputsError) as exc:
        return {"ok": False, "category": _safe_failure(exc), "phase": "stopped",
                "private_root": str(root) if root is not None else None}
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in _POLL_CATEGORIES:
            category = "private_location_invalid"
        return {"ok": False, "category": category, "phase": "stopped",
                "private_root": str(root) if root is not None else None}
    except Exception:
        return {"ok": False, "category": "delivery_failed", "phase": "stopped",
                "private_root": str(root) if root is not None else None}


def _source_check_result(authority, source_validator):
    try:
        source_validator(authority)
        return {"source_sha": authority["source_sha"], "ci_run_id": authority["ci_run_id"],
                "head_sha": authority["source_sha"], "checks_passed": True}
    except Exception:
        _fail("source_ci_failed")


def _protection_check_result(authority, protection_reader, owner_id, repository_id):
    try:
        actual_owner, actual_repository = protection_reader(
            expected_owner_id=owner_id, expected_repository_id=repository_id)
    except Exception:
        _fail("github_protection_failed")
    if (type(actual_owner) is not int or isinstance(actual_owner, bool)
            or type(actual_repository) is not int or isinstance(actual_repository, bool)
            or actual_owner != owner_id or actual_repository != repository_id):
        _fail("github_protection_failed")
    return {"owner_id": owner_id, "repository_id": repository_id,
            "dev_environment_protected": True}


def _verified_current_state(phase, _binding, private_inputs, callback):
    if private_inputs.assert_unchanged() is not True:
        _fail("private_inputs_unverified")
    return callback(phase, _binding)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-parent", type=Path, required=True)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", type=int, required=True)
    for name in (
        "owner-release-receipt", "owner-oauth-authorization", "owner-oauth-binding",
        "owner-oauth-state-dir", "mapit-bootstrap-authority", "mapit-bootstrap-state-dir",
        "mapit-publication-state-dir", "mapit-evidence", "synthetic-binding",
        "synthetic-authorization", "synthetic-state-dir", "invitation-authorization",
        "invitation-state-dir", "public-config",
    ):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args(argv)
    private_inputs = {
        "owner_release_receipt": args.owner_release_receipt,
        "owner_oauth_authorization_path": args.owner_oauth_authorization,
        "owner_oauth_binding_path": args.owner_oauth_binding,
        "owner_oauth_state_dir": args.owner_oauth_state_dir,
        "mapit_bootstrap_authority_path": args.mapit_bootstrap_authority,
        "mapit_bootstrap_state_dir": args.mapit_bootstrap_state_dir,
        "mapit_publication_state_dir": args.mapit_publication_state_dir,
        "mapit_evidence_path": args.mapit_evidence,
        "synthetic_binding_path": args.synthetic_binding,
        "synthetic_authorization_path": args.synthetic_authorization,
        "synthetic_state_dir": args.synthetic_state_dir,
        "invitation_authorization_path": args.invitation_authorization,
        "invitation_state_dir": args.invitation_state_dir,
        "public_config_path": args.public_config,
    }
    result = run_owner_enrolled_delivery_once(private_inputs=private_inputs,
        wheel_dir=args.wheel_dir, private_parent=args.private_parent,
        source_sha=args.source_sha, ci_run_id=args.ci_run_id)
    # Deliberately omit paths, hashes, identities and exception text.
    print(json.dumps({key: result[key] for key in ("ok", "category", "phase", "polls") if key in result},
                     separators=(",", ":")))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
