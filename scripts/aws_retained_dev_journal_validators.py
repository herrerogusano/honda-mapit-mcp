"""Closed, phase-bound state validation for the retained-dev S3 journal.

This module is deliberately separate from the SDK-free S3 CAS transport.  The
transport still owns the outer envelope and conditional-write fence; this
module owns the small metadata-only state machine used by an operational
phase.  Callers cannot provide a permissive validator to the factory.
"""

from __future__ import annotations

import copy
import math
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable

from scripts.aws_retained_dev_journal import (
    MAX_REVISION,
    PHASES,
    RetainedDevS3Journal,
)
from scripts.build_aws_retained_dev_runtime import retained_dev_artifact_bucket

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK_ARN = re.compile(
    r"arn:aws:cloudformation:eu-west-1:(?P<account>[0-9]{12}):stack/"
    r"honda-mapit-mcp-dev-retained/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_MAX_WINDOW_SECONDS = 3600

_STATE_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "account_id",
        "source_sha",
        "run_id",
        "phase",
        "binding_sha256",
        "template_sha256",
        "authorized_from_epoch",
        "authorized_until_epoch",
        "version",
        "operation",
        "closed",
        "intent",
        "acknowledged",
        "readback",
        "last_observed_epoch",
    }
)
_PHASE_OPERATION = {
    "preflight": "preflight",
    "artifact": "artifact",
    "update": "update",
    "recovery": "recovery",
}


class JournalValidatorError(ValueError):
    """Stable, non-sensitive category for rejected bindings or states."""

    def __init__(self, category: str = "journal_state_invalid") -> None:
        self.category = category
        super().__init__(category)


def _finite_int(value: Any, *, minimum: int = 0) -> bool:
    # bool is an int subclass but is never a valid journal counter or epoch.
    # Python integers are exact and finite; avoiding a float conversion also
    # closes the OverflowError path for adversarially huge integers.
    return type(value) is int and value >= minimum


def _check_binding_values(
    account_id: Any,
    source_sha: Any,
    run_id: Any,
    phase: Any,
    binding_sha256: Any,
    template_sha256: Any,
    authorized_from_epoch: Any,
    authorized_until_epoch: Any,
) -> None:
    if (
        type(account_id) is not str
        or _ACCOUNT.fullmatch(account_id) is None
        or account_id == "000000000000"
        or type(source_sha) is not str
        or _SHA1.fullmatch(source_sha) is None
        or source_sha == "0" * 40
        or type(run_id) is not str
        or _UUID.fullmatch(run_id) is None
        or type(phase) is not str
        or phase not in PHASES
        or type(binding_sha256) is not str
        or _SHA256.fullmatch(binding_sha256) is None
        or binding_sha256 == "0" * 64
        or type(template_sha256) is not str
        or _SHA256.fullmatch(template_sha256) is None
        or template_sha256 == "0" * 64
        or not _finite_int(authorized_from_epoch, minimum=1)
        or not _finite_int(authorized_until_epoch, minimum=1)
        or authorized_until_epoch <= authorized_from_epoch
        or authorized_until_epoch - authorized_from_epoch > _MAX_WINDOW_SECONDS
    ):
        raise JournalValidatorError("journal_binding_invalid")


@dataclass(frozen=True, slots=True)
class RetainedDevJournalBinding:
    """Immutable identity and authority binding for one journal phase."""

    account_id: str
    source_sha: str
    run_id: str
    phase: str
    binding_sha256: str
    template_sha256: str
    authorized_from_epoch: int
    authorized_until_epoch: int

    def __post_init__(self) -> None:
        _check_binding_values(
            self.account_id,
            self.source_sha,
            self.run_id,
            self.phase,
            self.binding_sha256,
            self.template_sha256,
            self.authorized_from_epoch,
            self.authorized_until_epoch,
        )

    def __repr__(self) -> str:
        # Do not put account/source/template material in logs or test failures.
        return f"RetainedDevJournalBinding(phase={self.phase!r})"


def _binding_fields(binding: RetainedDevJournalBinding) -> dict[str, Any]:
    return {
        "account_id": binding.account_id,
        "source_sha": binding.source_sha,
        "run_id": binding.run_id,
        "phase": binding.phase,
        "binding_sha256": binding.binding_sha256,
        "template_sha256": binding.template_sha256,
        "authorized_from_epoch": binding.authorized_from_epoch,
        "authorized_until_epoch": binding.authorized_until_epoch,
    }


def make_phase_state(
    binding: RetainedDevJournalBinding,
    *,
    version: int,
    intent: str | None,
    acknowledged: bool,
    readback: bool,
    last_observed_epoch: int,
) -> dict[str, Any]:
    """Build the only state shape accepted by the validated adapter."""
    state = {
        "schema": 1,
        "kind": "retained-dev-phase-state",
        **_binding_fields(binding),
        "version": version,
        "operation": _PHASE_OPERATION[binding.phase],
        "closed": True,
        "intent": intent,
        "acknowledged": acknowledged,
        "readback": readback,
        "last_observed_epoch": last_observed_epoch,
    }
    if not validate_phase_state(state, binding):
        raise JournalValidatorError("journal_state_invalid")
    return state


def validate_phase_state(value: Any, binding: RetainedDevJournalBinding) -> bool:
    """Return true only for the closed metadata-only state schema."""
    try:
        if not isinstance(value, Mapping) or set(value) != _STATE_FIELDS:
            return False
        if type(value.get("schema")) is not int or value.get("schema") != 1 or type(value.get("kind")) is not str or value.get("kind") != "retained-dev-phase-state":
            return False
        for key, expected in _binding_fields(binding).items():
            if value.get(key) != expected:
                return False
        if type(value.get("version")) is not int or not 1 <= value["version"] <= MAX_REVISION:
            return False
        if value.get("operation") != _PHASE_OPERATION[binding.phase] or value.get("closed") is not True:
            return False
        intent = value.get("intent")
        if intent is not None and (type(intent) is not str or intent != _PHASE_OPERATION[binding.phase]):
            return False
        if type(value.get("acknowledged")) is not bool or type(value.get("readback")) is not bool:
            return False
        if intent is None and (value["acknowledged"] or value["readback"]):
            return False
        if value["readback"] and not value["acknowledged"]:
            return False
        observed = value.get("last_observed_epoch")
        if not _finite_int(observed, minimum=binding.authorized_from_epoch) or observed >= binding.authorized_until_epoch:
            return False
        # State is metadata only.  Values which look like payloads, IDs, or
        # arbitrary nested receipts cannot enter the envelope.
        return all(type(key) is str for key in value)
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def build_phase_state_validator(binding: RetainedDevJournalBinding) -> Callable[[Any], bool]:
    """Create the fixed validator used internally by the adapter."""
    if not isinstance(binding, RetainedDevJournalBinding):
        raise JournalValidatorError("journal_binding_invalid")

    def validator(value: Any) -> bool:
        return validate_phase_state(value, binding)

    return validator


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    # The core serializes a plain mapping.  The second copy also prevents a
    # caller retaining a mutable nested object (future schema additions).
    return copy.deepcopy(dict(value))


class ValidatedRetainedDevS3Journal:
    """Strict adapter; unlike the transport, it has no validator callback."""

    def __init__(self, core: RetainedDevS3Journal, binding: RetainedDevJournalBinding) -> None:
        if not isinstance(core, RetainedDevS3Journal) or not isinstance(binding, (RetainedDevJournalBinding, ArtifactJournalBinding, PreflightJournalBinding, UpdateJournalBinding, RecoveryJournalBinding, RecoveryUpdateJournalBinding)):
            raise JournalValidatorError("journal_inputs_invalid")
        self._core = core
        self.binding = binding
        self._validator = build_phase_state_validator(binding) if isinstance(binding, RetainedDevJournalBinding) else build_concrete_phase_state_validator(binding)
        self._loaded_state: dict[str, Any] | None = None
        self._loaded = False

    def __repr__(self) -> str:
        return f"ValidatedRetainedDevS3Journal(phase={self.binding.phase!r})"

    @contextmanager
    def locked(self) -> Iterator["ValidatedRetainedDevS3Journal"]:
        with self._core.locked():
            self._loaded = False
            self._loaded_state = None
            try:
                yield self
            finally:
                self._loaded = False
                self._loaded_state = None

    def _outer_revision(self) -> int:
        revision = getattr(self._core, "_revision", None)
        if type(revision) is not int or not 0 <= revision <= MAX_REVISION:
            raise JournalValidatorError("journal_revision_invalid")
        return revision

    def _counter_field(self) -> str:
        # The legacy prototype uses ``version`` for every phase; concrete
        # coordinators mirror their actual envelopes (preflight=version,
        # artifact/update/recovery=revision).
        if isinstance(self.binding, RetainedDevJournalBinding):
            return "version"
        return "version" if self.binding.phase == "preflight" else "revision"

    def load(self) -> dict[str, Any] | None:
        if not self._loaded:
            state = self._core.load()
            outer = self._outer_revision()
            if state is not None:
                if not self._validator(state) or state[self._counter_field()] != outer:
                    raise JournalValidatorError("journal_revision_invalid")
                self._loaded_state = _detached(state)
            else:
                if outer != 0:
                    raise JournalValidatorError("journal_revision_invalid")
                self._loaded_state = None
            self._loaded = True
        return None if self._loaded_state is None else _detached(self._loaded_state)

    def _check_transition(self, previous: Mapping[str, Any] | None, current: Mapping[str, Any], expected: int | None) -> None:
        counter = self._counter_field()
        if expected is None:
            if previous is not None or current[counter] != 1:
                raise JournalValidatorError("journal_revision_invalid")
        else:
            if previous is None or previous[counter] != expected or current[counter] != expected + 1:
                raise JournalValidatorError("journal_revision_invalid")
            if "intent" in previous and previous["intent"] is not None and current.get("intent") is None:
                raise JournalValidatorError("journal_state_transition_invalid")
            if previous.get("acknowledged") is True and current.get("acknowledged") is not True:
                raise JournalValidatorError("journal_state_transition_invalid")
            if previous.get("readback") is True and current.get("readback") is not True:
                raise JournalValidatorError("journal_state_transition_invalid")
            if isinstance(self.binding, (ArtifactJournalBinding, RecoveryJournalBinding)) and previous.get("status") == "verified" and current.get("status") != "verified":
                raise JournalValidatorError("journal_state_transition_invalid")
            if isinstance(self.binding, UpdateJournalBinding):
                for key in ("preflight", "update_acknowledged", "update_event_observed", "update_verified"):
                    if previous.get(key) is True and current.get(key) is not True:
                        raise JournalValidatorError("journal_state_transition_invalid")

    def compare_and_set(self, expected_revision: int | None, state: Mapping[str, Any]) -> bool:
        if not self._loaded:
            raise JournalValidatorError("journal_lock_invalid")
        if expected_revision is not None and type(expected_revision) is not int:
            raise JournalValidatorError("journal_revision_invalid")
        if expected_revision is not None and (expected_revision < 1 or expected_revision > MAX_REVISION):
            raise JournalValidatorError("journal_revision_invalid")
        if not isinstance(state, Mapping) or not self._validator(state):
            return False
        detached = _detached(state)
        self._check_transition(self._loaded_state, detached, expected_revision)
        result = self._core.compare_and_set(expected_revision, detached)
        if result:
            if self._outer_revision() != detached[self._counter_field()]:
                raise JournalValidatorError("journal_revision_invalid")
            self._loaded_state = _detached(detached)
            return True
        # A known 412 causes the core to read the winner.  Reconcile it before
        # returning so this adapter cannot manufacture a stale next revision.
        observed = self._core.load()
        outer = self._outer_revision()
        if observed is None or not self._validator(observed) or observed[self._counter_field()] != outer:
            raise JournalValidatorError("journal_revision_invalid")
        self._loaded_state = _detached(observed)
        return False


def create_validated_retained_dev_journal(
    client: Any,
    binding: RetainedDevJournalBinding,
    *,
    create_first: bool = False,
    wall_clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> ValidatedRetainedDevS3Journal:
    """Build the operational journal without accepting a custom validator."""
    if not isinstance(binding, RetainedDevJournalBinding):
        raise JournalValidatorError("journal_binding_invalid")
    if type(create_first) is not bool:
        raise JournalValidatorError("journal_inputs_invalid")
    core = RetainedDevS3Journal(
        client,
        account_id=binding.account_id,
        run_id=binding.run_id,
        source_sha=binding.source_sha,
        phase=binding.phase,
        state_validator=build_phase_state_validator(binding),
        create_first=create_first,
        wall_clock=wall_clock,
        monotonic=monotonic,
    )
    return ValidatedRetainedDevS3Journal(core, binding)


# Concrete bindings used by the retained-dev coordinators.  These are kept
# separate from the small generic prototype above so the operational factory
# cannot accidentally accept an arbitrary state callback or metadata map.
@dataclass(frozen=True, slots=True)
class ArtifactJournalBinding:
    account_id: str
    bucket: str
    run_id: str
    source_sha: str
    artifact_key: str
    sha256: str
    manifest_sha256: str
    size_bytes: int
    authorized_from_epoch: int
    authorized_until_epoch: int
    phase: str = "artifact"

    def __post_init__(self) -> None:
        if self.phase != "artifact":
            raise JournalValidatorError("journal_binding_invalid")
        _check_binding_values(self.account_id, self.source_sha, self.run_id, self.phase, self.manifest_sha256, self.sha256, self.authorized_from_epoch, self.authorized_until_epoch)
        if type(self.bucket) is not str or self.bucket != retained_dev_artifact_bucket(self.account_id) or type(self.artifact_key) is not str or not re.fullmatch(r"runtime/[0-9a-f]{64}\.zip", self.artifact_key) or self.artifact_key != f"runtime/{self.sha256}.zip" or _SHA256.fullmatch(self.sha256) is None or _SHA256.fullmatch(self.manifest_sha256) is None or type(self.size_bytes) is not int or isinstance(self.size_bytes, bool) or not 0 < self.size_bytes <= 16 * 1024 * 1024:
            raise JournalValidatorError("journal_binding_invalid")

    def __repr__(self) -> str:
        return "ArtifactJournalBinding(<redacted>)"


@dataclass(frozen=True, slots=True)
class PreflightJournalBinding:
    account_id: str
    source_sha: str
    run_id: str
    binding_sha256: str
    authorized_from_epoch: int
    authorized_until_epoch: int
    phase: str = "preflight"

    def __post_init__(self) -> None:
        if self.phase != "preflight":
            raise JournalValidatorError("journal_binding_invalid")
        _check_binding_values(self.account_id, self.source_sha, self.run_id, self.phase, self.binding_sha256, self.binding_sha256, self.authorized_from_epoch, self.authorized_until_epoch)

    def __repr__(self) -> str:
        return "PreflightJournalBinding(<redacted>)"


@dataclass(frozen=True, slots=True)
class UpdateJournalBinding:
    account_id: str
    source_sha: str
    run_id: str
    binding_sha256: str
    prior_template_sha256: str
    prior_zip_sha256: str
    candidate_zip_sha256: str
    candidate_manifest_sha256: str
    candidate_template_sha256: str
    stack_arn: str
    authorized_from_epoch: int
    authorized_until_epoch: int
    phase: str = "update"

    def __post_init__(self) -> None:
        if self.phase != "update":
            raise JournalValidatorError("journal_binding_invalid")
        _check_binding_values(self.account_id, self.source_sha, self.run_id, self.phase, self.binding_sha256, self.candidate_template_sha256, self.authorized_from_epoch, self.authorized_until_epoch)
        if any(_SHA256.fullmatch(value) is None or value == "0" * 64 for value in (self.prior_template_sha256, self.prior_zip_sha256, self.candidate_zip_sha256, self.candidate_manifest_sha256, self.candidate_template_sha256)) or type(self.stack_arn) is not str or _STACK_ARN.fullmatch(self.stack_arn) is None or _STACK_ARN.fullmatch(self.stack_arn).group("account") != self.account_id:
            raise JournalValidatorError("journal_binding_invalid")

    def __repr__(self) -> str:
        return "UpdateJournalBinding(<redacted>)"


@dataclass(frozen=True, slots=True)
class RecoveryJournalBinding:
    account_id: str
    bucket: str
    run_id: str
    source_sha: str
    expected_caller_arn: str
    key: str
    zip_sha256: str
    template_sha256: str
    size_bytes: int
    authorized_from_epoch: int
    authorized_until_epoch: int
    phase: str = "recovery"

    def __post_init__(self) -> None:
        if self.phase != "recovery":
            raise JournalValidatorError("journal_binding_invalid")
        _check_binding_values(self.account_id, self.source_sha, self.run_id, self.phase, self.template_sha256, self.zip_sha256, self.authorized_from_epoch, self.authorized_until_epoch)
        if type(self.bucket) is not str or self.bucket != retained_dev_artifact_bucket(self.account_id) or type(self.expected_caller_arn) is not str or re.fullmatch(rf"arn:aws:(?:iam::{self.account_id}:(?:user|role)/[^\s:]+|sts::{self.account_id}:assumed-role/[^\s:/]+/[^\s:/]+)", self.expected_caller_arn) is None or self.expected_caller_arn.endswith(":root") or type(self.key) is not str or self.key != f"runtime/{self.zip_sha256}.zip" or type(self.size_bytes) is not int or isinstance(self.size_bytes, bool) or not 0 < self.size_bytes <= 16 * 1024 * 1024:
            raise JournalValidatorError("journal_binding_invalid")

    def __repr__(self) -> str:
        return "RecoveryJournalBinding(<redacted>)"


@dataclass(frozen=True, slots=True)
class RecoveryUpdateJournalBinding:
    """Binding for rollback/update state, distinct from ZIP publication."""

    account_id: str
    stack_arn: str
    api_id: str
    run_id: str
    source_sha: str
    binding_sha256: str
    current_zip_sha256: str
    current_template_sha256: str
    prior_zip_sha256: str
    prior_template_sha256: str
    prior_artifact_key: str
    expected_caller_arn: str
    authorized_from_epoch: int
    authorized_until_epoch: int
    phase: str = "recovery-update"

    def __post_init__(self) -> None:
        if self.phase != "recovery-update":
            raise JournalValidatorError("journal_binding_invalid")
        _check_binding_values(self.account_id, self.source_sha, self.run_id, self.phase, self.binding_sha256, self.current_template_sha256, self.authorized_from_epoch, self.authorized_until_epoch)
        stack = _STACK_ARN.fullmatch(self.stack_arn) if type(self.stack_arn) is str else None
        caller = re.fullmatch(rf"arn:aws:(?:iam::{self.account_id}:(?:user|role)/[^\s:]+|sts::{self.account_id}:assumed-role/[^\s:/]+/[^\s:/]+)", self.expected_caller_arn) if type(self.expected_caller_arn) is str else None
        if (
            stack is None or stack.group("account") != self.account_id
            or type(self.api_id) is not str or _API.fullmatch(self.api_id) is None
            or any(_SHA256.fullmatch(value) is None or value == "0" * 64 for value in (self.current_zip_sha256, self.current_template_sha256, self.prior_zip_sha256, self.prior_template_sha256))
            or type(self.prior_artifact_key) is not str or self.prior_artifact_key != f"runtime/{self.prior_zip_sha256}.zip"
            or caller is None or self.expected_caller_arn.endswith(":root")
        ):
            raise JournalValidatorError("journal_binding_invalid")

    def __repr__(self) -> str:
        return "RecoveryUpdateJournalBinding(<redacted>)"


def _base_match(value: Any, expected: Mapping[str, Any], *, revision_field: str = "revision") -> bool:
    if not isinstance(value, Mapping) or set(value) != set(expected):
        return False
    if any(value.get(key) != item for key, item in expected.items() if key not in {"status", revision_field, "last_observed_epoch", "observed_epoch"}):
        return False
    return True


def _observed_epoch(value: Any, key: str, binding: Any) -> bool:
    observed = value.get(key) if isinstance(value, Mapping) else None
    try:
        return (
            type(observed) in (int, float)
            and not isinstance(observed, bool)
            and math.isfinite(float(observed))
            and binding.authorized_from_epoch <= observed < binding.authorized_until_epoch
        )
    except (OverflowError, TypeError, ValueError):
        return False


def _artifact_validator(binding: ArtifactJournalBinding, value: Any) -> bool:
    expected = {
        "schema": 1, "kind": "retained-dev-artifact-publication", "account_id": binding.account_id,
        "bucket": binding.bucket, "run_id": binding.run_id, "source_sha": binding.source_sha,
        "authorized_from_epoch": binding.authorized_from_epoch, "authorized_until_epoch": binding.authorized_until_epoch,
        "artifact_key": binding.artifact_key, "sha256": binding.sha256, "manifest_sha256": binding.manifest_sha256,
        "size_bytes": binding.size_bytes,
        "last_observed_epoch": None,
        "revision": None,
        "status": None,
        "intent": {"operation": "publish", "artifact_key": binding.artifact_key, "sha256": binding.sha256, "manifest_sha256": binding.manifest_sha256},
    }
    if not _base_match(value, expected) or type(value.get("schema")) is not int or type(value.get("revision")) is not int or isinstance(value.get("revision"), bool) or not (1 <= value.get("revision", 0) <= 2) or value.get("status") not in {"intent", "verified"} or (value["status"] == "intent" and value["revision"] != 1) or (value["status"] == "verified" and value["revision"] != 2):
        return False
    return _observed_epoch(value, "last_observed_epoch", binding)


def _recovery_validator(binding: RecoveryJournalBinding, value: Any) -> bool:
    expected = {
        "schema": 1, "kind": "retained-dev-recovery-publication", "account_id": binding.account_id,
        "bucket": binding.bucket, "run_id": binding.run_id, "source_sha": binding.source_sha,
        "expected_caller_arn": binding.expected_caller_arn, "authorized_from_epoch": binding.authorized_from_epoch,
        "authorized_until_epoch": binding.authorized_until_epoch, "observed_epoch": None,
        "key": binding.key, "zip_sha256": binding.zip_sha256, "template_sha256": binding.template_sha256,
        "size_bytes": binding.size_bytes, "intent": {"operation": "publish-initial-recovery", "key": binding.key, "zip_sha256": binding.zip_sha256},
        "revision": None, "status": None,
    }
    if not _base_match(value, expected) or type(value.get("schema")) is not int or type(value.get("revision")) is not int or value["revision"] not in {1, 2} or value.get("status") not in {"intent", "verified"}:
        return False
    return _observed_epoch(value, "observed_epoch", binding) and ((value["status"] == "intent" and value["revision"] == 1) or (value["status"] == "verified" and value["revision"] == 2))


def _preflight_validator(binding: PreflightJournalBinding, value: Any) -> bool:
    fields = {"schema", "kind", "version", "binding_sha256", "account_id", "source_sha", "last_observed_epoch", "closed", "read_calls"}
    return isinstance(value, Mapping) and set(value) == fields and type(value.get("schema")) is int and value.get("schema") == 1 and type(value.get("version")) is int and 0 < value["version"] <= MAX_REVISION and value.get("kind") == "retained-dev-delivery-preflight" and value.get("binding_sha256") == binding.binding_sha256 and value.get("account_id") == binding.account_id and value.get("source_sha") == binding.source_sha and _observed_epoch(value, "last_observed_epoch", binding) and value.get("closed") is True and type(value.get("read_calls")) is int and not isinstance(value.get("read_calls"), bool) and 0 < value["read_calls"] <= 96


def _update_validator(binding: UpdateJournalBinding, value: Any) -> bool:
    fields = {"schema", "kind", "revision", "binding_sha256", "source_sha", "run_id", "prior_template_sha256", "prior_zip_sha256", "candidate_zip_sha256", "candidate_manifest_sha256", "candidate_template_sha256", "authorized_from_epoch", "authorized_until_epoch", "preflight", "update_intent", "update_acknowledged", "update_event_observed", "update_verified", "stack_id", "last_observed_epoch"}
    if not isinstance(value, Mapping) or set(value) != fields or type(value.get("schema")) is not int or value.get("schema") != 1 or value.get("kind") != "retained-dev-update" or value.get("binding_sha256") != binding.binding_sha256 or value.get("source_sha") != binding.source_sha or value.get("run_id") != binding.run_id or any(value.get(key) != getattr(binding, key) for key in ("prior_template_sha256", "prior_zip_sha256", "candidate_zip_sha256", "candidate_manifest_sha256", "candidate_template_sha256", "authorized_from_epoch", "authorized_until_epoch")) or type(value.get("revision")) is not int or isinstance(value.get("revision"), bool) or not 1 <= value["revision"] <= MAX_REVISION or any(type(value.get(key)) is not bool for key in ("preflight", "update_acknowledged", "update_event_observed", "update_verified")):
        return False
    if not _observed_epoch(value, "last_observed_epoch", binding):
        return False
    intent = value.get("update_intent")
    if intent is not None and (not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != binding.run_id):
        return False
    if value["update_acknowledged"] and intent is None or value["update_event_observed"] and intent is None or value["update_verified"] and not value["update_event_observed"]:
        return False
    stack_id = value.get("stack_id")
    if (value["update_acknowledged"] or value["update_event_observed"]) and stack_id != binding.stack_arn:
        return False
    return stack_id is None or (type(stack_id) is str and stack_id == binding.stack_arn)


def _recovery_update_validator(binding: RecoveryUpdateJournalBinding, value: Any) -> bool:
    fields = {
        "schema", "kind", "revision", "binding_sha256", "account_id", "stack_arn", "api_id", "source_sha", "run_id",
        "current_zip_sha256", "current_template_sha256", "prior_zip_sha256", "prior_template_sha256", "prior_artifact_key",
        "authorized_from_epoch", "authorized_until_epoch", "expected_caller_arn", "status", "preflight", "update_intent",
        "update_acknowledged", "update_event_observed", "update_verified", "stack_id", "last_observed_epoch",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        return False
    if (
        type(value.get("schema")) is not int or value.get("schema") != 1
        or value.get("kind") != "retained-dev-recovery-update"
        or type(value.get("revision")) is not int or isinstance(value.get("revision"), bool) or not 1 <= value["revision"] <= MAX_REVISION
        or any(value.get(key) != getattr(binding, key) for key in ("binding_sha256", "account_id", "stack_arn", "api_id", "source_sha", "run_id", "current_zip_sha256", "current_template_sha256", "prior_zip_sha256", "prior_template_sha256", "prior_artifact_key", "authorized_from_epoch", "authorized_until_epoch", "expected_caller_arn"))
        or not _observed_epoch(value, "last_observed_epoch", binding)
        or type(value.get("preflight")) is not bool
        or any(type(value.get(key)) is not bool for key in ("update_acknowledged", "update_event_observed", "update_verified"))
        or value.get("preflight") is not True
    ):
        return False
    intent = value.get("update_intent")
    if value["revision"] == 1:
        if value["status"] != "preflight" or intent is not None or any(value[key] for key in ("update_acknowledged", "update_event_observed", "update_verified")):
            return False
    else:
        if not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != binding.run_id:
            return False
    expected_status = {
        (1, False, False, False): "preflight",
        (2, False, False, False): "intent",
        (3, True, False, False): "acknowledged",
        (3, False, True, False): "reconciled",
        (4, True, True, True): "verified",
    }
    key = (value["revision"], value["update_acknowledged"], value["update_event_observed"], value["update_verified"])
    if value.get("status") != expected_status.get(key):
        return False
    stack_id = value.get("stack_id")
    if (value["update_acknowledged"] or value["update_event_observed"]) and stack_id != binding.stack_arn:
        return False
    return stack_id is None or stack_id == binding.stack_arn


def build_concrete_phase_state_validator(binding: Any) -> Callable[[Any], bool]:
    if isinstance(binding, ArtifactJournalBinding):
        return lambda value: _artifact_validator(binding, value)
    if isinstance(binding, PreflightJournalBinding):
        return lambda value: _preflight_validator(binding, value)
    if isinstance(binding, UpdateJournalBinding):
        return lambda value: _update_validator(binding, value)
    if isinstance(binding, RecoveryJournalBinding):
        return lambda value: _recovery_validator(binding, value)
    if isinstance(binding, RecoveryUpdateJournalBinding):
        return lambda value: _recovery_update_validator(binding, value)
    raise JournalValidatorError("journal_binding_invalid")


def create_concrete_phase_journal(client: Any, binding: Any, *, create_first: bool = False, wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> ValidatedRetainedDevS3Journal:
    """Build an actual coordinator-schema journal; no validator callback is accepted."""
    validator = build_concrete_phase_state_validator(binding)
    core = RetainedDevS3Journal(client, account_id=binding.account_id, run_id=binding.run_id, source_sha=binding.source_sha, phase=binding.phase, state_validator=validator, create_first=create_first, wall_clock=wall_clock, monotonic=monotonic)
    return ValidatedRetainedDevS3Journal(core, binding)


__all__ = [
    "ArtifactJournalBinding",
    "JournalValidatorError",
    "PreflightJournalBinding",
    "RecoveryJournalBinding",
    "RecoveryUpdateJournalBinding",
    "RetainedDevJournalBinding",
    "UpdateJournalBinding",
    "ValidatedRetainedDevS3Journal",
    "build_concrete_phase_state_validator",
    "build_phase_state_validator",
    "create_concrete_phase_journal",
    "create_validated_retained_dev_journal",
    "make_phase_state",
    "validate_phase_state",
]
