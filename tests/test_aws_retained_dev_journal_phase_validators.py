from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
from dataclasses import replace
from typing import Any

import pytest

from scripts.aws_retained_dev_journal import RetainedDevJournalError
from scripts.aws_retained_dev_journal_validators import (
    ArtifactJournalBinding,
    JournalValidatorError,
    PreflightJournalBinding,
    RecoveryJournalBinding,
    RecoveryUpdateJournalBinding,
    UpdateJournalBinding,
    build_concrete_phase_state_validator,
    create_concrete_phase_journal,
)
from tests import test_aws_retained_dev_delivery_update as update_base
from tests import test_aws_retained_dev_delivery_artifact as artifact_base
from tests import test_aws_retained_dev_recovery_artifact as recovery_base
from tests import test_aws_retained_dev_delivery_recovery as recovery_update_base
from tests import test_aws_retained_dev_delivery_preflight_sdk_happy as preflight_happy


ACCOUNT = "123456789012"
RUN = "12345678-1234-4234-8234-123456789abc"
SOURCE = "a" * 40
SHA = "b" * 64
MANIFEST = "c" * 64
TEMPLATE = "d" * 64
ZIP = "e" * 64
START = 1_900_000_000
BUCKET = f"honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/12345678-1234-4234-8234-123456789abc"


class S3Error(Exception):
    def __init__(self, code: str = "NoSuchKey", status: int = 404):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Body:
    def __init__(self, raw: bytes):
        self.raw = raw

    def read(self, size: int = -1) -> bytes:
        return self.raw if size < 0 else self.raw[:size]

    def close(self) -> None:
        return None


class S3:
    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.n = 0

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get", kwargs))
        if kwargs["Key"] not in self.objects:
            raise S3Error()
        raw, etag = self.objects[kwargs["Key"]]
        return {
            "Body": Body(raw), "ContentLength": len(raw),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(raw).digest()).decode(),
            "ServerSideEncryption": "AES256", "ContentType": "application/json",
            "ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put", kwargs))
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise S3Error("PreconditionFailed", 412)
        if kwargs.get("IfMatch") is not None and (key not in self.objects or self.objects[key][1] != kwargs["IfMatch"]):
            raise S3Error("PreconditionFailed", 412)
        self.n += 1
        etag = f'"etag{self.n}"'
        self.objects[key] = (kwargs["Body"], etag)
        return {"ChecksumSHA256": kwargs["ChecksumSHA256"], "ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200}}


class PublicationS3(S3):
    """One offline client exposing journal CAS plus the publisher methods."""

    def __init__(self):
        super().__init__()
        self.artifact_body: bytes | None = None
        self.put_calls: list[dict[str, Any]] = []
        self.head_calls: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        if str(kwargs.get("Key", "")).startswith("journals/"):
            return super().put_object(**kwargs)
        self.put_calls.append(kwargs)
        self.artifact_body = kwargs["Body"]
        return {"ChecksumSHA256": base64.b64encode(hashlib.sha256(self.artifact_body).digest()).decode(), "ResponseMetadata": {"HTTPStatusCode": 200}}

    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        self.head_calls.append(kwargs)
        if self.artifact_body is None:
            raise RuntimeError("missing-artifact")
        return {"ContentLength": len(self.artifact_body), "ChecksumSHA256": base64.b64encode(hashlib.sha256(self.artifact_body).digest()).decode(), "ServerSideEncryption": "AES256", "ContentType": "application/zip", "ResponseMetadata": {"HTTPStatusCode": 200}}


class Clock:
    def __init__(self):
        self.wall = START + 5
        self.mono = 1.0

    def w(self) -> float:
        return self.wall

    def m(self) -> float:
        return self.mono


def artifact_binding() -> ArtifactJournalBinding:
    return ArtifactJournalBinding(ACCOUNT, BUCKET, RUN, SOURCE, f"runtime/{SHA}.zip", SHA, MANIFEST, 1234, START, START + 900)


def preflight_binding() -> PreflightJournalBinding:
    return PreflightJournalBinding(ACCOUNT, SOURCE, RUN, SHA, START, START + 900)


def update_binding() -> UpdateJournalBinding:
    return UpdateJournalBinding(ACCOUNT, SOURCE, RUN, SHA, TEMPLATE, ZIP, SHA, MANIFEST, TEMPLATE, STACK, START, START + 900)


def recovery_binding() -> RecoveryJournalBinding:
    return RecoveryJournalBinding(ACCOUNT, BUCKET, RUN, SOURCE, f"arn:aws:iam::{ACCOUNT}:role/operator", f"runtime/{ZIP}.zip", ZIP, TEMPLATE, 1234, START, START + 900)


def recovery_update_binding() -> RecoveryUpdateJournalBinding:
    coordinator, _, _, _ = recovery_update_base._coordinator()
    return RecoveryUpdateJournalBinding(
        coordinator.account_id, coordinator.stack_arn, coordinator.api_id,
        coordinator.run_id, coordinator.source_sha, coordinator.binding_sha256,
        coordinator.current_build_receipt.zip_sha256, coordinator.current_template_sha256,
        coordinator.recovery_template.code_sha256, coordinator.recovery_template.recovery_template_sha256,
        coordinator.recovery_artifact.key, coordinator.expected_caller_arn,
        coordinator.authorized_from, coordinator.authorized_until,
    )


def artifact_state(revision: int, status: str = "intent") -> dict[str, Any]:
    b = artifact_binding()
    return {
        "schema": 1, "kind": "retained-dev-artifact-publication", "account_id": ACCOUNT,
        "bucket": BUCKET, "run_id": RUN, "source_sha": SOURCE,
        "authorized_from_epoch": START, "authorized_until_epoch": START + 900,
        "artifact_key": b.artifact_key, "sha256": SHA, "manifest_sha256": MANIFEST,
        "size_bytes": 1234, "intent": {"operation": "publish", "artifact_key": b.artifact_key, "sha256": SHA, "manifest_sha256": MANIFEST},
        "last_observed_epoch": START + 5, "revision": revision, "status": status,
    }


def recovery_state(revision: int, status: str = "intent") -> dict[str, Any]:
    b = recovery_binding()
    return {
        "schema": 1, "kind": "retained-dev-recovery-publication", "account_id": ACCOUNT,
        "bucket": BUCKET, "run_id": RUN, "source_sha": SOURCE, "expected_caller_arn": b.expected_caller_arn,
        "authorized_from_epoch": START, "authorized_until_epoch": START + 900, "observed_epoch": START + 5,
        "key": b.key, "zip_sha256": ZIP, "template_sha256": TEMPLATE, "size_bytes": 1234,
        "intent": {"operation": "publish-initial-recovery", "key": b.key, "zip_sha256": ZIP},
        "revision": revision, "status": status,
    }


def make_journal(client: S3, binding: Any, *, first: bool = True):
    clock = Clock()
    return create_concrete_phase_journal(client, binding, create_first=first, wall_clock=clock.w, monotonic=clock.m)


def test_concrete_artifact_create_first_uses_cas_without_existence_read():
    s3 = S3()
    journal = make_journal(s3, artifact_binding())
    with journal.locked():
        assert journal.load() is None
        assert not [call for call in s3.calls if call[0] == "get"]
        assert journal.compare_and_set(None, artifact_state(1))
        assert journal.compare_and_set(1, artifact_state(2, "verified"))
    assert len([call for call in s3.calls if call[0] == "put"]) == 2


def test_concrete_recovery_and_preflight_states_have_distinct_actual_shapes():
    assert build_concrete_phase_state_validator(recovery_binding())(recovery_state(1))
    pre = preflight_binding()
    pre_state = {"schema": 1, "kind": "retained-dev-delivery-preflight", "version": 1, "binding_sha256": SHA, "account_id": ACCOUNT, "source_sha": SOURCE, "last_observed_epoch": START + 5, "closed": True, "read_calls": 1}
    assert build_concrete_phase_state_validator(pre)(pre_state)
    assert not build_concrete_phase_state_validator(pre)(dict(pre_state, read_calls=True))
    assert not build_concrete_phase_state_validator(recovery_binding())(dict(recovery_state(1), observed_epoch=True))


def test_concrete_preflight_uses_actual_version_envelope_through_cas():
    s3 = S3()
    journal = make_journal(s3, preflight_binding())
    state = {"schema": 1, "kind": "retained-dev-delivery-preflight", "version": 1, "binding_sha256": SHA, "account_id": ACCOUNT, "source_sha": SOURCE, "last_observed_epoch": START + 5, "closed": True, "read_calls": 1}
    with journal.locked():
        assert journal.load() is None
        assert journal.compare_and_set(None, state)
    assert next(call[1]["Body"] for call in s3.calls if call[0] == "put")


def test_update_requires_exact_stack_arn_and_monotonic_flags():
    b = update_binding()
    validator = build_concrete_phase_state_validator(b)
    state = {
        "schema": 1, "kind": "retained-dev-update", "revision": 1, "binding_sha256": SHA,
        "source_sha": SOURCE, "run_id": RUN, "prior_template_sha256": TEMPLATE, "prior_zip_sha256": ZIP,
        "candidate_zip_sha256": SHA, "candidate_manifest_sha256": MANIFEST, "candidate_template_sha256": TEMPLATE,
        "authorized_from_epoch": START, "authorized_until_epoch": START + 900, "preflight": True,
        "update_intent": {"client_request_token": RUN}, "update_acknowledged": True,
        "update_event_observed": True, "update_verified": True, "stack_id": STACK, "last_observed_epoch": START + 5,
    }
    assert validator(state)
    assert not validator(dict(state, stack_id=STACK.replace(ACCOUNT, "999999999999")))
    assert not validator(dict(state, update_event_observed=False))
    assert not validator(dict(state, stack_id=None))
    assert not validator(dict(state, schema=True))


def test_concrete_artifact_rejects_boolean_revision_and_huge_epoch():
    validator = build_concrete_phase_state_validator(artifact_binding())
    assert not validator(dict(artifact_state(1), revision=True))
    assert not validator(dict(artifact_state(1), last_observed_epoch=10**10000))


def test_unknown_write_is_fenced_and_fresh_concrete_journal_reconciles():
    s3 = S3()
    original = s3.put_object

    def ambiguous(**kwargs: Any):
        original(**kwargs)
        raise RuntimeError("redacted")

    s3.put_object = ambiguous  # type: ignore[method-assign]
    first = make_journal(s3, artifact_binding())
    with first.locked():
        assert first.load() is None
        with pytest.raises(RetainedDevJournalError, match="journal_write_ambiguous"):
            first.compare_and_set(None, artifact_state(1))
    second = make_journal(s3, artifact_binding(), first=False)
    with second.locked():
        assert second.load()["revision"] == 1


def test_concrete_conditional_412_reconciles_winner_and_allows_followup():
    s3 = S3()
    winner = make_journal(s3, artifact_binding())
    with winner.locked():
        assert winner.load() is None
        assert winner.compare_and_set(None, artifact_state(1))
    contender = make_journal(s3, artifact_binding())
    with contender.locked():
        assert contender.load() is None
        assert contender.compare_and_set(None, artifact_state(1)) is False
        assert contender.load()["revision"] == 1
        assert contender.compare_and_set(1, artifact_state(2, "verified"))


def test_concrete_binding_rejects_zero_hashes_and_wrong_namespace():
    with pytest.raises(JournalValidatorError):
        ArtifactJournalBinding(ACCOUNT, "other-" + BUCKET, RUN, SOURCE, f"runtime/{SHA}.zip", SHA, MANIFEST, 1, START, START + 1)
    with pytest.raises(JournalValidatorError):
        UpdateJournalBinding(ACCOUNT, SOURCE, RUN, SHA, "0" * 64, ZIP, SHA, MANIFEST, TEMPLATE, STACK, START, START + 1)


@pytest.mark.parametrize(
    ("factory", "wrong_phase"),
    [
        (artifact_binding, "update"),
        (preflight_binding, "artifact"),
        (update_binding, "recovery"),
        (recovery_binding, "preflight"),
    ],
)
def test_typed_bindings_cannot_retarget_journal_phase(factory, wrong_phase):
    with pytest.raises(JournalValidatorError, match="journal_binding_invalid"):
        replace(factory(), phase=wrong_phase)


def test_recovery_update_binding_cannot_retarget_publication_namespace():
    binding = RecoveryUpdateJournalBinding(
        ACCOUNT, STACK, "a1b2c3d4e5", RUN, SOURCE, SHA,
        ZIP, TEMPLATE, MANIFEST, SHA, f"runtime/{MANIFEST}.zip",
        f"arn:aws:iam::{ACCOUNT}:role/operator", START, START + 900,
    )
    with pytest.raises(JournalValidatorError, match="journal_binding_invalid"):
        replace(binding, phase="recovery")


@pytest.mark.parametrize(
    "factory,wrong_phase",
    [
        (lambda: artifact_binding(), "update"),
        (lambda: preflight_binding(), "artifact"),
        (lambda: update_binding(), "recovery"),
        (lambda: recovery_binding(), "recovery-update"),
        (lambda: recovery_update_binding(), "update"),
    ],
)
def test_typed_binding_rejects_cross_phase_namespace(factory, wrong_phase):
    """A typed journal must not be retargetable by overriding its phase field."""
    binding = factory()
    with pytest.raises(JournalValidatorError):
        replace(binding, phase=wrong_phase)


def _attach_update_journal(coordinator: Any):
    binding = UpdateJournalBinding(
        coordinator.account_id, coordinator.source_sha, coordinator.run_id,
        coordinator.binding_sha256, coordinator.prior_template_sha256,
        coordinator.prior_zip_sha256, coordinator.candidate_zip_sha256,
        coordinator.candidate_manifest_sha256, coordinator.candidate_template_sha256,
        coordinator.stack_arn, coordinator.authorized_from, coordinator.authorized_until,
    )
    wall = lambda: float(coordinator.authorized_from + 5)
    mono = lambda: 1.0
    coordinator.journal = create_concrete_phase_journal(
        S3(), binding, create_first=True, wall_clock=wall, monotonic=mono,
    )
    return coordinator


def test_actual_update_coordinator_sequence_uses_concrete_cas_journal():
    coordinator, _ = update_base._coordinator()
    coordinator = _attach_update_journal(coordinator)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_acknowledged"
    assert coordinator.run_step("check-update")["category"] == "readback_verified"


def test_actual_update_coordinator_eventual_write_accepts_event_without_http_ack():
    coordinator, cfn = update_base._coordinator()

    class EventualCloudFormation(update_base.CloudFormation):
        def update_stack(self, **kwargs: Any):
            self.calls.append(("update_stack", kwargs))
            self.updated = True
            raise RuntimeError("ambiguous")

    cfn.__class__ = EventualCloudFormation
    coordinator = _attach_update_journal(coordinator)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("check-update")["category"] == "update_reconciled_without_ack"


def test_actual_runtime_publisher_uses_concrete_artifact_cas_journal(tmp_path):
    path, body, digest = artifact_base._archive(tmp_path)
    manifest_sha = hashlib.sha256(artifact_base._manifest_bytes()).hexdigest()
    binding = ArtifactJournalBinding(ACCOUNT, BUCKET, RUN, SOURCE, f"runtime/{digest}.zip", digest, manifest_sha, len(body), 1_893_455_000, 1_893_458_000)
    s3 = PublicationS3()
    journal = create_concrete_phase_journal(s3, binding, create_first=True, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    result = artifact_base._publish(path, digest, s3, journal)
    assert result.success and result.category == "artifact_uploaded_verified"
    assert len(s3.put_calls) == 1 and len(s3.head_calls) == 1


def test_actual_recovery_publisher_uses_concrete_recovery_cas_journal():
    snapshot = recovery_base._snapshot()
    key = f"runtime/{snapshot.zip_sha256}.zip"
    binding = RecoveryJournalBinding(ACCOUNT, BUCKET, RUN, SOURCE, recovery_base.CALLER, key, snapshot.zip_sha256, snapshot.template_sha256, len(snapshot.archive_bytes), 1_893_455_000, 1_893_458_000)
    s3 = PublicationS3()
    journal = create_concrete_phase_journal(s3, binding, create_first=True, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    result = recovery_base.publish_initial_recovery_artifact(s3, journal, **recovery_base._kwargs(snapshot))
    assert result.success and result.category == "published"
    assert len(s3.put_calls) == 1 and len(s3.head_calls) == 1


def _attach_recovery_update_journal(coordinator: Any):
    binding = RecoveryUpdateJournalBinding(
        coordinator.account_id, coordinator.stack_arn, coordinator.api_id,
        coordinator.run_id, coordinator.source_sha, coordinator.binding_sha256,
        coordinator.current_build_receipt.zip_sha256, coordinator.current_template_sha256,
        coordinator.recovery_template.code_sha256, coordinator.recovery_template.recovery_template_sha256,
        coordinator.recovery_artifact.key, coordinator.expected_caller_arn,
        coordinator.authorized_from, coordinator.authorized_until,
    )
    coordinator.journal = create_concrete_phase_journal(
        S3(), binding, create_first=True,
        wall_clock=lambda: float(coordinator.authorized_from + 5), monotonic=lambda: 1.0,
    )
    return coordinator


def test_actual_recovery_update_coordinator_uses_separate_typed_journal_phase():
    coordinator, _, _, _ = recovery_update_base._coordinator()
    coordinator = _attach_recovery_update_journal(coordinator)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_acknowledged"
    assert coordinator.run_step("check-update")["category"] == "readback_verified"


def test_actual_recovery_update_ambiguous_write_reconciles_without_ack():
    coordinator, cfn, _, _ = recovery_update_base._coordinator(ambiguous=True)
    coordinator = _attach_recovery_update_journal(coordinator)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("check-update")["category"] == "update_reconciled_without_ack"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_actual_preflight_coordinator_uses_concrete_versioned_cas_journal():
    contract_binding, values = preflight_happy._fixture("map")
    values = {**values, "control": values.pop("controls")}
    clients = {name: preflight_happy.Clients(contract_binding, values).client(name) for name in ("sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch")}
    binding = PreflightJournalBinding(
        contract_binding.account_id, contract_binding.source_sha, contract_binding.run_id,
        contract_binding.binding_sha256, contract_binding.authorized_from_epoch,
        contract_binding.authorized_until_epoch,
    )
    journal = create_concrete_phase_journal(
        S3(), binding, create_first=True, wall_clock=lambda: 1_900_000_001, monotonic=lambda: 1.0,
    )
    result = preflight_happy.RetainedDevDeliveryPreflight(
        clients, journal, binding=contract_binding,
        wall_clock=lambda: 1_900_000_001, monotonic=lambda: 1.0,
    ).run()
    assert result == {"ok": True, "category": "preflight_verified", "calls": 51}
