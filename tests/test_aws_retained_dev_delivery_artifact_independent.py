from __future__ import annotations

from scripts.aws_retained_dev_delivery_artifact import _journal_state, _valid_state
from scripts.aws_retained_dev_delivery_artifact import publish_retained_dev_runtime
from scripts.build_aws_retained_dev_archive import _make_receipt
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest, retained_dev_artifact_bucket

from test_aws_retained_dev_delivery_artifact import ACCOUNT, MANIFEST_PATH, RUN, SOURCE, S3, Journal, _archive, _manifest_bytes


def _expected():
    return _journal_state(
        account_id="123456789012",
        bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        run_id="12345678-1234-4234-8234-123456789abc",
        source_sha="a" * 40,
        key="runtime/" + "b" * 64 + ".zip",
        sha256="b" * 64,
        manifest_sha256="c" * 64,
        size_bytes=128,
        authorized_from_epoch=100,
        authorized_until_epoch=200,
        last_observed_epoch=110,
        status="intent",
        revision=1,
    )


def test_journal_revision_and_status_are_an_inseparable_cas_state():
    expected = _expected()
    assert _valid_state(expected, expected)
    assert not _valid_state({**expected, "status": "intent", "revision": 2}, expected)
    assert not _valid_state({**expected, "status": "verified", "revision": 1}, expected)


def _publish_args(path, digest):
    receipt = _make_receipt(
        source_sha=SOURCE, api_id="a1b2c3d4e5", jwks_sha256="b" * 64,
        execution_start_epoch=1_893_456_000, execution_end_epoch=1_893_456_300,
        zip_sha256=digest, manifest_sha256=__import__("hashlib").sha256(_manifest_bytes()).hexdigest(),
        source_allowlist_sha256="f" * 64, source_proof_sha256="e" * 64,
        wheel_lock_sha256="d" * 64, wheel_proof_sha256="c" * 64,
        archive_entries=2, wheel_count=0, source_modules=0, public_key_count=0,
    )
    return dict(
        bucket=retained_dev_artifact_bucket(ACCOUNT), expected_owner=ACCOUNT, run_id=RUN,
        archive_path=path, build_receipt=receipt,
        authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000,
    )


def test_expiry_after_head_verification_never_writes_verified_cas(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal()

    class Clock:
        def __init__(self):
            self.expired = False

        def wall(self):
            return 1_893_459_000 if self.expired else 1_893_456_100

        def mono(self):
            return 1.0

    clock = Clock()

    class HeadExpires(S3):
        def head_object(self, **kwargs):
            result = super().head_object(**kwargs)
            clock.expired = True
            return result

    s3 = HeadExpires()
    result = publish_retained_dev_runtime(s3, journal, **_publish_args(path, digest), wall_clock=clock.wall, monotonic=clock.mono)
    assert result.category == "window_expired"
    assert [state["status"] for state in journal.saves] == ["intent"]


def test_restart_with_lower_wall_clock_than_persisted_state_is_fenced(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal(); s3 = S3()
    kwargs = _publish_args(path, digest)
    first = publish_retained_dev_runtime(s3, journal, **kwargs, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    second = publish_retained_dev_runtime(s3, journal, **kwargs, wall_clock=lambda: 1_893_456_090, monotonic=lambda: 1.0)
    assert first.success and second.category == "window_expired"
    assert len(s3.put_calls) == 1


def test_restart_with_different_authority_window_cannot_reuse_journal(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal(); s3 = S3(); kwargs = _publish_args(path, digest)
    assert publish_retained_dev_runtime(s3, journal, **kwargs, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0).success
    changed = dict(kwargs, authorized_from_epoch=1_893_455_001)
    result = publish_retained_dev_runtime(s3, journal, **changed, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    assert result.category == "journal_conflict" and len(s3.put_calls) == 1


def test_schema_bool_and_nonfinite_last_observation_fail_closed(tmp_path):
    path, _, digest = _archive(tmp_path)
    kwargs = _publish_args(path, digest)
    for mutation in (lambda state: state.update(schema=True), lambda state: state.update(last_observed_epoch=float("nan"))):
        journal = Journal(); s3 = S3()
        assert publish_retained_dev_runtime(s3, journal, **kwargs, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0).success
        mutation(journal.state)
        result = publish_retained_dev_runtime(s3, journal, **kwargs, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
        assert result.category == "journal_conflict" and len(s3.put_calls) == 1


def test_head_requires_zip_content_type(tmp_path):
    path, body, digest = _archive(tmp_path)
    bad_head = {
        "ContentLength": len(body),
        "ChecksumSHA256": __import__("base64").b64encode(__import__("hashlib").sha256(body).digest()).decode("ascii"),
        "ServerSideEncryption": "AES256", "ContentType": "text/plain",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    result = publish_retained_dev_runtime(S3(head=bad_head), Journal(), **_publish_args(path, digest), wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    assert result.category == "artifact_head_mismatch"
