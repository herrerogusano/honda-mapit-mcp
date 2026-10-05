from __future__ import annotations

import pytest

from tests.test_aws_dev_runtime_artifact_retirement import (
    FakeS3,
    S3Error,
    _empty_objects,
    _retire,
)


def test_delete_precondition_race_is_ambiguous_and_never_retried():
    client = FakeS3(deleted=S3Error("PreconditionFailed", 412))

    result = _retire(client)

    assert result.success is False
    assert result.category == "retirement_delete_ambiguous"
    assert result.delete_attempted is True
    assert result.delete_succeeded is False
    assert result.delete_outcome_unknown is True
    assert [name for name, _ in client.calls] == [
        "get_bucket_versioning", "head_object", "delete_object",
    ]


@pytest.mark.parametrize("marker", ["Prefix", "Delimiter"])
def test_empty_object_listing_rejects_a_scope_marker(marker: str):
    client = FakeS3(
        heads=[S3Error("NoSuchKey", 404)],
        objects=_empty_objects(**{marker: "runtime/"}),
    )

    result = _retire(client)

    assert result.success is False
    assert result.category == "retirement_bucket_not_empty_or_truncated"
    assert result.object_absent_verified is True
    assert result.bucket_empty_verified is False
    assert [name for name, _ in client.calls] == [
        "get_bucket_versioning", "head_object", "list_objects_v2",
    ]


def test_known_object_absence_survives_listing_failure():
    client = FakeS3(
        heads=[S3Error("NoSuchKey", 404)],
        objects=S3Error("AccessDenied", 403),
    )

    result = _retire(client)

    assert result.success is False
    assert result.category == "retirement_object_listing_failed"
    assert result.object_absent_verified is True
    assert result.bucket_empty_verified is False
    assert result.delete_attempted is False
