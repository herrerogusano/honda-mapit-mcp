from __future__ import annotations

from scripts.aws_retained_dev_delivery_artifact import _journal_state, _valid_state


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
        status="intent",
        revision=1,
    )


def test_journal_revision_and_status_are_an_inseparable_cas_state():
    expected = _expected()
    assert _valid_state(expected, expected)
    assert not _valid_state({**expected, "status": "intent", "revision": 2}, expected)
    assert not _valid_state({**expected, "status": "verified", "revision": 1}, expected)
