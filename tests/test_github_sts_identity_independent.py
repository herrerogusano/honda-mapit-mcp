from __future__ import annotations

import pytest

from scripts.github_sts_identity import StsProofError, prove_github_sts_identity
from test_github_sts_identity import (
    ACCOUNT,
    OWNER_ID,
    REPO_ID,
    ROLE_ARN,
    SHA,
    FakeSts,
    NOW,
    _responses,
    _token,
)


def test_caller_identity_exception_is_redacted_without_retry_or_extra_factory() -> None:
    class FailingCaller:
        def get_caller_identity(self):
            raise RuntimeError("synthetic-caller-secret-canary")

    assume_reply, _caller_reply = _responses()
    unsigned = FakeSts(assume=assume_reply)
    explicit_calls = []

    def factory(**kwargs):
        explicit_calls.append(kwargs)
        return FailingCaller()

    with pytest.raises(StsProofError, match="sts_exchange_failed") as caught:
        prove_github_sts_identity(
            _token(),
            target="dev",
            source_sha=SHA,
            expected_account_id=ACCOUNT,
            expected_owner_id=OWNER_ID,
            expected_repository_id=REPO_ID,
            role_arn=ROLE_ARN,
            anonymous_sts=unsigned,
            explicit_sts_factory=factory,
            clock=lambda: NOW,
        )

    assert "synthetic-caller-secret-canary" not in repr(caught.value)
    assert len(unsigned.calls) == 1
    assert len(explicit_calls) == 1
