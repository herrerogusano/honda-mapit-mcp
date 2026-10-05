"""Independent local-only guards for the production release runner."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts import run_cd_release as release


def test_invalid_oidc_context_is_rejected_before_any_aws_client_factory(monkeypatch, tmp_path):
    monkeypatch.setattr(release.Path, "home", lambda: tmp_path)
    calls = []

    def client_factory(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("AWS client construction must not occur")

    bindings = {
        "repository_id": "7654321",
        "owner_id": "1234567",
        "account_id": "123456789012",
        "executor_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cd-executor",
    }
    with pytest.raises(release.ReleaseError) as error:
        release._assume_executor(
            bindings, "a" * 40,
            {"ACTIONS_ID_TOKEN_REQUEST_URL": "not-a-url", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic"},
            opener=lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("synthetic-canary")),
            client_factory=client_factory,
        )
    assert error.value.category == "oidc_claims_mismatch"
    assert "synthetic-canary" not in str(error.value)
    assert calls == []


@pytest.mark.parametrize("age,expected", [
    (0, True), (900, True), (-1, False), (901, False),
])
def test_closed_window_requires_timezone_aware_execution_start(age, expected):
    class SF:
        def describe_execution(self, **kwargs):
            assert kwargs == {"executionArn": "synthetic-execution-arn"}
            return {
                "ResponseMetadata": {"HTTPStatusCode": 200},
                "startDate": datetime.fromtimestamp(10_000 - age, timezone.utc),
            }

    state = {"close_intent": {"execution_arn": "synthetic-execution-arn"}}
    assert release._close_age({"stepfunctions": SF()}, state, now=lambda: 10_000) is expected


def test_terminal_tagging_rejects_foreign_journal_before_s3_calls():
    class S3:
        calls = []

        def get_object_tagging(self, **kwargs):
            self.calls.append(("get", kwargs))
            raise AssertionError("foreign object must not be queried")

        def put_object_tagging(self, **kwargs):
            self.calls.append(("put", kwargs))
            raise AssertionError("foreign object must not be tagged")

    class Journal:
        key = "journals/other-run.json"
        bucket = "synthetic-bucket"
        account_id = "123456789012"
        client = S3()

    runner = release.CDReleaseRunner(environ={"GITHUB_RUN_ID": "42"})
    bindings = {"artifact_bucket": "synthetic-bucket", "account_id": "123456789012"}
    assert runner._tag_terminal_journal(Journal(), bindings) is False
    assert Journal.client.calls == []


def test_release_workflow_has_no_manual_dispatch_and_uses_separate_prod_gates():
    workflow = Path(".github/workflows/cd-release.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" not in workflow
    assert "workflow_run:" in workflow
    assert "persist-credentials: false" in workflow
    assert "environment: prod" in workflow
    assert "needs: [source-gate, arm-runtime-probe]" in workflow
    assert "needs: [source-gate, release]" in workflow
    assert "cancel-in-progress: false" in workflow
    assert "permissions: {}" in workflow
