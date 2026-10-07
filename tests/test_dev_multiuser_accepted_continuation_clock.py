"""Independent clock regression for delayed closed deployment + fresh login."""
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest

from scripts import run_dev_multiuser_accepted_continuation as continuation


@pytest.mark.parametrize("value", [True, None, "1", float("inf"), float("nan"), 0, -1])
def test_continuation_rejects_invalid_clock(value):
    with pytest.raises(continuation.AcceptedContinuationError, match="window_expired"):
        continuation._safe_now(lambda: value)


def test_arm_clock_uses_fresh_post_login_time_not_old_deployment_window(monkeypatch):
    from scripts import probe_aws_dev_multiuser_arm as probe

    captured = {}

    def run(path, *, context, payload):
        captured.update(payload)
        return {"success": True, "category": "multiuser_arm_probe_passed"}

    monkeypatch.setattr(probe.docker_helpers, "_docker_context", lambda: "synthetic-context")
    monkeypatch.setattr(probe, "probe_candidate_archive", run)
    receipt = SimpleNamespace(
        manifest_sha256="a" * 64, jwks_sha256="b" * 64, source_sha="c" * 40,
        user_pool_id="eu-west-1_A1b2C3d4E", client_id="a" * 26,
        api_id="abcdefghij", execution_start_epoch=1900000000,
        execution_end_epoch=1900000300,
    )
    manifest = {"tenants": [{"key": "tenant-a"}, {"key": "tenant-b"}]}
    users = {"account_id": "123456789012", "slots": [{"username": "a"}, {"username": "b"}]}
    assert continuation._run_arm_probe(
        "synthetic.zip", manifest, receipt, {"a": "synthetic-a", "b": "synthetic-b"},
        users, clock=lambda: 1900000500,
    ) is False
    assert captured["start"] == 1900000500
    assert captured["now"] == 1900000560
    assert captured["end"] == 1900000800
    assert receipt.execution_start_epoch == 1900000000
    assert receipt.execution_end_epoch == 1900000300


def test_accepted_completion_event_respects_exclusive_authorization_end():
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001"
    event = {
        "StackId": stack, "StackName": "honda-mapit-mcp-dev-retained",
        "PhysicalResourceId": stack, "ResourceType": "AWS::CloudFormation::Stack",
        "ResourceStatus": "UPDATE_COMPLETE", "ClientRequestToken": "synthetic-token",
        "Timestamp": datetime.fromtimestamp(1900000300, timezone.utc),
    }
    kwargs = {"stack_arn": stack, "token": "synthetic-token", "start": 1900000000, "end": 1900000300}
    assert not continuation._has_exact_accepted_completion_event({"StackEvents": [event]}, **kwargs)
    event["Timestamp"] = datetime.fromtimestamp(1900000299, timezone.utc)
    assert continuation._has_exact_accepted_completion_event({"StackEvents": [event]}, **kwargs)
