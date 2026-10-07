from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

from scripts.run_dev_multiuser_accepted_continuation import (
    _only_artifact_source_window_delta,
    _safe_http_receipt,
    _has_exact_accepted_completion_event,
    _same_resource_inventory,
)


def _templates():
    base = {
        "Resources": {
            "McpHandler": {
                "Properties": {
                    "Code": {"S3Bucket": "owned-dev-bucket", "S3Key": "runtime/" + "a" * 64 + ".zip"},
                    "Environment": {"Variables": {
                        "MAPIT_SOURCE_SHA256": "1" * 40,
                        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": "2" * 64,
                        "MAPIT_DEV_EXECUTION_START_EPOCH": "1900000000",
                        "MAPIT_DEV_EXECUTION_END_EPOCH": "1900000300",
                        "MAPIT_COGNITO_JWKS_SHA256": "3" * 64,
                    }},
                }
            },
            "McpApi": {"Properties": {"DisableExecuteApiEndpoint": True}},
        },
        "Metadata": {
            "SourceSha256": "1" * 40,
            "ManifestSha256": "2" * 64,
            "ExecutionStartEpoch": 1900000000,
            "ExecutionEndEpoch": 1900000300,
            "ManifestContract": {"source_sha": "1" * 40, "api_id": "abcdefghij"},
        },
    }
    candidate = deepcopy(base)
    props = candidate["Resources"]["McpHandler"]["Properties"]
    props["Code"]["S3Key"] = "runtime/" + "b" * 64 + ".zip"
    variables = props["Environment"]["Variables"]
    variables["MAPIT_SOURCE_SHA256"] = "4" * 40
    variables["MAPIT_DEV_MULTIUSER_MANIFEST_SHA256"] = "5" * 64
    variables["MAPIT_DEV_EXECUTION_START_EPOCH"] = "1900000600"
    variables["MAPIT_DEV_EXECUTION_END_EPOCH"] = "1900000900"
    metadata = candidate["Metadata"]
    metadata["SourceSha256"] = "4" * 40
    metadata["ManifestSha256"] = "5" * 64
    metadata["ExecutionStartEpoch"] = 1900000600
    metadata["ExecutionEndEpoch"] = 1900000900
    metadata["ManifestContract"]["source_sha"] = "4" * 40
    return base, candidate


def test_template_delta_allows_only_new_artifact_source_and_window():
    before, after = _templates()
    assert _only_artifact_source_window_delta(before, after)


def test_template_delta_rejects_api_or_other_runtime_changes():
    before, after = _templates()
    after["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = False
    assert not _only_artifact_source_window_delta(before, after)


def test_template_delta_rejects_new_or_removed_template_fields():
    before, after = _templates()
    after["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]["NEW_SECRET"] = "x"
    assert not _only_artifact_source_window_delta(before, after)


def test_template_delta_rejects_jwks_rebinding_or_only_window_change():
    before, after = _templates()
    after["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]["MAPIT_COGNITO_JWKS_SHA256"] = "6" * 64
    assert not _only_artifact_source_window_delta(before, after)
    before, after = _templates()
    before["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] = after["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"]
    assert not _only_artifact_source_window_delta(before, after)


def test_post_close_inventory_must_preserve_exact_physical_resource_set():
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-3333-4444-555555555555"
    original = {
        f"Resource{i}": {
            "LogicalResourceId": f"Resource{i}", "ResourceType": "AWS::Lambda::Function",
            "PhysicalResourceId": f"physical-{i}", "ResourceStatus": "UPDATE_COMPLETE",
            "StackId": stack, "StackName": "honda-mapit-mcp-dev-retained",
        }
        for i in range(19)
    }
    rows = list(original.values())
    assert _same_resource_inventory(rows, original, stack)
    changed = [dict(row) for row in rows]
    changed[0]["PhysicalResourceId"] = "other-function"
    assert not _same_resource_inventory(changed, original, stack)
    assert not _same_resource_inventory(rows[:-1], original, stack)


def test_success_http_receipt_requires_all_canonical_checks_and_call_count():
    checks = {
        "initialize", "tools_exact", "tenant_a_status", "tenant_a_distance",
        "tenant_b_status", "tenant_b_distance", "foreign_route_denied",
        "anonymous_denied", "revocation_committed", "revoked_a_denied",
        "b_after_a_revocation",
    }
    valid = {
        "success": True, "category": "http_acceptance_verified", "calls": 10,
        "checks": {key: True for key in checks},
    }
    assert _safe_http_receipt(valid)["success"] is True
    assert _safe_http_receipt({**valid, "checks": {}}) == {
        "success": False, "category": "http_receipt_invalid",
    }
    assert _safe_http_receipt({**valid, "calls": 9})["category"] == "http_receipt_invalid"
    assert _safe_http_receipt({**valid, "checks": {**valid["checks"], "tenant_b_status": False}})["category"] == "http_receipt_invalid"
    assert _safe_http_receipt({**valid, "failure_stage": "unexpected"})["category"] == "http_receipt_invalid"


def test_accepted_completion_event_is_found_on_first_bounded_page_without_pagination():
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-3333-4444-555555555555"
    event = {
        "StackId": stack, "StackName": "honda-mapit-mcp-dev-retained",
        "PhysicalResourceId": stack, "ResourceType": "AWS::CloudFormation::Stack",
        "ResourceStatus": "UPDATE_COMPLETE", "ClientRequestToken": "accepted-token",
        "Timestamp": datetime.fromtimestamp(1900000123, tz=timezone.utc),
    }
    response = {"StackEvents": [event] + [{"ResourceStatus": "UPDATE_IN_PROGRESS"} for _ in range(99)],
                "NextToken": "private-continuation-token"}
    assert _has_exact_accepted_completion_event(response, stack_arn=stack, token="accepted-token", start=1900000000, end=1900000300)
    assert not _has_exact_accepted_completion_event(response, stack_arn=stack, token="other-token", start=1900000000, end=1900000300)
