from __future__ import annotations

import copy

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
from mapit.aws_dev_oauth_cleanup import build_dev_oauth_cleanup


API = "abc123def4"
POOL = "eu-west-1_AbCdEf123"
STACK_UUID = "00000000-0000-4000-8000-000000000001"
SCHEDULE = "2026-10-02T15:01:02"
AUTHORIZE = "auth123"
INTEGRATION = "integ234"
POST_ROUTE = "postroute1"
METADATA_ROUTE = "metaroute2"


def _base():
    return build_dev_bootstrap_cleanup(AwsDevShutdownPolicy(API), POOL, STACK_UUID, SCHEDULE)


def _build(**overrides):
    values = {
        "policy": AwsDevShutdownPolicy(API),
        "user_pool_id": POOL,
        "stack_uuid": STACK_UUID,
        "schedule_at_utc": SCHEDULE,
        "authorizer_id": AUTHORIZE,
        "integration_id": INTEGRATION,
        "post_route_id": POST_ROUTE,
        "metadata_route_id": METADATA_ROUTE,
    }
    values.update(overrides)
    policy = values.pop("policy")
    return build_dev_oauth_cleanup(policy, **values)


def _statements(template):
    return template["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def test_cleanup_extends_only_exact_oauth_scopes_and_retains_disabled_schedule():
    base = _base()
    before = copy.deepcopy(base)
    template = _build()
    statements = _statements(template)
    base_statements = _statements(base)

    assert len(statements) == 7
    assert statements[0]["Action"] == ["apigateway:GET", "apigateway:DELETE"]
    assert statements[0]["Resource"] == base_statements[0]["Resource"] + [
        {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{API}/authorizers/{AUTHORIZE}"},
        {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{API}/integrations/{INTEGRATION}"},
        {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{API}/routes/{POST_ROUTE}"},
        {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{API}/routes/{METADATA_ROUTE}"},
    ]
    assert statements[1]["Action"] == [
        "cognito-idp:DeleteUserPool",
        "cognito-idp:DeleteUserPoolDomain",
        "cognito-idp:DeleteResourceServer",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    assert statements[1]["Resource"] == base_statements[1]["Resource"]
    assert statements[2] == {
        "Effect": "Allow",
        "Action": "cognito-idp:DescribeUserPoolDomain",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
    }
    assert statements[3]["Action"] == ["lambda:DeleteFunction", "lambda:GetFunction", "lambda:RemovePermission"]
    assert statements[3]["Resource"] == base_statements[2]["Resource"]
    assert statements[4:] == base_statements[3:]

    resources = template["Resources"]
    assert resources["BootstrapCleanupSchedule"]["Properties"] == base["Resources"]["BootstrapCleanupSchedule"]["Properties"]
    assert resources["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["BootstrapDeletionRole"]["Properties"]["RoleName"] == "honda-mapit-mcp-dev-bootstrap-delete"
    assert resources["BootstrapCleanupSchedulerRole"] == base["Resources"]["BootstrapCleanupSchedulerRole"]
    assert template["Metadata"]["Readiness"] == "OAUTH_CLEANUP_NOT_DEPLOY_READY"
    assert template["Metadata"]["OptionalProviderPermissionBranchesPending"] is True
    assert template["Metadata"]["RuntimeArtifactRetirementAndEmptyBucketVerificationRequired"] is True
    assert _base() == before


def test_only_two_readonly_describe_actions_use_star_resource_with_region_condition():
    wildcard = [statement for statement in _statements(_build()) if statement.get("Resource") == "*"]
    assert wildcard == [
        {
            "Effect": "Allow",
            "Action": "cognito-idp:DescribeUserPoolDomain",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
        },
        {
            "Effect": "Allow",
            "Action": "logs:DescribeLogGroups",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
        },
    ]
    all_actions = repr(_statements(_build())).lower()
    assert "s3:" not in all_actions
    assert "kms:" not in all_actions
    assert "iam:putrolepolicy" not in all_actions


@pytest.mark.parametrize("field,value", [
    ("authorizer_id", ""),
    ("authorizer_id", "upperID"),
    ("authorizer_id", "bad/id"),
    ("integration_id", "*"),
    ("integration_id", "id-123"),
    ("post_route_id", "id with space"),
    ("metadata_route_id", "x" * 65),
    ("metadata_route_id", True),
])
def test_observed_ids_require_bounded_lowercase_alphanumeric(field, value):
    with pytest.raises(ValueError):
        _build(**{field: value})


def test_route_ids_must_be_distinct():
    with pytest.raises(ValueError):
        _build(metadata_route_id=POST_ROUTE)


@pytest.mark.parametrize("field,value", [
    ("policy", object()),
    ("user_pool_id", "bad"),
    ("stack_uuid", "not-a-uuid"),
    ("schedule_at_utc", "2026-10-02T15:01:02Z"),
])
def test_base_cleanup_bindings_are_revalidated(field, value):
    with pytest.raises(ValueError):
        _build(**{field: value})


def test_unexpected_base_policy_shape_fails_closed(monkeypatch: pytest.MonkeyPatch):
    from mapit import aws_dev_oauth_cleanup as cleanup

    base = _base()
    statements = _statements(base)
    statements[0]["Action"] = ["apigateway:*", "apigateway:GET"]
    monkeypatch.setattr(cleanup, "build_dev_bootstrap_cleanup", lambda *_args: base)
    with pytest.raises(ValueError, match="bootstrap cleanup contract invalid"):
        _build()
