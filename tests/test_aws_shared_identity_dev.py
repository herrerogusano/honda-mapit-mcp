from __future__ import annotations

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_shared_identity_dev_cleanup import (
    build_shared_identity_bootstrap_cleanup,
    build_shared_identity_dev_cleanup,
    build_shared_identity_dev_cleanup_operator_retired,
)
from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template
from scripts.build_aws_dev_oauth_template import build_dev_oauth_setup_template
from scripts.build_aws_dev_oauth_template import build_dev_oauth_template
from scripts.build_aws_shared_identity_dev import (
    SharedIdentityTemplateError,
    build_shared_identity_bootstrap_template,
    build_shared_identity_dev_template,
    build_shared_identity_dev_retained_template,
    build_shared_identity_oauth_setup_template,
    build_shared_identity_oauth_setup_retained_template,
)

POOL = "eu-west-1_Abcdefghi"
API = "abcdefghij"
CLIENT = "SyntheticClient123"
CALLBACK = "http://localhost:39031/callback/synthetic"
ZIP_SHA = "a" * 64
JWKS_SHA = "b" * 64
STACK_UUID = "11111111-2222-3333-4444-555555555555"


def _policy():
    return CognitoDevPolicy(POOL, API, CLIENT, "12345678-1234-4234-8234-123456789abc")


def _runtime_kwargs():
    return {
        "bucket": "honda-mapit-mcp-dev-synthetic-artifact",
        "zip_sha256": ZIP_SHA,
        "jwks_sha256": JWKS_SHA,
        "callback_url": CALLBACK,
        "execution_start": 1893456000,
        "execution_end": 1893456300,
    }


def _contains_old_pool_reference(value):
    if isinstance(value, dict):
        return (
            value == {"Ref": "McpUserPool"}
            or any("${McpUserPool}" in child for key, child in value.items() if key == "Fn::Sub" and type(child) is str)
            or any(_contains_old_pool_reference(child) for child in value.values())
        )
    if isinstance(value, list):
        return any(_contains_old_pool_reference(child) for child in value)
    return False


def test_shared_identity_dev_template_removes_only_pool_and_domain():
    original = build_dev_oauth_template(_policy(), **_runtime_kwargs())
    template = build_shared_identity_dev_template(_policy(), **_runtime_kwargs())
    resources = template["Resources"]
    assert len(original["Resources"]) == 16
    assert len(resources) == 14
    assert "McpUserPool" not in resources and "McpUserPoolDomain" not in resources
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert resources["McpHandler"]["Properties"]["Environment"]["Variables"]["MAPIT_COGNITO_USER_POOL_ID"] == POOL
    assert resources["McpResourceServer"]["Properties"]["UserPoolId"] == POOL
    assert resources["McpUserPoolClient"]["Properties"]["UserPoolId"] == POOL
    assert resources["McpUserPoolClient"]["DependsOn"] == ["McpResourceServer"]
    assert "DependsOn" not in resources["McpManagedLoginBranding"]
    resource_uri = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
    assert resources["McpResourceServer"]["Properties"]["Identifier"] == {"Ref": "McpResourceUri"}
    assert template["Parameters"]["McpResourceUri"]["Default"] == resource_uri
    assert resources["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert resources["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"] == {
        "Fn::Sub": f"https://cognito-idp.${{AWS::Region}}.amazonaws.com/{POOL}"
    }
    assert _contains_old_pool_reference(template) is False
    assert template["Outputs"]["UserPoolId"]["Value"] == POOL
    assert template["Metadata"]["SharedPersistentIdentityPool"] is True
    assert template["Metadata"]["DevClientMustBeCreatedAndReadBackBeforeRuntimeComposition"] is True
    assert template["Metadata"]["RuntimeClientIdIsValidatedLiteralBinding"] is True


def test_shared_identity_bootstrap_has_five_resources_and_no_pool_output_or_reference():
    original = fixed_bootstrap_template()
    template = build_shared_identity_bootstrap_template()
    assert len(original["Resources"]) == 6
    assert len(template["Resources"]) == 5
    assert set(template["Resources"]) == set(original["Resources"]) - {"McpUserPool"}
    assert set(template["Outputs"]) == {"ApiId"}
    assert _contains_old_pool_reference(template) is False
    assert template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert template["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0


def test_shared_identity_oauth_setup_has_eight_resources_and_literal_pool_binding():
    original = build_dev_oauth_setup_template(API, callback_url=CALLBACK)
    template = build_shared_identity_oauth_setup_template(API, POOL, callback_url=CALLBACK)
    assert len(original["Resources"]) == 10
    assert len(template["Resources"]) == 8
    assert "McpUserPool" not in template["Resources"]
    assert "McpUserPoolDomain" not in template["Resources"]
    assert template["Resources"]["McpResourceServer"]["Properties"]["UserPoolId"] == POOL
    assert template["Resources"]["McpUserPoolClient"]["Properties"]["UserPoolId"] == POOL
    assert template["Resources"]["McpUserPoolClient"]["DependsOn"] == ["McpResourceServer"]
    assert "DependsOn" not in template["Resources"]["McpManagedLoginBranding"]
    assert template["Outputs"]["UserPoolId"]["Value"] == POOL
    assert _contains_old_pool_reference(template) is False
    assert template["Metadata"]["PoolIDIsValidatedLiteralBinding"] is True


def test_shared_identity_setup_and_runtime_can_retain_all_three_pool_children():
    expected = ("McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding")
    setup = build_shared_identity_oauth_setup_retained_template(API, POOL, callback_url=CALLBACK)
    runtime = build_shared_identity_dev_retained_template(_policy(), **_runtime_kwargs())
    for template in (setup, runtime):
        for name in expected:
            assert template["Resources"][name]["DeletionPolicy"] == "Retain"
            assert template["Resources"][name]["UpdateReplacePolicy"] == "Retain"
        assert template["Metadata"]["NoAutomaticPoolChildDeletion"] is True
        assert template["Metadata"]["SharedPoolDevChildrenRequireSeparateOperatorRetirement"] is True


def test_operator_retirement_cleanup_has_no_cognito_actions():
    kwargs = dict(authorizer_id="auth123", integration_id="int123", post_route_id="post123", metadata_route_id="meta123")
    template = build_shared_identity_dev_cleanup_operator_retired(
        AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00", **kwargs,
    )
    statements = template["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statements) == 5
    assert all(not any(str(action).startswith("cognito-idp:") for action in (
        statement["Action"] if type(statement.get("Action")) is list else [statement.get("Action")]
    )) for statement in statements)
    assert template["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert template["Metadata"]["NoAutomaticPoolChildDeletion"] is True
    assert template["Metadata"]["ExactObservedChildIDsAndOwnershipRequired"] is True


def test_shared_bootstrap_cleanup_has_no_cognito_pool_or_pool_child_grant():
    original = build_shared_identity_bootstrap_cleanup(
        AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00",
    )
    statements = original["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statements) == 5
    assert all(not any(str(action).startswith("cognito-idp:") for action in (
        statement["Action"] if type(statement.get("Action")) is list else [statement.get("Action")]
    )) for statement in statements)
    assert original["Metadata"]["PersistentIdentityPoolDeletionPermissionExcluded"] is True
    assert original["Metadata"]["PoolARNChildPermissionNotIncluded"] is True
    assert original["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"


def test_shared_identity_cleanup_preserves_pool_but_child_permissions_are_pool_scoped():
    kwargs = dict(
        authorizer_id="auth123", integration_id="int123", post_route_id="post123", metadata_route_id="meta123",
    )
    original = build_shared_identity_dev_cleanup(
        AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00", **kwargs,
    )
    statements = original["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    cognito = [item for item in statements if any(str(action).startswith("cognito-idp:") for action in ([item.get("Action")] if type(item.get("Action")) is str else item.get("Action", [])))]
    assert len(cognito) == 1
    assert cognito[0]["Resource"] == {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{POOL}"
    }
    assert cognito[0]["Action"] == [
        "cognito-idp:DeleteResourceServer", "cognito-idp:DeleteUserPoolClient", "cognito-idp:DeleteManagedLoginBranding",
    ]
    assert not {"cognito-idp:DeleteUserPool", "cognito-idp:DeleteUserPoolDomain", "cognito-idp:DescribeUserPoolDomain"} & set(cognito[0]["Action"])
    assert original["Metadata"]["PersistentPoolAndDomainPreserved"] is True
    assert "PermanentIdentityClientPreserved" not in original["Metadata"]
    assert original["Metadata"]["CognitoChildDeletesAreScopedToPoolNotIndividualChildren"] is True
    assert original["Metadata"]["SharedPoolChildDeletionBlastRadiusRequiresExplicitAcceptance"] is True
    assert original["Metadata"]["ExactWorkflowChildBindingsMustBeVerifiedBeforeUse"] is True
    assert original["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"


def test_shared_cleanup_factory_does_not_mutate_original_full_cleanup():
    from mapit.aws_dev_oauth_cleanup import build_dev_oauth_cleanup

    kwargs = dict(
        authorizer_id="auth123", integration_id="int123", post_route_id="post123", metadata_route_id="meta123",
    )
    full = build_dev_oauth_cleanup(
        AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00", **kwargs,
    )
    full_statement = full["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][1]
    assert "cognito-idp:DeleteUserPool" in full_statement["Action"]
    build_shared_identity_dev_cleanup(
        AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00", **kwargs,
    )
    assert "cognito-idp:DeleteUserPool" in full_statement["Action"]


def test_shared_identity_factory_rejects_invalid_policy_without_fallback():
    try:
        policy = CognitoDevPolicy("eu-west-1_Abcdefghi", "abcdefghij", CLIENT, "12345678-1234-4234-8234-123456789abc")
    except ValueError:
        policy = None
    assert policy is not None
    try:
        build_shared_identity_dev_template(policy, **{**_runtime_kwargs(), "callback_url": "https://example.invalid/callback"})
    except SharedIdentityTemplateError as exc:
        assert str(exc) == "shared_identity_runtime_candidate_invalid"
    else:
        raise AssertionError("invalid callback must fail closed")
