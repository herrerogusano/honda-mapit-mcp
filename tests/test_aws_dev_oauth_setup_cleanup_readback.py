from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from scripts.aws_dev_oauth_setup_cleanup_readback import check_oauth_setup_cleanup


ACCOUNT = "123456789012"
RUN = "11111111-1111-4111-8111-111111111111"
STACK_UUID = "22222222-2222-4222-8222-222222222222"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"
NAMES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpUserPool": "AWS::Cognito::UserPool",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}


def _ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _state():
    return {
        "account_id": ACCOUNT,
        "region": "eu-west-1",
        "run_id": RUN,
        "app_stack_id": STACK,
        "stack_uuid": STACK_UUID,
        "api_id": "abcdefghij",
        "user_pool_id": "eu-west-1_Abcdefghi",
        "oauth_setup_client_id": "SyntheticClient123",
        "oauth_setup_verified": True,
        "app_delete_attempted": True,
    }


class NotFound(Exception):
    def __init__(self):
        self.response = {
            "Error": {"Code": "ResourceNotFoundException", "Message": "private canary"},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }


class Cfn:
    def describe_stacks(self, *, StackName):
        assert StackName == STACK
        return _ok(Stacks=[{
            "StackId": STACK,
            "StackName": "honda-mapit-mcp-dev",
            "StackStatus": "DELETE_COMPLETE",
            "Tags": [{"Key": "ClosedRehearsalRunId", "Value": RUN}],
        }])

    def describe_stack_resources(self, *, StackName):
        assert StackName == STACK
        return _ok(StackResources=[
            {"LogicalResourceId": logical, "ResourceType": kind, "ResourceStatus": "DELETE_COMPLETE"}
            for logical, kind in NAMES.items()
        ])


class Cognito:
    def describe_user_pool(self, *, UserPoolId):
        assert UserPoolId == "eu-west-1_Abcdefghi"
        raise NotFound()

    def describe_user_pool_domain(self, *, Domain):
        assert Domain == "hm-dev-honda-mapit-mcp-dev"
        return _ok(DomainDescription={})


def test_exact_deleted_setup_stack_and_cognito_parent_domain_verified():
    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": Cognito()}, state=_state(), expected_account_id=ACCOUNT,
    )
    assert result.verified is True
    assert result.category == "oauth_setup_deleted_verified"
    assert result.calls == 4
    assert result.safe_projection() == {
        "verified": True,
        "category": "oauth_setup_deleted_verified",
        "calls": 4,
        "stack_delete_complete": True,
        "setup_resources_deleted": True,
        "user_pool_absent": True,
        "domain_absent": True,
        "user_pool_client_absent": True,
    }


def test_invalid_binding_makes_no_client_calls():
    cfn = Cfn()
    result = check_oauth_setup_cleanup(
        {"cloudformation": cfn, "cognito": Cognito()},
        state={**_state(), "stack_uuid": str(uuid.uuid4())}, expected_account_id=ACCOUNT,
    )
    assert result.verified is False
    assert result.category == "cleanup_inputs_invalid"
    assert result.calls == 0


def test_present_pool_or_domain_fails_closed():
    class PresentPool(Cognito):
        def describe_user_pool(self, *, UserPoolId):
            return _ok(UserPool={"Id": UserPoolId})

    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": PresentPool()}, state=_state(), expected_account_id=ACCOUNT,
    )
    assert result.category == "user_pool_still_present"
    assert result.user_pool_absent is False

    class PresentDomain(Cognito):
        def describe_user_pool_domain(self, *, Domain):
            return _ok(DomainDescription={"Domain": Domain, "UserPoolId": "eu-west-1_Abcdefghi"})

    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": PresentDomain()}, state=_state(), expected_account_id=ACCOUNT,
    )
    assert result.category == "domain_still_present"
    assert result.user_pool_absent is True
    assert result.domain_absent is False

    class DomainExtraField(Cognito):
        def describe_user_pool_domain(self, *, Domain):
            return _ok(DomainDescription={"CloudFrontDistribution": "distribution-canary"})

    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": DomainExtraField()}, state=_state(), expected_account_id=ACCOUNT,
    )
    assert result.category == "domain_still_present"
    assert result.domain_absent is False


def test_verified_scheduled_cleanup_is_an_authorized_readback_path():
    state = _state()
    started = 1_798_000_000
    state.pop("app_delete_attempted")
    state["oauth_setup_controls_verified"] = True
    state["resource_started_epoch"] = started
    state["oauth_setup_cleanup_schedule_expression"] = "at(" + datetime.fromtimestamp(
        started + 2700, timezone.utc,
    ).strftime("%Y-%m-%dT%H:%M:%S") + ")"
    result = check_oauth_setup_cleanup(
        {"cloudformation": Cfn(), "cognito": Cognito()}, state=state, expected_account_id=ACCOUNT,
    )
    assert result.verified is True


def test_resources_must_have_exact_delete_complete_inventory():
    class Incomplete(Cfn):
        def describe_stack_resources(self, *, StackName):
            response = super().describe_stack_resources(StackName=StackName)
            response["StackResources"] = response["StackResources"][:-1]
            return response

    result = check_oauth_setup_cleanup(
        {"cloudformation": Incomplete(), "cognito": Cognito()}, state=_state(), expected_account_id=ACCOUNT,
    )
    assert result.category == "setup_resources_invalid"
    assert result.stack_delete_complete is True
    assert result.setup_resources_deleted is False


def test_aws_request_shapes_match_pinned_cognito_and_cloudformation_models():
    session = pytest.importorskip("botocore.session")
    from botocore.validate import validate_parameters

    model = session.get_session().get_service_model("cloudformation")
    validate_parameters({"StackName": STACK}, model.operation_model("DescribeStacks").input_shape)
    validate_parameters({"StackName": STACK}, model.operation_model("DescribeStackResources").input_shape)
    cognito = session.get_session().get_service_model("cognito-idp")
    validate_parameters({"UserPoolId": "eu-west-1_Abcdefghi"}, cognito.operation_model("DescribeUserPool").input_shape)
    validate_parameters({"Domain": "hm-dev-honda-mapit-mcp-dev"}, cognito.operation_model("DescribeUserPoolDomain").input_shape)
