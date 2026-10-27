from __future__ import annotations

import copy

import scripts.build_aws_retained_dev as retained
from scripts.build_aws_shared_identity_dev import build_shared_identity_bootstrap_template


EXPECTED_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
}


def test_retained_dev_is_exactly_five_closed_resources_with_fixed_names_and_scope():
    template = retained.build_retained_dev_template()
    resources = template["Resources"]

    assert {name: resource["Type"] for name, resource in resources.items()} == EXPECTED_TYPES
    assert template["Conditions"] == {
        "SupportedDeployment": {
            "Fn::And": [
                {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
                {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-retained"]},
            ],
        }
    }
    assert all(resource.get("Condition") == "SupportedDeployment" for resource in resources.values())

    api = resources["McpApi"]["Properties"]
    handler = resources["McpHandler"]["Properties"]
    role = resources["McpHandlerRole"]["Properties"]
    log_group = resources["McpHandlerLogGroup"]["Properties"]
    assert api["Name"] == "honda-mapit-mcp-dev-retained-api"
    assert api["DisableExecuteApiEndpoint"] is True
    assert handler["FunctionName"] == "honda-mapit-mcp-dev-retained-handler"
    assert handler["ReservedConcurrentExecutions"] == 0
    assert role["RoleName"] == "honda-mapit-mcp-dev-retained-handler-role"
    assert role["Policies"][0]["PolicyName"] == "honda-mapit-mcp-dev-retained-owned-log-writes"
    assert log_group["LogGroupName"] == "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
    assert role["Policies"][0]["PolicyDocument"]["Statement"] == [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": {
            "Fn::Sub": (
                "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
                "log-group:/aws/lambda/honda-mapit-mcp-dev-retained-handler:*"
            )
        },
    }]


def test_retained_dev_is_off_and_has_no_new_identity_pool_oauth_or_secret_capability():
    template = retained.build_retained_dev_template()
    metadata = template["Metadata"]
    encoded = repr(template)

    assert metadata["Readiness"] == "RETAINED_DEV_NOT_DEPLOY_READY"
    assert metadata["RuntimeImplementation"] is False
    assert metadata["ApiEndpointOpen"] is False
    assert metadata["OAuthConfigured"] is False
    assert metadata["UserCreated"] is False
    assert metadata["NoActivation"] is True
    assert metadata["NoPoolResourceOrPoolOutput"] is True
    assert metadata["NoCredentialsSsmOrBusinessCalls"] is True
    for marker in (
        "AWS::Cognito::UserPool",
        "AWS::Cognito::UserPoolDomain",
        "McpUserPool",
        "McpUserPoolDomain",
        "cognito-idp:",
        "dynamodb:",
        "secretsmanager:",
        "ssm:",
        "kms:",
        "s3:",
        "MfaConfiguration",
    ):
        assert marker not in encoded


def test_retained_factory_does_not_mutate_or_relax_shared_source_factory():
    baseline_before = build_shared_identity_bootstrap_template()
    retained_template = retained.build_retained_dev_template()
    baseline_after = build_shared_identity_bootstrap_template()
    assert baseline_before == baseline_after

    retained_template["Resources"]["McpHandlerRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]["Action"] = ["logs:CreateLogStream", "ssm:GetParameter"]
    retained_template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = False
    assert build_shared_identity_bootstrap_template() == baseline_before

    second = retained.build_retained_dev_template()
    assert second["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert second["Resources"]["McpHandlerRole"]["Properties"]["Policies"][0][
        "PolicyDocument"
    ]["Statement"][0]["Action"] == ["logs:CreateLogStream", "logs:PutLogEvents"]
    assert copy.deepcopy(second) == retained.build_retained_dev_template()
