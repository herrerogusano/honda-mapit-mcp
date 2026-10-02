from __future__ import annotations

import json
from pathlib import Path


TEMPLATE = Path(__file__).parents[1] / "infra" / "aws" / "dev-shutdown.template.json"


def _template():
    return json.loads(TEMPLATE.read_text(encoding="utf-8"))


def _statements(template):
    role = template["Resources"]["ShutdownRole"]["Properties"]
    return role["Policies"][0]["PolicyDocument"]["Statement"]


def test_shutdown_template_is_explicitly_disabled_fixed_dev_only_component():
    template = _template()
    resources = template["Resources"]

    assert template["Metadata"]["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert template["Metadata"]["Region"] == "eu-west-1"
    assert template["Metadata"]["NoActivation"] is True
    assert {
        "independent triggers",
        "verified reserved capacity",
        "owned-resource cleanup",
        "operator/account binding",
    } <= set(template["Metadata"]["MissingPrerequisites"])
    assert set(resources) == {"ShutdownLogs", "ShutdownRole", "ShutdownFunction"}
    assert {resource["Type"] for resource in resources.values()} == {
        "AWS::Logs::LogGroup",
        "AWS::IAM::Role",
        "AWS::Lambda::Function",
    }
    assert all(resource.get("Condition") == "SupportedRegion" for resource in resources.values())
    assert template["Conditions"]["SupportedRegion"] == {
        "Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]
    }


def test_template_has_no_triggers_permissions_endpoint_or_prod_resources():
    template = _template()
    resources = template["Resources"]
    forbidden_types = {
        "AWS::Lambda::Permission",
        "AWS::Lambda::EventSourceMapping",
        "AWS::Events::Rule",
        "AWS::Scheduler::Schedule",
        "AWS::ApiGatewayV2::Api",
        "AWS::ApiGatewayV2::Stage",
        "AWS::ApiGatewayV2::Route",
    }
    assert {resource["Type"] for resource in resources.values()}.isdisjoint(forbidden_types)
    function = resources["ShutdownFunction"]["Properties"]
    assert "Events" not in function
    assert "FunctionUrlConfig" not in function
    assert function["ReservedConcurrentExecutions"] == 0
    assert function["FunctionName"] == "honda-mapit-mcp-dev-shutdown"
    assert function["Runtime"] == "python3.13"
    assert function["Architectures"] == ["arm64"]
    assert "prod" not in template["Description"].lower()
    assert "EnvironmentName" not in template["Parameters"]


def test_parameters_are_required_patterns_and_s3_code_is_version_pinned():
    template = _template()
    parameters = template["Parameters"]
    assert set(parameters) == {"ApiId", "ArtifactBucket", "ArtifactKey", "ArtifactVersion"}
    assert all("Default" not in parameter for parameter in parameters.values())
    assert parameters["ApiId"]["AllowedPattern"] == "^[a-z0-9]{10}$"
    assert parameters["ArtifactBucket"]["AllowedPattern"].startswith("^honda-mapit-mcp-dev-")
    assert parameters["ArtifactKey"]["AllowedPattern"] == "^shutdown/[a-f0-9]{64}\\.zip$"
    assert parameters["ArtifactVersion"]["MinLength"] == 1
    function = template["Resources"]["ShutdownFunction"]["Properties"]
    assert function["Code"] == {
        "S3Bucket": {"Ref": "ArtifactBucket"},
        "S3Key": {"Ref": "ArtifactKey"},
        "S3ObjectVersion": {"Ref": "ArtifactVersion"},
    }
    assert function["Environment"]["Variables"] == {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_API_ID": {"Ref": "ApiId"},
    }


def test_shutdown_role_has_only_fixed_minimum_actions_and_resources():
    template = _template()
    role = template["Resources"]["ShutdownRole"]["Properties"]
    assume = role["AssumeRolePolicyDocument"]["Statement"]
    assert assume == [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]
    statements = _statements(template)
    assert len(statements) == 4
    by_action = {str(statement["Action"]): statement for statement in statements}

    api_patch = by_action["apigateway:PATCH"]
    assert api_patch["Resource"] == {
        "Fn::Sub": "arn:${AWS::Partition}:apigateway:eu-west-1::/apis/${ApiId}"
    }
    assert api_patch["Condition"] == {
        "Bool": {"apigateway:Request/DisableExecuteApiEndpoint": "true"}
    }
    assert by_action["apigateway:GET"]["Resource"] == api_patch["Resource"]

    lambda_statement = by_action["['lambda:PutFunctionConcurrency', 'lambda:GetFunctionConcurrency']"]
    assert set(lambda_statement["Action"]) == {
        "lambda:PutFunctionConcurrency",
        "lambda:GetFunctionConcurrency",
    }
    assert lambda_statement["Resource"] == {
        "Fn::Sub": "arn:${AWS::Partition}:lambda:eu-west-1:${AWS::AccountId}:function:honda-mapit-mcp-dev-handler"
    }

    logs_statement = by_action["['logs:CreateLogStream', 'logs:PutLogEvents']"]
    assert set(logs_statement["Action"]) == {"logs:CreateLogStream", "logs:PutLogEvents"}
    assert logs_statement["Resource"] == {
        "Fn::Sub": "arn:${AWS::Partition}:logs:eu-west-1:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-dev-shutdown:*"
    }
    resources = template["Resources"]
    assert resources["ShutdownLogs"]["Properties"]["RetentionInDays"] == 7
    assert resources["ShutdownLogs"]["Properties"]["LogGroupName"] == "/aws/lambda/honda-mapit-mcp-dev-shutdown"


def test_template_contains_no_credentials_or_fixed_account_resource_identifiers():
    raw = TEMPLATE.read_text(encoding="utf-8")
    template = json.loads(raw)
    assert "AWS::AccountId" in raw  # Account is a deployment intrinsic, not a committed account ID.
    assert not any(secret in raw.lower() for secret in ("aws_access_key_id", "aws_secret_access_key", "session_token"))
    assert "123456789012" not in raw
    assert "Cognito" not in raw
    assert "MAPIT_OWNER_SUBJECT" not in raw
    assert set(template["Resources"]) == {"ShutdownLogs", "ShutdownRole", "ShutdownFunction"}
