from __future__ import annotations

import json

import pytest

import scripts.build_aws_retained_dev as retained
from scripts.build_aws_shared_identity_dev import build_shared_identity_bootstrap_template


def _template():
    return retained.build_retained_dev_template()


def test_retained_dev_is_five_resource_closed_candidate_with_exact_condition():
    template = _template()
    assert "Parameters" not in template
    assert set(template["Resources"]) == set(retained.EXPECTED_RESOURCES)
    assert template["Conditions"] == {
        "SupportedDeployment": {
            "Fn::And": [
                {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
                {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-retained"]},
            ]
        }
    }
    assert all(resource["Condition"] == "SupportedDeployment" for resource in template["Resources"].values())
    assert template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert template["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert template["Resources"]["McpApi"]["Properties"]["Name"] == "honda-mapit-mcp-dev-retained-api"
    assert template["Resources"]["McpHandler"]["Properties"]["FunctionName"] == "honda-mapit-mcp-dev-retained-handler"
    assert template["Resources"]["McpHandlerLogGroup"]["Properties"]["LogGroupName"] == "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
    assert template["Resources"]["McpHandlerRole"]["Properties"]["RoleName"] == "honda-mapit-mcp-dev-retained-handler-role"
    assert template["Resources"]["McpApi"]["Properties"]["Tags"] == {
        "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev",
    }
    for resource_name in ("McpHandler", "McpHandlerLogGroup", "McpHandlerRole"):
        tags = template["Resources"][resource_name]["Properties"]["Tags"]
        assert {item["Key"]: item["Value"] for item in tags} == {
            "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev",
        }


def test_retained_dev_has_no_identity_or_business_capability():
    encoded = json.dumps(_template(), sort_keys=True)
    for forbidden in ("McpUserPool", "McpUserPoolDomain", "AWS::Cognito", "MfaConfiguration", "EnabledMfas", "ssm:", "secretsmanager:", "dynamodb:", "cognito-idp:"):
        assert forbidden not in encoded
    role = _template()["Resources"]["McpHandlerRole"]["Properties"]
    assert role["Policies"][0]["PolicyDocument"]["Statement"] == [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": role["Policies"][0]["PolicyDocument"]["Statement"][0]["Resource"],
    }]


def test_metadata_explicitly_requires_fresh_acceptance_and_is_not_deploy_ready():
    metadata = _template()["Metadata"]
    assert metadata["Readiness"] == "RETAINED_DEV_NOT_DEPLOY_READY"
    assert metadata["StackName"] == "honda-mapit-mcp-dev-retained"
    assert metadata["Region"] == "eu-west-1"
    assert metadata["NotDeployReady"] is True
    for key in (
        "RequiresFreshOperatorAcceptance",
        "RequiresFreshBootstrapAcceptance",
        "RequiresFreshCDAcceptance",
        "RequiresIndependentShutdownAcceptance",
        "RequiresActivationAcceptance",
    ):
        assert metadata[key] is True


def test_log_role_is_exactly_inherited_from_shared_closed_scaffold():
    baseline = build_shared_identity_bootstrap_template()
    retained_template = _template()
    baseline_role = baseline["Resources"]["McpHandlerRole"]["Properties"]
    retained_role = retained_template["Resources"]["McpHandlerRole"]["Properties"]
    assert retained_role["AssumeRolePolicyDocument"] == baseline_role["AssumeRolePolicyDocument"]
    base_statement = baseline_role["Policies"][0]["PolicyDocument"]["Statement"][0]
    retained_statement = retained_role["Policies"][0]["PolicyDocument"]["Statement"][0]
    assert retained_statement["Effect"] == base_statement["Effect"] == "Allow"
    assert retained_statement["Action"] == base_statement["Action"] == ["logs:CreateLogStream", "logs:PutLogEvents"]
    assert retained_role["RoleName"] == "honda-mapit-mcp-dev-retained-handler-role"
    baseline_log = baseline["Resources"]["McpHandlerLogGroup"]["Properties"]
    retained_log = retained_template["Resources"]["McpHandlerLogGroup"]["Properties"]
    assert retained_log["RetentionInDays"] == baseline_log["RetentionInDays"] == 7
    assert retained_log["LogGroupName"] == "/aws/lambda/honda-mapit-mcp-dev-retained-handler"


def test_factory_is_deterministic_and_does_not_mutate_reused_source():
    first = _template()
    second = _template()
    assert first == second
    first["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = False
    first["Metadata"]["StackName"] = "mutated"
    assert _template()["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert _template()["Metadata"]["StackName"] == "honda-mapit-mcp-dev-retained"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["Resources"]["McpApi"]["Properties"].update(DisableExecuteApiEndpoint=False),
        lambda value: value["Resources"]["McpHandler"]["Properties"].update(ReservedConcurrentExecutions=1),
        lambda value: value["Resources"].update(McpUserPool={"Type": "AWS::Cognito::UserPool"}),
        lambda value: value["Resources"]["McpHandlerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0].update(Action=["ssm:GetParameter"]),
        lambda value: value["Conditions"].update(SupportedDeployment={"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}),
        lambda value: value["Resources"]["McpApiStage"].update(Type="AWS::Lambda::Function"),
        lambda value: value["Resources"]["McpHandler"]["Properties"].update(Code={"ZipFile": "altered"}),
        lambda value: value["Resources"]["McpHandler"]["Properties"].update(ReservedConcurrentExecutions=False),
        lambda value: value["Resources"]["McpHandlerRole"]["Properties"]["Tags"].append({"Key": "Unexpected", "Value": "x"}),
    ],
)
def test_source_mutations_fail_closed_without_relaxing_contract(monkeypatch, mutation):
    source = build_shared_identity_bootstrap_template()
    mutation(source)
    monkeypatch.setattr(retained, "build_shared_identity_bootstrap_template", lambda: source)
    with pytest.raises(retained.RetainedDevTemplateError):
        retained.build_retained_dev_template()


def test_factory_rejects_non_mapping_source_without_cloud_fallback(monkeypatch):
    monkeypatch.setattr(retained, "build_shared_identity_bootstrap_template", lambda: None)
    with pytest.raises(retained.RetainedDevTemplateError) as exc:
        retained.build_retained_dev_template()
    assert str(exc.value) == "retained_dev_source_invalid"
