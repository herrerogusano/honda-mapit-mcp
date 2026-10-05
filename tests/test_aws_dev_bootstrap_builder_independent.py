from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import scripts.build_aws_dev_bootstrap as builder


def _source_scaffold() -> dict:
    return json.loads((Path(__file__).parents[1] / "infra/aws/template.json").read_text(encoding="utf-8"))


def test_closed_bootstrap_has_only_six_conditioned_dev_resources_and_closed_api():
    template = builder.fixed_bootstrap_template()
    resources = template["Resources"]
    assert set(resources) == {
        "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole",
        "McpHandlerLogGroup", "McpHandler",
    }
    assert all(item["Condition"] == "SupportedDeployment" for item in resources.values())
    assert template["Conditions"]["SupportedDeployment"] == {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev"]},
        ]
    }
    assert template["Parameters"]["EnvironmentName"]["AllowedValues"] == ["dev"]
    assert set(template["Outputs"]) == {"ApiId", "UserPoolId"}
    assert all(output["Condition"] == "SupportedDeployment" for output in template["Outputs"].values())
    assert all(item["DeletionPolicy"] == "Delete" for item in resources.values())
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert resources["McpHandler"]["Properties"]["Code"].keys() == {"ZipFile"}


def test_bootstrap_has_no_oauth_resources_vpc_s3_code_or_route_integrations():
    resources = builder.fixed_bootstrap_template()["Resources"]
    forbidden_types = {
        "AWS::Cognito::UserPoolClient", "AWS::Cognito::UserPoolDomain",
        "AWS::Cognito::UserPoolResourceServer", "AWS::ApiGatewayV2::Integration",
        "AWS::ApiGatewayV2::Route", "AWS::Lambda::Permission", "AWS::Lambda::Url",
    }
    assert not any(item["Type"] in forbidden_types for item in resources.values())
    pool = resources["McpUserPool"]["Properties"]
    assert "LambdaConfig" not in pool
    function = resources["McpHandler"]["Properties"]
    assert not ({"VpcConfig", "Layers", "Environment", "FileSystemConfigs"} & function.keys())
    assert function["Code"] == {"ZipFile": function["Code"]["ZipFile"]}


@pytest.mark.parametrize("property_name,value", [
    ("LambdaConfig", {"PreSignUp": "arn:aws:lambda:eu-west-1:111111111111:function:synthetic-external"}),
    ("EmailConfiguration", {"EmailSendingAccount": "DEVELOPER", "SourceArn": "arn:aws:ses:eu-west-1:111111111111:identity/example.invalid"}),
    ("SmsConfiguration", {"SnsCallerArn": "arn:aws:iam::111111111111:role/synthetic-external", "ExternalId": "synthetic"}),
    ("UserPoolAddOns", {"AdvancedSecurityMode": "ENFORCED"}),
])
def test_scaffold_with_extra_cognito_integrations_or_cost_settings_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, property_name: str, value: dict,
):
    altered = copy.deepcopy(_source_scaffold())
    altered["Resources"]["McpUserPool"]["Properties"][property_name] = value
    scaffold = tmp_path / "infra" / "aws" / "template.json"
    scaffold.parent.mkdir(parents=True)
    scaffold.write_text(json.dumps(altered), encoding="utf-8")
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)
    with pytest.raises(builder.BootstrapTemplateError):
        builder.fixed_bootstrap_template()
