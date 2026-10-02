from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

import scripts.build_aws_dev_bootstrap as builder


def _template() -> dict:
    return builder.fixed_bootstrap_template()


def _write_base(tmp_path: Path, document: dict) -> Path:
    base = tmp_path / "infra" / "aws" / "template.json"
    base.parent.mkdir(parents=True, exist_ok=True)
    base.write_text(json.dumps(document), encoding="utf-8")
    return base


def _use_base(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, document: dict) -> None:
    _write_base(tmp_path, document)
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)


def test_factory_selects_only_six_closed_dev_resources_and_fixed_outputs() -> None:
    document = _template()
    expected = {
        "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole",
        "McpHandlerLogGroup", "McpHandler",
    }
    assert set(document["Resources"]) == expected
    assert document["Parameters"] == {
        "EnvironmentName": {
            "Type": "String",
            "Default": "dev",
            "AllowedValues": ["dev"],
            "Description": "Fixed dev environment for a closed bootstrap rehearsal.",
        }
    }
    assert document["Conditions"]["SupportedDeployment"] == {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev"]},
        ]
    }
    assert all(resource["Condition"] == "SupportedDeployment" for resource in document["Resources"].values())
    assert set(document["Outputs"]) == {"ApiId", "UserPoolId"}
    assert document["Outputs"] == {
        "ApiId": {"Condition": "SupportedDeployment", "Value": {"Ref": "McpApi"}},
        "UserPoolId": {"Condition": "SupportedDeployment", "Value": {"Ref": "McpUserPool"}},
    }
    assert document["Metadata"] == {
        "Readiness": "BOOTSTRAP_REHEARSAL_NOT_DEPLOY_READY",
        "Purpose": "closed creation, shutdown, and deletion rehearsal",
        "RuntimeImplementation": False,
        "ApiEndpointOpen": False,
        "OAuthConfigured": False,
        "UserCreated": False,
        "PermissionsAndCleanupPending": True,
        "DeletionPolicy": "Delete",
        "NoActivation": True,
    }


def test_selected_resources_have_delete_policies_and_no_auth_or_public_entrypoint() -> None:
    document = _template()
    resources = document["Resources"]
    assert all(resource["DeletionPolicy"] == "Delete" for resource in resources.values())
    assert all(resource["UpdateReplacePolicy"] == "Delete" for resource in resources.values())
    api = resources["McpApi"]["Properties"]
    assert api["DisableExecuteApiEndpoint"] is True
    assert api["ProtocolType"] == "HTTP"
    assert resources["McpUserPool"]["Properties"]["DeletionProtection"] == "INACTIVE"
    assert not {"McpUserPoolDomain", "McpUserPoolClient", "McpResourceServer", "McpManagedLoginBranding"} & resources.keys()
    assert not any(resource["Type"] in {"AWS::Lambda::Permission", "AWS::Lambda::Url"} for resource in resources.values())


def test_function_remains_constant_503_zero_concurrency_and_without_runtime_configuration() -> None:
    function = _template()["Resources"]["McpHandler"]["Properties"]
    assert function["Handler"] == "index.handler"
    assert function["ReservedConcurrentExecutions"] == 0
    assert "Environment" not in function
    assert "VpcConfig" not in function
    assert "Layers" not in function
    assert "FunctionUrlConfig" not in function
    code = function["Code"]["ZipFile"]
    ast.parse(code)
    namespace: dict = {}
    exec(compile(code, "<offline-bootstrap-inline-handler>", "exec"), namespace)
    assert namespace["handler"]({"body": "private", "headers": {"authorization": "canary"}}, None) == {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
    }


def test_only_owned_log_permissions_are_retained() -> None:
    role = _template()["Resources"]["McpHandlerRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": {
            "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-${EnvironmentName}-handler:*"
        },
    }]
    assert _template()["Resources"]["McpHandlerLogGroup"]["Properties"]["RetentionInDays"] == 7


def test_factory_returns_fresh_templates_without_mutating_scaffold() -> None:
    first = _template()
    second = _template()
    assert first == second and first is not second
    first["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] = 9
    assert second["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0


@pytest.mark.parametrize("mutate", [
    lambda d: d["Resources"]["McpApi"]["Properties"].update(DisableExecuteApiEndpoint=False),
    lambda d: d["Resources"]["McpApi"]["Properties"].update(Body={}),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(ReservedConcurrentExecutions=True),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(Handler="other.handler"),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(Code={"ZipFile": "def handler(event, context): return event"}),
    lambda d: d["Resources"]["McpHandler"]["Properties"]["Code"].update(S3Bucket="unexpected"),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(Environment={"Variables": {"TOKEN": "x"}}),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(VpcConfig={}),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(Layers=["arn"]),
    lambda d: d["Resources"]["McpHandler"]["Properties"].update(FunctionUrlConfig={}),
    lambda d: d["Resources"]["McpUserPool"]["Properties"].update(LambdaConfig={"PreSignUp": "arn"}),
    lambda d: d["Resources"]["McpUserPool"]["Properties"].update(EmailConfiguration={}),
    lambda d: d["Resources"]["McpUserPool"]["Properties"].update(SmsConfiguration={}),
    lambda d: d["Resources"]["McpUserPool"]["Properties"].update(UserPoolAddOns={}),
])
def test_changed_critical_scaffold_properties_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate,
) -> None:
    base = json.loads((Path(__file__).parents[1] / "infra/aws/template.json").read_text(encoding="utf-8"))
    altered = copy.deepcopy(base)
    mutate(altered)
    _use_base(monkeypatch, tmp_path, altered)
    with pytest.raises(builder.BootstrapTemplateError):
        _template()


def test_dangling_reference_to_pruned_resource_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = json.loads((Path(__file__).parents[1] / "infra/aws/template.json").read_text(encoding="utf-8"))
    altered = copy.deepcopy(base)
    altered["Resources"]["McpApiStage"]["Properties"]["ApiId"] = {"Ref": "McpPostRoute"}
    _use_base(monkeypatch, tmp_path, altered)
    with pytest.raises(builder.BootstrapTemplateError):
        _template()


def test_template_input_is_bounded_and_duplicate_json_keys_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "infra" / "aws" / "template.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b'{"Resources":{},"Resources":{}}')
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)
    with pytest.raises(builder.BootstrapTemplateError, match="scaffold_invalid"):
        _template()

    path.write_bytes(b" " * (builder.MAX_TEMPLATE_BYTES + 1))
    with pytest.raises(builder.BootstrapTemplateError, match="scaffold_size_invalid"):
        _template()


def test_scaffold_symlink_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    infra = tmp_path / "infra"
    infra.mkdir()
    aws = infra / "aws"
    aws.mkdir()
    link = aws / "template.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)
    with pytest.raises(builder.BootstrapTemplateError, match="scaffold_unavailable"):
        _template()
