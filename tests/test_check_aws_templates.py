from __future__ import annotations

import hashlib
import json
import os
import socket
from types import SimpleNamespace

import pytest

from scripts import check_aws_templates as checker


def test_fixed_documents_have_only_synthetic_disabled_targets():
    documents = checker.fixed_documents()
    assert set(documents) == {
        "application_draft", "shutdown_lambda_draft",
        "shutdown_control_draft", "cleanup_schedule_draft", "combined_control_draft",
        "closed_bootstrap_draft",
        "retained_dev_closed_bootstrap_draft",
        "retained_dev_closed_runtime_draft",
        "retained_dev_controls_draft", "retained_dev_artifacts_draft",
        "retained_dev_oauth_draft",
        "retained_dev_multiuser_setup", "retained_dev_multiuser_runtime",
        "retained_dev_multiuser_roles_bootstrap", "retained_dev_multiuser_roles_recurrent",
        "retained_dev_multiuser_roles_recurrent_existing_key",
        "retained_dev_multiuser_timed_controls",
        "permanent_identity_draft",
        "bootstrap_cleanup_draft", "bootstrap_control_draft",
        "runtime_artifact_bucket_draft", "runtime_artifact_candidate_draft",
        "closed_oauth_setup_draft",
        "closed_oauth_runtime_draft",
        "closed_oauth_cleanup_draft", "closed_oauth_setup_cleanup_draft",
        "closed_oauth_setup_control_draft",
        "shared_identity_dev_runtime_draft", "shared_identity_dev_cleanup_draft",
        "prod_bootstrap_draft", "prod_controls_draft", "prod_artifacts_draft", "prod_artifacts_cd_retention",
        "prod_oauth_draft", "prod_runtime_draft",
        "cd_identity_legacy_draft", "cd_identity_immutable_draft",
        "cd_delivery_legacy_draft", "cd_delivery_immutable_draft",
        "cd_delivery_lambda_key_draft",
        "cd_retained_dev_legacy_draft", "cd_retained_dev_immutable_draft",
        "cd_retained_dev_lambda_key_draft",
        "cd_retained_dev_readonly_proof_draft",
    }
    app = json.loads(documents["application_draft"])
    assert app["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert app["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    control = json.loads(documents["shutdown_control_draft"])
    assert control["Resources"]["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    cleanup = json.loads(documents["cleanup_schedule_draft"])
    assert cleanup["Resources"]["CleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert "a1b2c3d4e5" in documents["shutdown_control_draft"]
    combined = json.loads(documents["combined_control_draft"])
    assert combined["Resources"]["CleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert combined["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    oauth_setup = json.loads(documents["closed_oauth_setup_draft"])
    assert len(oauth_setup["Resources"]) == 10
    assert oauth_setup["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert oauth_setup["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert "McpPostRoute" not in oauth_setup["Resources"]
    assert "McpLambdaInvokePermission" not in oauth_setup["Resources"]
    setup_control = json.loads(documents["closed_oauth_setup_control_draft"])
    assert len(setup_control["Resources"]) == 12
    assert setup_control["Metadata"]["NoActivation"] is True
    assert setup_control["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    setup_cleanup = json.loads(documents["closed_oauth_setup_cleanup_draft"])
    statements = setup_cleanup["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert "cognito-idp:DeleteUserPoolClient" in statements[1]["Action"]
    assert statements[2]["Action"] == "cognito-idp:DescribeUserPoolDomain"
    identity = json.loads(documents["permanent_identity_draft"])
    assert set(identity["Resources"]) == {"McpUserPool", "McpUserPoolDomain", "McpUserPoolClient", "McpManagedLoginBranding"}
    assert identity["Resources"]["McpUserPool"]["DeletionPolicy"] == "Retain"
    assert identity["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"] == ["openid"]
    shared = json.loads(documents["shared_identity_dev_runtime_draft"])
    assert "McpUserPool" not in shared["Resources"] and "McpUserPoolDomain" not in shared["Resources"]
    assert shared["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert shared["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    shared_cleanup = json.loads(documents["shared_identity_dev_cleanup_draft"])
    shared_statements = shared_cleanup["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    shared_actions = [action for statement in shared_statements for action in (
        statement["Action"] if isinstance(statement.get("Action"), list) else [statement.get("Action")]
    )]
    assert not {"cognito-idp:DeleteUserPool", "cognito-idp:DeleteUserPoolDomain", "cognito-idp:DescribeUserPoolDomain"} & set(shared_actions)

    prod_bootstrap = json.loads(documents["prod_bootstrap_draft"])
    assert prod_bootstrap["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert prod_bootstrap["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert not any(item["Type"].startswith("AWS::Cognito") for item in prod_bootstrap["Resources"].values())

    prod_controls = json.loads(documents["prod_controls_draft"])
    assert prod_controls["Metadata"]["NoActivation"] is True
    assert prod_controls["Resources"]["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert prod_controls["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert not any(item["Type"] == "AWS::Lambda::Function" for item in prod_controls["Resources"].values())

    prod_artifacts = json.loads(documents["prod_artifacts_draft"])
    assert prod_artifacts["Metadata"]["NoDeployment"] is True
    assert len(prod_artifacts["Resources"]) == 2
    prod_bucket = prod_artifacts["Resources"]["RuntimeArtifactBucket"]
    assert prod_bucket["DeletionPolicy"] == prod_bucket["UpdateReplacePolicy"] == "Retain"
    prod_bucket_props = prod_bucket["Properties"]
    assert all(value is True for value in prod_bucket_props["PublicAccessBlockConfiguration"].values())
    assert "BucketName" not in prod_bucket_props and "VersioningConfiguration" not in prod_bucket_props

    prod_oauth = json.loads(documents["prod_oauth_draft"])
    assert prod_oauth["Metadata"]["NoActivation"] is True
    assert set(prod_oauth["Resources"]) == {
        "ProdMcpResourceServer", "ProdMcpUserPoolClient", "ProdMcpManagedLoginBranding",
    }
    assert prod_oauth["Resources"]["ProdMcpUserPoolClient"]["Properties"]["GenerateSecret"] is False
    assert prod_oauth["Resources"]["ProdMcpUserPoolClient"]["Properties"]["AllowedOAuthFlows"] == ["code"]

    prod_runtime = json.loads(documents["prod_runtime_draft"])
    assert prod_runtime["Metadata"]["RuntimeActivation"] is False
    assert prod_runtime["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert prod_runtime["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert not any(item["Type"].startswith("AWS::Cognito") for item in prod_runtime["Resources"].values())

    synthetic_account = "123456789012"
    synthetic_owner = "1234567"
    synthetic_repository = "7654321"
    provider_arn = f"arn:aws:iam::{synthetic_account}:oidc-provider/token.actions.githubusercontent.com"
    for label, subject_format in (
        ("cd_identity_legacy_draft", "legacy_environment"),
        ("cd_identity_immutable_draft", "immutable_environment"),
    ):
        identity_template = json.loads(documents[label])
        assert set(identity_template["Resources"]) == {
            "DevCdPermissionsBoundary", "DevCdIdentityRole",
            "ProdCdPermissionsBoundary", "ProdCdIdentityRole",
        }
        assert "Outputs" not in identity_template and "Parameters" not in identity_template
        assert all(
            item["Type"] != "AWS::IAM::OpenIDConnectProvider"
            for item in identity_template["Resources"].values()
        )
        for target in ("dev", "prod"):
            title = target.title()
            role = identity_template["Resources"][f"{title}CdIdentityRole"]
            boundary = identity_template["Resources"][f"{title}CdPermissionsBoundary"]
            role_props = role["Properties"]
            assert role["Type"] == "AWS::IAM::Role"
            assert role_props["RoleName"] == f"honda-mapit-mcp-{target}-cd"
            assert role_props["Tags"] == [
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": target},
                {"Key": "Purpose", "Value": "CDIdentityOwnership"},
            ]
            assert role_props["PermissionsBoundary"] == {
                "Fn::GetAtt": [f"{title}CdPermissionsBoundary", "PolicyArn"]
            }
            if subject_format == "legacy_environment":
                subject = f"repo:herrerogusano/honda-mapit-mcp:environment:{target}"
            else:
                subject = (
                    f"repo:herrerogusano@{synthetic_owner}/honda-mapit-mcp@{synthetic_repository}"
                    f":environment:{target}"
                )
            statement = role_props["AssumeRolePolicyDocument"]["Statement"]
            assert statement == [{
                "Sid": "TrustExactRepositoryEnvironmentSubject",
                "Effect": "Allow",
                "Principal": {"Federated": provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": subject,
                }},
            }]
            inline = role_props["Policies"]
            assert len(inline) == 1
            assert inline[0]["PolicyDocument"]["Statement"] == [{
                "Sid": "AllowOnlyCallerIdentity", "Effect": "Allow",
                "Action": "sts:GetCallerIdentity", "Resource": "*",
            }]
            boundary_props = boundary["Properties"]
            assert boundary["Type"] == "AWS::IAM::ManagedPolicy"
            assert "Tags" not in boundary_props
            assert boundary_props["PolicyDocument"]["Statement"] == [
                {"Sid": "AllowOnlyCallerIdentity", "Effect": "Allow",
                 "Action": "sts:GetCallerIdentity", "Resource": "*"},
                {"Sid": "DenyEverythingExceptCallerIdentity", "Effect": "Deny",
                 "NotAction": "sts:GetCallerIdentity", "Resource": "*"},
            ]

    for label, subject_format in (
        ("cd_delivery_legacy_draft", "legacy_environment"),
        ("cd_delivery_immutable_draft", "immutable_environment"),
    ):
        delivery = json.loads(documents[label])
        assert delivery["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
        assert delivery["Metadata"]["ApiGatewayHttpApiResourceScopePendingClosedValidation"] is True
        assert delivery["Metadata"]["ApiGatewayPropertyChangeGuardIsTemplateOnly"] is True
        assert set(delivery["Resources"]) == {
            "ProdCdExecutorBoundary", "ProdCdExecutorRole",
            "ProdCdCloudFormationBoundary", "ProdCdCloudFormationRole",
        }
        executor_trust = delivery["Resources"]["ProdCdExecutorRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
        expected_subject = (
            f"repo:herrerogusano/honda-mapit-mcp:environment:prod"
            if subject_format == "legacy_environment"
            else f"repo:herrerogusano@{synthetic_owner}/honda-mapit-mcp@{synthetic_repository}:environment:prod"
        )
        assert executor_trust["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] == expected_subject
        cfn_role = delivery["Resources"]["ProdCdCloudFormationRole"]["Properties"]
        assert cfn_role["AssumeRolePolicyDocument"]["Statement"][0]["Principal"] == {
            "Service": "cloudformation.amazonaws.com"
        }


def test_socket_and_dns_guard_restores_after_success_and_exception():
    original_socket, original_dns = socket.socket, socket.getaddrinfo
    with pytest.raises(ValueError, match="fixture_failure"):
        with checker.deny_python_network():
            with pytest.raises(RuntimeError, match="static_lint_network_denied"):
                socket.socket()
            with pytest.raises(RuntimeError, match="static_lint_network_denied"):
                socket.getaddrinfo("example.invalid", 443)
            raise ValueError("fixture_failure")
    assert socket.socket is original_socket
    assert socket.getaddrinfo is original_dns


@pytest.mark.parametrize("rule,valid", [("E3012", False), ("W3005", False), ("I3011", True)])
def test_checker_uses_fixed_region_no_user_config_and_closed_result_projection(rule, valid):
    def lint(document, **options):
        assert document == "{}"
        assert options["regions"] == ["eu-west-1"]
        assert options["config"]["config_file"] == os.devnull
        assert options["config"]["ignore_checks"] == []
        return [SimpleNamespace(rule=SimpleNamespace(id=rule), message="not-for-output")]

    result = checker.check_documents({"fixture": "{}"}, lint)
    assert result["success"] is valid
    assert result["account_operations"] is False and result["deployment"] is False
    assert result["components"][0]["rule_ids"] == [rule]
    assert "not-for-output" not in json.dumps(result)


def test_unexpected_rule_identifier_is_rejected():
    with pytest.raises(ValueError, match="static_lint_result_invalid"):
        checker.check_documents({"fixture": "{}"}, lambda *_a, **_k: [
            SimpleNamespace(rule=SimpleNamespace(id="raw-provider-value")),
        ])


def test_missing_or_wrong_tool_version_fails_with_safe_category(monkeypatch, capsys):
    monkeypatch.setattr(checker, "version", lambda _name: "unsupported")
    assert checker.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "success": False, "category": "static_template_check_failed",
        "account_operations": False, "deployment": False,
    }
