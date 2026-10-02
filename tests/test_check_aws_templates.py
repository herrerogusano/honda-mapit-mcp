from __future__ import annotations

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
        "bootstrap_cleanup_draft", "bootstrap_control_draft",
        "runtime_artifact_bucket_draft", "runtime_artifact_candidate_draft",
        "closed_oauth_setup_draft",
        "closed_oauth_runtime_draft",
        "closed_oauth_cleanup_draft", "closed_oauth_setup_cleanup_draft",
        "closed_oauth_setup_control_draft",
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
