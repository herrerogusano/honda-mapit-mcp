from __future__ import annotations

import json
import inspect
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_aws_templates as checker


def test_fixed_documents_ignore_environment_canaries_and_have_no_path_input(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-access-canary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret-canary")
    monkeypatch.setenv("MAPIT_EMAIL", "synthetic-user-canary@example.invalid")
    docs = checker.fixed_documents()
    assert set(docs) == {
        "application_draft", "shutdown_lambda_draft", "shutdown_control_draft",
        "cleanup_schedule_draft", "combined_control_draft",
    }
    rendered = "\n".join(docs.values())
    assert "synthetic-access-canary" not in rendered
    assert "synthetic-secret-canary" not in rendered
    assert "synthetic-user-canary" not in rendered
    assert "a1b2c3d4e5" in docs["shutdown_control_draft"]
    bundle = json.loads(docs["combined_control_draft"])
    assert bundle["Metadata"]["NoActivation"] is True
    assert bundle["Metadata"]["NoHardBillingCap"] is True
    assert all(resource["Condition"] == "SupportedRegion" for resource in bundle["Resources"].values())
    assert bundle["Resources"]["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert bundle["Resources"]["CleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert bundle["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert bundle["Resources"]["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert not inspect.signature(checker.fixed_documents).parameters
    assert not inspect.signature(checker.main).parameters


def test_fixed_document_loader_rejects_oversized_template_before_reading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scripts_dir = tmp_path / "scripts"
    scripts_dir.mkdir()
    fake_script = scripts_dir / "check_aws_templates.py"
    fake_script.write_text("# fixture", encoding="utf-8")
    aws_dir = tmp_path / "infra" / "aws"
    aws_dir.mkdir(parents=True)
    (aws_dir / "template.json").write_bytes(b"x" * (checker.MAX_TEMPLATE_BYTES + 1))
    (aws_dir / "dev-shutdown.template.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(checker, "__file__", str(fake_script))
    with pytest.raises(ValueError, match="fixed_template_invalid"):
        checker.fixed_documents()


def test_report_projection_fails_all_warning_or_error_rules_and_hides_diagnostic_text():
    canary = "private-template-content-canary"

    def fake_lint(_document, **options):
        assert options["regions"] == ["eu-west-1"]
        config = options["config"]
        assert config["config_file"] == os.devnull
        assert config["ignore_checks"] == []
        assert config["append_rules"] == []
        assert config["custom_rules"] is None
        assert config["ignore_bad_template"] is False
        return [
            SimpleNamespace(rule=SimpleNamespace(id="I3011"), message=canary),
            SimpleNamespace(rule=SimpleNamespace(id="W3005"), message=canary),
        ]

    docs = checker.fixed_documents()
    report = checker.check_documents(docs, fake_lint)
    assert report["success"] is False
    assert all(component["valid"] is False for component in report["components"])
    assert all(component["rule_ids"] == ["I3011", "W3005"] for component in report["components"])
    assert canary not in json.dumps(report)
    assert all("message" not in component and "document" not in component for component in report["components"])
    assert report["account_operations"] is False and report["deployment"] is False


def test_every_python_socket_and_dns_entrypoint_is_denied_and_restored():
    names = (
        "socket", "SocketType", "socketpair", "create_connection", "getaddrinfo",
        "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    )
    originals = {name: getattr(socket, name) for name in names if hasattr(socket, name)}
    with checker.deny_python_network():
        for name in names:
            if hasattr(socket, name):
                with pytest.raises(RuntimeError, match="static_lint_network_denied"):
                    getattr(socket, name)("synthetic.invalid", 443)
    assert all(getattr(socket, name) is function for name, function in originals.items())


@pytest.mark.parametrize("rule_id", ["E0001", "W9999", "I0000", "E12x4", "I12345", "raw-secret-rule"])
def test_rule_ids_are_strict_and_malformed_results_fail_closed(rule_id: str):
    fake = lambda *_args, **_kwargs: [SimpleNamespace(rule=SimpleNamespace(id=rule_id), message="not-for-output")]
    if len(rule_id) == 5 and rule_id[0] in "EWI" and rule_id[1:].isdigit():
        result = checker.check_documents({"fixed": "{}"}, fake)
        assert result["components"][0]["rule_ids"] == [rule_id]
    else:
        with pytest.raises(ValueError, match="static_lint_result_invalid"):
            checker.check_documents({"fixed": "{}"}, fake)
