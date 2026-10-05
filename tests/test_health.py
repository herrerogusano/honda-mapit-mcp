from __future__ import annotations

import json

import pytest

from mapit import health


def test_health_reads_only_allowlisted_package_metadata(monkeypatch):
    observed = []

    def version(name):
        observed.append(name)
        return "synthetic-version"

    monkeypatch.setattr(health.metadata, "version", version)
    monkeypatch.setattr(health.sys, "version_info", (3, 13, 0))
    monkeypatch.setattr(health.sys, "platform", "win32")
    monkeypatch.setenv("MAPIT_PASSWORD", "private-sentinel")
    result = health.environment_health()
    assert result["success"] is True
    assert set(observed) == {"mcp", "pydantic", "openai-agents", "websockets", "keyring"}
    assert result["credentials_checked"] is False
    assert result["provider_connectivity_checked"] is False
    assert "private-sentinel" not in json.dumps(result)
    assert all(type(value) is bool for name, value in result.items() if name not in {"category", "check_kind"})


def test_missing_optional_dependencies_do_not_claim_provider_failure(monkeypatch):
    def version(name):
        if name not in {"mcp", "pydantic"}:
            raise health.metadata.PackageNotFoundError(name)
        return "synthetic-version"

    monkeypatch.setattr(health.metadata, "version", version)
    monkeypatch.setattr(health.sys, "version_info", (3, 11, 0))
    monkeypatch.setattr(health.sys, "platform", "linux")
    result = health.environment_health()
    assert result["success"] is True
    assert result["agent_dependency_available"] is False
    assert result["realtime_dependency_available"] is False
    assert result["windows_keyring_dependency_available"] is False


@pytest.mark.parametrize("python_version", [(3, 10, 0), (3, 14, 0)])
def test_unsupported_python_reports_local_requirement_only(monkeypatch, python_version):
    monkeypatch.setattr(health.metadata, "version", lambda _name: "synthetic-version")
    monkeypatch.setattr(health.sys, "version_info", python_version)
    assert health.environment_health()["success"] is False


def test_cli_suppresses_metadata_exception_details(monkeypatch, capsys):
    def fail(_name):
        raise RuntimeError("private-path-and-secret")

    monkeypatch.setattr(health.metadata, "version", fail)
    assert health.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result == {"success": False, "category": "local_check_failed", "check_kind": "offline_environment"}
