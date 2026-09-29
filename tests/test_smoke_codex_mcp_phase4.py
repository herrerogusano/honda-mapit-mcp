from __future__ import annotations

import json

from scripts import smoke_codex_mcp_phase4 as smoke


def _events(
    *,
    status: str = "completed",
    error=None,
    tool: str = "get_vehicle_status",
    server: str = "mapit-local",
    extra_item: dict | None = None,
    answer: str = '{"success":true,"grounded":true,"safe":true}',
) -> str:
    events = [
        json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "mcp_tool_call",
                    "id": "call-1",
                    "server": server,
                    "tool": tool,
                    "status": status,
                    "error": error,
                    "arguments": {},
                    "result": {"status": "private"},
                },
            }
        )
    ]
    if extra_item is not None:
        events.append(json.dumps({"type": "item.completed", "item": extra_item}))
    events.append(
        json.dumps(
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": answer},
            }
        )
    )
    return "\n".join(events)


def test_completed_null_error_is_accepted_and_output_is_redacted():
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def fake_runner(argv, env):
        calls.append((tuple(argv), dict(env)))
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(), "raw private stderr")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["success"] is True
    assert result["mcp_call_ok"] is True
    assert result["final_safe"] is True
    assert "private" not in json.dumps(result)
    assert calls[1][0][: len(smoke.EXEC_COMMAND_PREFIX)] == smoke.EXEC_COMMAND_PREFIX
    assert calls[1][0][-1] == smoke.PROMPT


def test_mcp_error_is_rejected_without_leaking_error_text():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(error={"message": "private secret"}), "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["success"] is False
    assert result["category"] == "mcp_status_failed"
    assert "private" not in json.dumps(result)


def test_non_completed_mcp_status_is_rejected():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(status="failed"), "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["success"] is False
    assert result["category"] == "mcp_status_failed"


def test_completed_action_item_is_rejected_even_with_valid_mcp_call():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(extra_item={"type": "command_execution", "command": "private"}), "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["success"] is False
    assert result["category"] == "unexpected_mcp_call"


def test_reasoning_item_is_inert_and_allowed():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(extra_item={"type": "reasoning", "text": "private"}), "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["success"] is True


def test_wrong_server_or_tool_is_rejected():
    for kwargs in ({"server": "other-server"}, {"tool": "get_distance"}):
        def fake_runner(argv, env, kwargs=kwargs):
            if tuple(argv) == smoke.LOGIN_COMMAND:
                return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
            return smoke.ProcessResult(0, _events(**kwargs), "")

        result = smoke.run_codex_mcp_phase4_gate(fake_runner)
        assert result["success"] is False
        assert result["category"] == "unexpected_mcp_call"


def test_real_event_completion_contract_requires_tool_server_and_null_error():
    assert smoke.validate_mcp_call(
        {"tool": "get_vehicle_status", "server": "mapit-local", "status": "completed", "error": None}
    ) is True
    assert smoke.validate_mcp_call(
        {"tool": "get_vehicle_status", "server": "other", "status": "completed", "error": None}
    ) is False


def test_login_required_prevents_mcp_execution():
    commands = []

    def fake_runner(argv, env):
        commands.append(tuple(argv))
        return smoke.ProcessResult(0, "not logged in", "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["category"] == "login_required"
    assert commands == [smoke.LOGIN_COMMAND]


def test_child_environment_removes_provider_and_mapit_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "provider-secret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "provider-secret")
    monkeypatch.setenv("MAPIT_EMAIL", "email-secret")
    monkeypatch.setenv("MAPIT_PASSWORD", "password-secret")
    monkeypatch.setenv("hTtP_PrOxY", "proxy-secret")
    monkeypatch.setenv("HTTPS_PROXY", "proxy-secret")
    monkeypatch.setenv("ALL_PROXY", "proxy-secret")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.invalid")
    monkeypatch.setenv("ANTHROPIC_API_TOKEN", "provider-secret")
    monkeypatch.setenv("CODEX_HOME", "codex-config")
    seen = []

    def fake_runner(argv, env):
        seen.append(dict(env))
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(), "")

    smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert seen
    for env in seen:
        assert "OPENAI_API_KEY" not in env
        assert "ANTHROPIC_API_KEY" not in env
        assert "MAPIT_EMAIL" not in env
        assert "MAPIT_PASSWORD" not in env
        assert "hTtP_PrOxY" not in env
        assert "HTTPS_PROXY" not in env
        assert "ALL_PROXY" not in env
        assert "OPENAI_BASE_URL" not in env
        assert "ANTHROPIC_API_TOKEN" not in env
        assert env["CODEX_HOME"] == "codex-config"


def test_final_response_requires_all_three_true_booleans():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(0, _events(answer='{"success":true,"grounded":true,"safe":false}'), "")

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["category"] == "final_response_invalid"


def test_final_response_rejects_private_extra_field():
    def fake_runner(argv, env):
        if tuple(argv) == smoke.LOGIN_COMMAND:
            return smoke.ProcessResult(0, "Logged in using ChatGPT", "")
        return smoke.ProcessResult(
            0,
            _events(answer='{"success":true,"grounded":true,"safe":true,"private":"secret"}'),
            "",
        )

    result = smoke.run_codex_mcp_phase4_gate(fake_runner)
    assert result["category"] == "final_response_invalid"
    assert "secret" not in json.dumps(result)
