from __future__ import annotations

import asyncio
import json
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mapit.codex_cli_backend import (
    EXEC_COMMAND,
    LOGIN_COMMAND,
    CodexCliBackend,
    CodexProcessResult,
    build_codex_child_env,
)

REPOSITORY_DIR = Path.cwd().resolve()


def _jsonl(*, calls=(), answer=None, items=(), turn=True):
    events = []
    for call in calls:
        events.append(json.dumps({"type": "item.completed", "item": call}))
    events.extend(json.dumps({"type": "item.completed", "item": item}) for item in items)
    if answer is not None:
        events.append(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(answer)}}))
    if turn:
        events.append(json.dumps({"type": "turn.completed"}))
    return "\n".join(events)


def _call(*, tool="get_vehicle_status", server="mapit-local", status="completed", error=None):
    return {
        "type": "mcp_tool_call",
        "id": "synthetic-call",
        "server": server,
        "tool": tool,
        "status": status,
        "error": error,
        "arguments": {},
        "result": {"private": "never returned"},
    }


class FakeRunner:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []
        self.cleaned = 0

    async def run(self, argv, *, stdin_text, env, cwd, timeout_seconds):
        self.calls.append((tuple(argv), stdin_text, dict(env), cwd, timeout_seconds))
        output = self.outputs.pop(0)
        if isinstance(output, BaseException):
            raise output
        return output

    async def cleanup(self):
        self.cleaned += 1


def _backend(runner):
    return CodexCliBackend(runner=runner, parent_env={"PATH": "safe", "OPENAI_API_KEY": "secret"}, repository_dir=REPOSITORY_DIR)


def test_command_uses_stdin_no_shell_shape_and_scrubs_environment():
    runner = FakeRunner(
        [
            CodexProcessResult(0, "Logged in using ChatGPT"),
            CodexProcessResult(
                0,
                _jsonl(calls=[_call()], answer={"answer": "ok", "caveats": [], "needs_clarification": False}),
            ),
        ]
    )
    result = asyncio.run(_backend(runner).ask("status question"))
    assert result.success is True
    assert result.answer is not None
    assert runner.calls[0][0] == LOGIN_COMMAND
    command = runner.calls[1][0]
    assert command[: len(EXEC_COMMAND)] == EXEC_COMMAND
    assert "--output-schema" in command
    assert runner.calls[1][1] != "status question"
    assert "<untrusted_user_input>" in runner.calls[1][1]
    assert "status question" in runner.calls[1][1]
    assert runner.calls[1][3] != str(REPOSITORY_DIR)
    assert any("features.shell_tool=false" in part for part in command)
    assert any("features.multi_agent=false" in part for part in command)
    assert any("mcp_servers.mapit-local.command" in part and "mapit-local" not in part.split("=", 1)[-1] for part in command)
    assert "OPENAI_API_KEY" not in runner.calls[0][2]
    assert "PYTHONPATH" not in runner.calls[0][2]


def test_effective_config_values_are_typed_toml_and_mcp_is_pinned():
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[_call()], answer={"answer": "ok", "caveats": [], "needs_clarification": False}))])
    asyncio.run(_backend(runner).ask("status"))
    command = runner.calls[1][0]
    config = [command[i + 1] for i, value in enumerate(command[:-1]) if value == "-c"]
    assert all(len(tomllib.loads(value.split("=", 1)[0] + " = " + value.split("=", 1)[1])) == 1 for value in config)
    assert any(value.startswith("features.unified_exec=") for value in config)
    expected_false = {
        "features.shell_tool", "features.unified_exec", "features.multi_agent",
        "features.skill_mcp_dependency_install", "features.apps", "features.browser_use",
        "features.browser_use_external", "features.browser_use_full_cdp_access", "features.code_mode_host",
        "features.computer_use", "features.image_generation", "features.in_app_browser",
        "features.in_app_local_automation",
        "features.remote_plugin", "features.plugins", "features.skill_search",
        "features.view_image", "features.workspace_dependencies", "features.hooks", "features.goals",
    }
    for key in expected_false:
        assert key + "=false" in config
    assert any(value.startswith("mcp_servers.mapit-local.required=") for value in config)
    assert "mcp_servers.mapit-local.tool_timeout_sec=30" in config
    assert "tool_timeout_sec=30" not in config
    env_config = next(value for value in config if value.startswith("mcp_servers.mapit-local.env="))
    parsed_env = tomllib.loads(env_config.split("=", 1)[0] + " = " + env_config.split("=", 1)[1])
    assert parsed_env["mcp_servers"]["mapit-local"]["env"] == {"PYTHONPATH": str(REPOSITORY_DIR / "src")}


def test_prompt_has_injected_host_date_timezone_and_raw_payload_wording():
    prompt = CodexCliBackend._prompt("relative month", now=datetime(2026, 9, 29, 12, tzinfo=timezone.utc))
    assert "2026-09-29" in prompt
    assert "UTC" in prompt
    assert "raw tool payloads" in prompt


def test_login_is_required_before_exec():
    runner = FakeRunner([CodexProcessResult(0, "not logged in")])
    result = asyncio.run(_backend(runner).ask("status"))
    assert result.category == "login_required"
    assert len(runner.calls) == 1


def test_zero_calls_only_succeeds_for_clarification():
    answer = {"answer": "Need a date range.", "caveats": [], "needs_clarification": True}
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(answer=answer))])
    assert asyncio.run(_backend(runner).ask("compare periods")).success is True

    answer["needs_clarification"] = False
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(answer=answer))])
    assert asyncio.run(_backend(runner).ask("status")).category == "no_tool_call"

    started_only = [
        CodexProcessResult(0, "Logged in using ChatGPT"),
        CodexProcessResult(
            0,
            "\n".join(
                [
                    json.dumps({"type": "item.started", "item": _call()}),
                    json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps({"answer": "Need a date.", "caveats": [], "needs_clarification": True})}}),
                    json.dumps({"type": "turn.completed"}),
                ]
            ),
        ),
    ]
    assert asyncio.run(_backend(FakeRunner(started_only)).ask("status")).category == "mcp_status_failed"


@pytest.mark.parametrize(
    "call,category",
    [
        (_call(server="other"), "mcp_status_failed"),
        (_call(tool="unknown"), "mcp_status_failed"),
        (_call(status="failed"), "mcp_status_failed"),
        (_call(error={"private": "secret"}), "mcp_status_failed"),
    ],
)
def test_mcp_calls_are_strictly_allowlisted(call, category):
    runner = FakeRunner(
        [CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[call], answer={"answer": "x", "caveats": [], "needs_clarification": False}))]
    )
    result = asyncio.run(_backend(runner).ask("status"))
    assert result.category == category
    assert "secret" not in repr(result)


def test_max_six_calls_and_unknown_actions_fail_closed():
    calls = [_call() for _ in range(7)]
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=calls, answer={"answer": "x", "caveats": [], "needs_clarification": False}))])
    assert asyncio.run(_backend(runner).ask("status")).category == "too_many_tool_calls"

    for unknown in ("command_execution", "file_change", "web_search"):
        runner = FakeRunner(
            [CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[_call()], items=[{"type": unknown}], answer={"answer": "x", "caveats": [], "needs_clarification": False}))]
        )
        assert asyncio.run(_backend(runner).ask("status")).category == "unexpected_item"


def test_reasoning_is_inert_and_agent_answer_is_exact():
    runner = FakeRunner(
        [
            CodexProcessResult(0, "Logged in using ChatGPT"),
            CodexProcessResult(0, _jsonl(calls=[_call()], items=[{"type": "reasoning", "text": "private"}], answer={"answer": "ok", "caveats": ["safe"], "needs_clarification": False})),
        ]
    )
    result = asyncio.run(_backend(runner).ask("status"))
    assert result.success is True
    assert result.answer.caveats == ["safe"]

    extra = {"answer": "ok", "caveats": [], "needs_clarification": False, "private": "secret"}
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[_call()], answer=extra))])
    assert asyncio.run(_backend(runner).ask("status")).category == "final_response_invalid"

    oversized = {"answer": "x" * 4097, "caveats": [], "needs_clarification": False}
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[_call()], answer=oversized))])
    assert asyncio.run(_backend(runner).ask("status")).category == "final_response_invalid"


def test_jsonl_lifecycle_and_output_limits_fail_closed():
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, "not json")])
    assert asyncio.run(_backend(runner).ask("status")).category == "malformed_jsonl"


def test_lifecycle_ids_unknown_top_level_and_multiple_final_messages_fail_closed():
    call = _call()
    message = {"type": "agent_message", "text": json.dumps({"answer": "ok", "caveats": [], "needs_clarification": False})}
    started = json.dumps({"type": "item.started", "item": call})
    completed = json.dumps({"type": "item.completed", "item": call})
    valid = "\n".join([started, completed, json.dumps({"type": "item.completed", "item": message}), json.dumps({"type": "turn.completed"})])
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, valid)])
    assert asyncio.run(_backend(runner).ask("status")).success is True

    unresolved = "\n".join([started, json.dumps({"type": "turn.completed"})])
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, unresolved)])
    assert asyncio.run(_backend(runner).ask("status")).category == "mcp_status_failed"

    multiple = "\n".join([json.dumps({"type": "item.completed", "item": message})] * 2 + [json.dumps({"type": "turn.completed"})])
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, multiple)])
    assert asyncio.run(_backend(runner).ask("status")).category == "final_response_invalid"

    unknown = json.dumps({"type": "future.lifecycle", "item": {"type": "reasoning"}})
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, unknown)])
    assert asyncio.run(_backend(runner).ask("status")).category == "unexpected_item"
    huge = "x" * (4 * 1024 * 1024 + 1)
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, huge)])
    assert asyncio.run(_backend(runner).ask("status")).category == "output_too_large"
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), CodexProcessResult(0, _jsonl(calls=[_call()], answer={"answer": "x", "caveats": [], "needs_clarification": False}, turn=False))])
    assert asyncio.run(_backend(runner).ask("status")).category == "malformed_jsonl"


def test_timeout_cleanup_and_question_limit():
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), asyncio.TimeoutError()])
    result = asyncio.run(_backend(runner).ask("status"))
    assert result.category == "timeout"
    assert runner.cleaned == 1
    assert asyncio.run(_backend(FakeRunner([])).ask("x" * 4097)).category == "invalid_question"


def test_cancellation_cleanup_is_safe():
    runner = FakeRunner([CodexProcessResult(0, "Logged in using ChatGPT"), asyncio.CancelledError()])
    result = asyncio.run(_backend(runner).ask("status"))
    assert result.category == "cancelled"
    assert runner.cleaned == 1


def test_child_env_allowlist_keeps_codex_home_and_removes_secrets():
    env = build_codex_child_env(
        {
            "PATH": "safe",
            "CODEX_HOME": "config",
            "MAPIT_PASSWORD": "secret",
            "TELEGRAM_BOT_TOKEN": "secret",
            "HTTP_PROXY": "proxy",
            "OPENAI_BASE_URL": "https://secret.invalid",
            "PYTHONPATH": "arbitrary",
        }
    )
    assert env == {"PATH": "safe", "CODEX_HOME": "config"}
