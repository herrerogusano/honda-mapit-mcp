from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from mapit.agent import (
    AgentAdapterError,
    AgentAnswer,
    AgentRunOutcome,
    build_agent_prompt,
    build_child_env,
    build_mcp_server_params,
    capture_used_tool_names,
    run_agent_once,
)


def test_agent_answer_is_strict_and_prompt_has_host_context():
    answer = AgentAnswer(answer="ok", caveats=[], needs_clarification=False)
    assert answer.answer == "ok"
    with pytest.raises(Exception):
        AgentAnswer(answer="ok", caveats=[], needs_clarification=False, extra="secret")
    prompt = build_agent_prompt(
        "status?",
        now=datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc),
    )
    assert "2026-09-28" in prompt
    assert "status?" in prompt
    assert "MAPIT" in prompt


def test_child_environment_is_minimal_and_excludes_provider_secrets():
    env = build_child_env(
        {
            "PATH": "safe-path",
            "PYTHONPATH": "safe-pythonpath",
            "OPENAI_API_KEY": "secret-key",
            "MAPIT_AGENT_MODEL": "secret-model",
            "MAPIT_EMAIL": "user@example.invalid",
            "MAPIT_PASSWORD": "secret-password",
            "HTTPS_PROXY": "http://proxy-secret",
            "OTEL_EXPORTER_OTLP_HEADERS": "secret-trace",
        }
    )
    assert env == {"PATH": "safe-path"}
    params = build_mcp_server_params(repository_dir="C:/repo", parent_env=env)
    assert params["command"]
    assert params["args"] == ["-m", "mapit.mcp_server"]
    assert params["cwd"].replace("\\", "/") == "C:/repo"
    assert params["env"]["PYTHONPATH"].replace("\\", "/") == "C:/repo/src"
    assert "OPENAI_API_KEY" not in params["env"]


def test_tool_names_are_derived_from_run_items_and_unknown_is_redacted():
    class Item:
        type = "tool_call_item"

        def __init__(self, name):
            self.tool_name = name

    class Result:
        new_items = [Item("get_vehicle_status"), Item("get_vehicle_status"), Item("delete_everything")]

    assert capture_used_tool_names(Result()) == ("get_vehicle_status", "unknown_tool")


class _FakeServer:
    def __init__(self):
        self.entered = False
        self.exited = False

    async def __aenter__(self):
        self.entered = True
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.exited = True


class _FakeSDK:
    class RunConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class Agent:
        pass

    class Runner:
        pass

    class MCPServerStdio:
        pass


def test_run_agent_injected_sdk_uses_limits_tracing_off_and_closes_context():
    captured = {}
    server = _FakeServer()

    def server_factory(params):
        captured["params"] = params
        return server

    def agent_factory(**kwargs):
        captured["agent"] = kwargs
        return object()

    class Item:
        type = "tool_call_item"
        tool_name = "get_vehicle_status"

    class Result:
        final_output = {"answer": "safe in memory", "caveats": ["read-only"], "needs_clarification": False}
        new_items = [Item()]

    class Runner:
        @staticmethod
        async def run(agent, prompt, *, max_turns, run_config):
            captured["max_turns"] = max_turns
            captured["run_config"] = run_config
            return Result()

    outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model", "OPENAI_TRACING": "1"},
            sdk=_FakeSDK,
            mcp_server_factory=server_factory,
            agent_factory=agent_factory,
            runner=Runner,
        )
    )

    assert outcome.success is True
    assert outcome.answer is not None
    assert outcome.used_tool_names == ("get_vehicle_status",)
    assert outcome.category is None
    assert server.entered and server.exited
    assert captured["max_turns"] == 6
    assert captured["run_config"].kwargs == {"tracing_disabled": True}
    assert "OPENAI_API_KEY" not in captured["params"]["env"]
    assert "MAPIT_AGENT_MODEL" not in captured["params"]["env"]


def test_run_agent_timeout_and_cancellation_close_mcp_context():
    class Runner:
        mode = "timeout"

        @staticmethod
        async def run(*args, **kwargs):
            if Runner.mode == "cancel":
                raise asyncio.CancelledError
            await asyncio.sleep(1)

    for mode, expected in (("timeout", "agent_timeout"), ("cancel", "agent_cancelled")):
        Runner.mode = mode
        server = _FakeServer()
        outcome = asyncio.run(
            run_agent_once(
                "status?",
                env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
                sdk=_FakeSDK,
                mcp_server_factory=lambda params, server=server: server,
                agent_factory=lambda **kwargs: object(),
                runner=Runner,
                timeout_seconds=0.01,
            )
        )
        assert outcome.success is False
        assert outcome.category == expected
        assert server.entered and server.exited


def test_missing_live_configuration_fails_before_sdk_import(monkeypatch):
    monkeypatch.setattr("mapit.agent._load_agents_sdk", lambda: (_ for _ in ()).throw(AgentAdapterError("secret")))
    outcome = asyncio.run(run_agent_once("status?", env={}))
    assert outcome == AgentRunOutcome(False, None, (), "configuration_missing")


def test_missing_agents_sdk_is_a_safe_category(monkeypatch):
    monkeypatch.setattr(
        "mapit.agent._load_agents_sdk",
        lambda: (_ for _ in ()).throw(AgentAdapterError("agent_sdk_missing")),
    )
    outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
        )
    )
    assert outcome == AgentRunOutcome(False, None, (), "agent_sdk_missing")


def test_invalid_agent_output_is_redacted():
    class Result:
        final_output = {"answer": "", "caveats": [], "needs_clarification": False}
        new_items = []

    class Runner:
        @staticmethod
        async def run(*args, **kwargs):
            return Result()

    outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
            sdk=_FakeSDK,
            mcp_server_factory=lambda params: _FakeServer(),
            agent_factory=lambda **kwargs: object(),
            runner=Runner,
        )
    )
    assert outcome.success is False
    assert outcome.category == "agent_run_failed"


def test_mcp_start_and_close_failures_are_distinguished_without_details():
    class BrokenEnter:
        async def __aenter__(self):
            raise RuntimeError("private start detail")

        async def __aexit__(self, *args):
            raise AssertionError("must not run after failed enter")

    start_outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
            sdk=_FakeSDK,
            mcp_server_factory=lambda params: BrokenEnter(),
        )
    )
    assert start_outcome.category == "mcp_start_failed"

    class BrokenExit(_FakeServer):
        async def __aexit__(self, *args):
            self.exited = True
            raise RuntimeError("private close detail")

    close_outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
            sdk=_FakeSDK,
            mcp_server_factory=lambda params: BrokenExit(),
            agent_factory=lambda **kwargs: object(),
            runner=type("Runner", (), {"run": staticmethod(async_def_run_result)}),
        )
    )
    assert close_outcome.category == "mcp_close_failed"


def test_host_timeout_covers_blocked_context_enter_and_exit():
    class BlockingEnter:
        async def __aenter__(self):
            await asyncio.sleep(1)
            return self

        async def __aexit__(self, *args):
            raise AssertionError("enter never completed")

    enter_outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
            sdk=_FakeSDK,
            mcp_server_factory=lambda params: BlockingEnter(),
            timeout_seconds=0.01,
        )
    )
    assert enter_outcome.category == "agent_timeout"

    class BlockingExit(_FakeServer):
        async def __aexit__(self, *args):
            self.exited = True
            await asyncio.sleep(1)

    exit_outcome = asyncio.run(
        run_agent_once(
            "status?",
            env={"OPENAI_API_KEY": "key", "MAPIT_AGENT_MODEL": "model"},
            sdk=_FakeSDK,
            mcp_server_factory=lambda params: BlockingExit(),
            agent_factory=lambda **kwargs: object(),
            runner=type("Runner", (), {"run": staticmethod(async_def_run_result)}),
            timeout_seconds=0.01,
        )
    )
    assert exit_outcome.category == "agent_timeout"


async def async_def_run_result(*args, **kwargs):
    class Result:
        final_output = {"answer": "ok", "caveats": [], "needs_clarification": False}
        new_items = []

    return Result()
