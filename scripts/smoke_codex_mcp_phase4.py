"""Bounded local Codex-to-MCP Phase 4 gate.

The gate is intentionally not run by CI or this module's tests.  It invokes
the installed Codex CLI without a shell, keeps process output in memory, and
prints only an allowlisted status record.  Prompts, tool arguments/results,
dates, metrics, identifiers, and raw errors never leave this process.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]

MODEL = "gpt-6-sol"
TOOL_NAME = "get_vehicle_status"
MCP_SERVER_NAME = "mapit-local"
PROMPT = (
    "Use exactly one read-only MCP call to retrieve the current vehicle status. "
    "Do not call any other tool. Return JSON only with boolean fields success, "
    "grounded, and safe, all true only when the tool result was observed and "
    "the answer is grounded and safe. Do not include the tool result or any "
    "private data."
)

LOGIN_COMMAND = ("codex", "login", "status")
EXEC_COMMAND_PREFIX = (
    "codex",
    "exec",
    "--json",
    "--ephemeral",
    "--ignore-user-config",
    "-s",
    "read-only",
    "-m",
    MODEL,
    "-c",
    "model_reasoning_effort=medium",
    "-c",
    "mcp_servers.mapit-local.command=mapit-mcp",
)

_SAFE_CATEGORIES = frozenset(
    {
        "success",
        "codex_missing",
        "login_required",
        "login_failed",
        "codex_timeout",
        "codex_failed",
        "malformed_jsonl",
        "unexpected_mcp_call",
        "mcp_status_failed",
        "final_response_invalid",
    }
)

_SENSITIVE_EXACT = frozenset(
    {
        "OPENAI_API_KEY",
        "OPENAI_ADMIN_KEY",
        "AZURE_OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "COHERE_API_KEY",
        "MISTRAL_API_KEY",
        "MAPIT_EMAIL",
        "MAPIT_PASSWORD",
        "MAPIT_REFRESH_TOKEN",
        "MAPIT_ID_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_ENDPOINT",
        "OPENAI_API_TOKEN",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_BASE_URL",
        "AZURE_OPENAI_API_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_TOKEN",
        "GOOGLE_API_BASE",
        "GOOGLE_API_ENDPOINT",
        "GOOGLE_API_TOKEN",
        "COHERE_BASE_URL",
        "MISTRAL_BASE_URL",
        "PROVIDER_TOKEN",
    }
)
_PROXY_VARIABLES = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"})
_INERT_ITEM_TYPES = frozenset({"agent_message", "reasoning"})


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[Sequence[str], Mapping[str, str]], ProcessResult]


def scrub_child_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """Return an environment without provider, MAPIT, or cloud credentials."""
    current = dict(os.environ if source is None else source)
    for key in tuple(current):
        upper = key.upper()
        if (
            upper in _SENSITIVE_EXACT
            or upper in _PROXY_VARIABLES
            or upper.endswith("_API_KEY")
            or upper.endswith("_API_TOKEN")
            or upper.startswith("MAPIT_")
            or upper.startswith("AWS_SECRET")
            or upper.startswith("AWS_ACCESS")
        ):
            current.pop(key, None)
    return current


def _run_process(argv: Sequence[str], env: Mapping[str, str]) -> ProcessResult:
    completed = subprocess.run(
        list(argv),
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        env=dict(env),
        cwd=str(ROOT),
        timeout=90,
    )
    return ProcessResult(completed.returncode, completed.stdout, completed.stderr)


def _safe_result(
    *,
    category: str,
    logged_in: bool = False,
    mcp_call_ok: bool = False,
    final_safe: bool = False,
) -> dict[str, object]:
    safe_category = category if category in _SAFE_CATEGORIES else "codex_failed"
    return {
        "success": safe_category == "success",
        "logged_in": bool(logged_in),
        "mcp_call_ok": bool(mcp_call_ok),
        "final_safe": bool(final_safe),
        "category": safe_category,
        "model": MODEL,
        "tool_name": TOOL_NAME,
    }


def _chatgpt_login_ok(result: ProcessResult) -> bool:
    if result.returncode != 0:
        return False
    text = f"{result.stdout}\n{result.stderr}".lower()
    if "chatgpt" not in text:
        return False
    return not any(marker in text for marker in ("not logged", "logged out", "not authenticated"))


def _extract_events(stdout: str) -> list[dict[str, Any]] | None:
    events: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict):
            return None
        events.append(value)
    return events


def validate_mcp_call(
    call: Mapping[str, Any],
    *,
    expected_tool: str = TOOL_NAME,
    expected_server: str = MCP_SERVER_NAME,
) -> bool:
    """Validate only the public completion contract, never inspect its result."""
    return (
        call.get("tool") == expected_tool
        and call.get("server") == expected_server
        and call.get("status") == "completed"
        and "error" in call
        and call.get("error") is None
    )


def _inspect_run(stdout: str) -> tuple[str, bool, bool]:
    events = _extract_events(stdout)
    if events is None:
        return "malformed_jsonl", False, False

    calls: list[Mapping[str, Any]] = []
    final_objects: list[Mapping[str, Any]] = []
    for event in events:
        if event.get("type") == "item.completed":
            item = event.get("item")
            if not isinstance(item, dict):
                return "unexpected_mcp_call", False, False
            item_type = item.get("type")
            if item_type == "mcp_tool_call":
                calls.append(item)
            elif item_type == "agent_message":
                final_objects.append(item)
            elif item_type in _INERT_ITEM_TYPES:
                continue
            else:
                return "unexpected_mcp_call", False, False

    if len(calls) != 1 or calls[0].get("tool") != TOOL_NAME or calls[0].get("server") != MCP_SERVER_NAME:
        return "unexpected_mcp_call", False, False
    if not validate_mcp_call(calls[0]):
        return "mcp_status_failed", False, False

    for item in reversed(final_objects):
        text = item.get("text")
        if not isinstance(text, str):
            continue
        try:
            response = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(response, dict):
            continue
        if set(response) != {"success", "grounded", "safe"}:
            continue
        if all(type(response[name]) is bool and response[name] is True for name in response):
            return "success", True, True
    return "final_response_invalid", True, False


def run_codex_mcp_phase4_gate(runner: Runner | None = None) -> dict[str, object]:
    """Run the local Codex gate with injectable process execution for tests."""
    execute = _run_process if runner is None else runner
    env = scrub_child_environment()
    try:
        login = execute(LOGIN_COMMAND, env)
    except FileNotFoundError:
        return _safe_result(category="codex_missing")
    except subprocess.TimeoutExpired:
        return _safe_result(category="codex_timeout")
    except Exception:
        return _safe_result(category="login_failed")
    if not _chatgpt_login_ok(login):
        category = "login_failed" if login.returncode != 0 else "login_required"
        return _safe_result(category=category)

    try:
        run = execute((*EXEC_COMMAND_PREFIX, PROMPT), env)
    except FileNotFoundError:
        return _safe_result(category="codex_missing", logged_in=True)
    except subprocess.TimeoutExpired:
        return _safe_result(category="codex_timeout", logged_in=True)
    except Exception:
        return _safe_result(category="codex_failed", logged_in=True)
    if run.returncode != 0:
        return _safe_result(category="codex_failed", logged_in=True)
    category, mcp_ok, final_ok = _inspect_run(run.stdout)
    return _safe_result(
        category=category,
        logged_in=True,
        mcp_call_ok=mcp_ok,
        final_safe=final_ok,
    )


def main() -> int:
    try:
        result = run_codex_mcp_phase4_gate()
    except KeyboardInterrupt:
        result = _safe_result(category="codex_failed")
    except Exception:
        result = _safe_result(category="codex_failed")
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
