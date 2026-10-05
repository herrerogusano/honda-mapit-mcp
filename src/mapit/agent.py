"""Optional local conversational-agent adapter for the read-only MCP server.

The Agents SDK is deliberately imported only inside the live execution path.
Importing :mod:`mapit` or starting the MCP server must remain SDK- and
credential-free.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_TURNS = 6
AGENT_TIMEOUT_SECONDS = 60.0

READ_ONLY_TOOL_NAMES = frozenset(
    {
        "get_vehicle_status",
        "get_vehicle_details",
        "list_routes",
        "get_route_detail",
        "get_distance",
        "compare_distance_periods",
        "get_route_statistics",
        "get_distance_breakdown",
        "get_route_extremes",
        "compare_route_periods",
    }
)

_CHILD_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "PYTHONIOENCODING",
        "LANG",
        "LC_ALL",
    }
)

AGENT_INSTRUCTIONS = """You are a focused, read-only Honda MAPIT assistant.

Use MCP tools for every MAPIT fact; never answer account, vehicle, route, or
distance facts from prior model knowledge. Use the four analytics tools for
analytics instead of downloading a large route list and calculating it in the
agent. Only use capabilities exposed by the current read-only MCP tools.

Prefer an explicitly returned `*_km` field for user-facing distance. Those fields
are derived by dividing MAPIT's native distance by 1000 under a UI-correlated
meter interpretation; state that this interpretation is unconfirmed when it
matters. Never relabel a native field as kilometres, and never infer km/h,
complete history, or GPS accuracy. Preserve `metric_unit=mapit_native_unconfirmed`
and `completeness=unverified`. If an older result has no `*_km` companion, keep
its distance unit unlabelled rather than guessing.

For route quality, use only `has_inferred_segments` and the accompanying
`inference_quality_status`/warning. A true value means at least one inspected
LineString is marked inferred, not that it follows real streets. False means no
inspected LineString is marked inferred; it does not guarantee GPS accuracy.
Null/unknown must remain unknown. `starts_at_last_known` is a separate hint,
never proof of an inferred segment or GPS quality.
Ask for clarification when a period is not a deterministic date range, using
the host-supplied current date and timezone. State when a capability is
unavailable or a tool result is partial/error. For “where is the bike?”, use
latest Core vehicle status only; do not use or imply Phase 3 realtime
freshness. Return only the strict structured answer schema.
"""


class AgentAdapterError(RuntimeError):
    """Stable public category for optional agent-adapter failures."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class AgentAnswer(BaseModel):
    """Strict model output; raw output is never printed by the adapter."""

    model_config = ConfigDict(extra="forbid", strict=True)

    answer: str = Field(min_length=1)
    caveats: list[str] = Field(default_factory=list)
    needs_clarification: bool

    @field_validator("answer")
    @classmethod
    def _nonblank_answer(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("answer must not be blank")
        return value


@dataclass(frozen=True)
class AgentRunOutcome:
    """In-memory result with only stable metadata safe for callers to inspect."""

    success: bool
    answer: AgentAnswer | None
    used_tool_names: tuple[str, ...]
    category: str | None = None


def build_child_env(
    parent: Mapping[str, str] | None = None,
    *,
    repository_dir: str | Path | None = None,
) -> dict[str, str]:
    """Copy only harmless process settings to the MCP child.

    In particular, provider credentials, MAPIT credentials, proxy variables,
    model selection, and tracing settings are intentionally not inherited.
    """
    source = dict(os.environ if parent is None else parent)
    child = {
        key: value
        for key, value in source.items()
        if key.upper() in _CHILD_ENV_ALLOWLIST
        and isinstance(value, str)
    }
    if repository_dir is not None:
        child["PYTHONPATH"] = str(Path(repository_dir) / "src")
    return child


def build_mcp_server_params(
    *,
    repository_dir: str | Path | None = None,
    parent_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the explicit no-shell MCP subprocess parameters."""
    root = Path(repository_dir) if repository_dir is not None else Path(__file__).resolve().parents[2]
    return {
        "command": sys.executable,
        "args": ["-m", "mapit.mcp_server"],
        "env": build_child_env(parent_env, repository_dir=root),
        "cwd": str(root),
    }


def build_agent_prompt(question: str, *, now: datetime | None = None) -> str:
    """Add host-owned date/timezone context without exposing credentials."""
    if not isinstance(question, str) or not question.strip():
        raise ValueError("question must not be blank")
    instant = (now or datetime.now().astimezone())
    timezone_name = getattr(instant.tzinfo, "key", None) or str(instant.tzinfo or "local")
    host_context = f"Host current date: {instant.date().isoformat()}; timezone: {timezone_name}."
    return f"{AGENT_INSTRUCTIONS}\n\n{host_context}\n\nUser question:\n{question.strip()}"


def _load_agents_sdk() -> Any:
    try:
        from agents import Agent, RunConfig, Runner
        from agents.mcp import MCPServerStdio
    except ImportError:
        raise AgentAdapterError("agent_sdk_missing") from None
    return type(
        "AgentsSDK",
        (),
        {"Agent": Agent, "RunConfig": RunConfig, "Runner": Runner, "MCPServerStdio": MCPServerStdio},
    )


def capture_used_tool_names(run_result: Any) -> tuple[str, ...]:
    """Derive tool names from SDK run items, never from model self-reporting."""
    names: list[str] = []
    for item in getattr(run_result, "new_items", ()) or ():
        if getattr(item, "type", None) != "tool_call_item":
            continue
        name = getattr(item, "tool_name", None)
        if not isinstance(name, str) or not name:
            raw_item = getattr(item, "raw_item", None)
            name = raw_item.get("name") if isinstance(raw_item, Mapping) else getattr(raw_item, "name", None)
        safe_name = name if isinstance(name, str) and name in READ_ONLY_TOOL_NAMES else "unknown_tool"
        if safe_name not in names:
            names.append(safe_name)
    return tuple(names)


def _outcome(category: str, *, tools: tuple[str, ...] = ()) -> AgentRunOutcome:
    return AgentRunOutcome(False, None, tools, category)


async def run_agent_once(
    question: str,
    *,
    env: Mapping[str, str] | None = None,
    repository_dir: str | Path | None = None,
    sdk: Any | None = None,
    mcp_server_factory: Callable[[dict[str, Any]], Any] | None = None,
    agent_factory: Callable[..., Any] | None = None,
    runner: Any | None = None,
    run_config_factory: Callable[..., Any] | None = None,
    now: datetime | None = None,
    timeout_seconds: float = AGENT_TIMEOUT_SECONDS,
) -> AgentRunOutcome:
    """Run one bounded agent turn with injectable SDK boundaries for tests."""
    source_env = dict(os.environ if env is None else env)
    if not source_env.get("OPENAI_API_KEY") or not source_env.get("MAPIT_AGENT_MODEL"):
        return _outcome("configuration_missing")
    try:
        prompt = build_agent_prompt(question, now=now)
    except (TypeError, ValueError):
        return _outcome("invalid_question")

    if sdk is None:
        try:
            sdk = _load_agents_sdk()
        except AgentAdapterError as exc:
            return _outcome(exc.category)
        except Exception:
            return _outcome("agent_sdk_missing")
    params = build_mcp_server_params(repository_dir=repository_dir, parent_env=source_env)
    server_factory = mcp_server_factory or sdk.MCPServerStdio
    selected_agent_factory = agent_factory or sdk.Agent
    selected_runner = runner or sdk.Runner
    selected_run_config_factory = run_config_factory or sdk.RunConfig
    try:
        server = server_factory(params)
    except Exception:
        return _outcome("mcp_start_failed")

    tool_names: tuple[str, ...] = ()
    entered = False
    try:
        limit = min(AGENT_TIMEOUT_SECONDS, max(0.0, float(timeout_seconds)))
    except (TypeError, ValueError, OverflowError):
        return _outcome("invalid_timeout")
    answer: AgentAnswer | None = None
    run_outcome: AgentRunOutcome | None = None
    try:
        async with asyncio.timeout(limit) as timeout_scope:
            async with server:
                entered = True
                try:
                    agent = selected_agent_factory(
                        name="Honda MAPIT read-only assistant",
                        instructions=AGENT_INSTRUCTIONS,
                        mcp_servers=[server],
                        output_type=AgentAnswer,
                        model=source_env["MAPIT_AGENT_MODEL"],
                    )
                    run_config = selected_run_config_factory(tracing_disabled=True)
                    result = await selected_runner.run(
                        agent,
                        prompt,
                        max_turns=MAX_TURNS,
                        run_config=run_config,
                    )
                    tool_names = capture_used_tool_names(result)
                    answer = AgentAnswer.model_validate(getattr(result, "final_output", None))
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    raise
                except Exception:
                    run_outcome = _outcome("agent_run_failed", tools=tool_names)
        if timeout_scope.expired():
            return _outcome("agent_timeout", tools=tool_names)
        if run_outcome is not None:
            return run_outcome
        if answer is None:
            return _outcome("agent_run_failed", tools=tool_names)
        return AgentRunOutcome(True, answer, tool_names)
    except asyncio.TimeoutError:
        return _outcome("agent_timeout", tools=tool_names)
    except asyncio.CancelledError:
        return _outcome("agent_cancelled", tools=tool_names)
    except Exception:
        return _outcome("mcp_close_failed" if entered else "mcp_start_failed", tools=tool_names)


__all__ = [
    "AGENT_INSTRUCTIONS",
    "AGENT_TIMEOUT_SECONDS",
    "MAX_TURNS",
    "READ_ONLY_TOOL_NAMES",
    "AgentAdapterError",
    "AgentAnswer",
    "AgentRunOutcome",
    "build_agent_prompt",
    "build_child_env",
    "build_mcp_server_params",
    "capture_used_tool_names",
    "run_agent_once",
]
