from __future__ import annotations

import asyncio

from mapit.agent import AgentAnswer, AgentRunOutcome
from scripts import smoke_agent_phase4 as smoke


def test_live_gate_emits_only_safe_success_metadata(monkeypatch):
    async def fake_run(question):
        return AgentRunOutcome(
            True,
            AgentAnswer(answer="private answer", caveats=[], needs_clarification=False),
            ("get_vehicle_status",),
        )

    monkeypatch.setattr(smoke, "run_agent_once", fake_run)
    result = asyncio.run(smoke.perform_agent_phase4_gate())
    assert result == {"success": True, "used_tool_names": ["get_vehicle_status"]}
    assert "private" not in str(result)


def test_live_gate_rejects_no_tool_and_unknown_tool():
    async def fake_run(question):
        return AgentRunOutcome(True, AgentAnswer(answer="hidden", caveats=[], needs_clarification=False), ())

    monkeypatch = None
    # Directly replace the module function for this isolated offline check.
    original = smoke.run_agent_once
    smoke.run_agent_once = fake_run
    try:
        result = asyncio.run(smoke.perform_agent_phase4_gate())
    finally:
        smoke.run_agent_once = original
    assert result == {"success": False, "used_tool_names": [], "category": "no_tool_call"}
