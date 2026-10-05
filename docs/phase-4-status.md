# Phase 4 status

Status: **COMPLETED** on 2026-09-29.

## Delivered

- Lazy, injectable Agents SDK adapter using one bounded read-only agent run and
  one `MCPServerStdio` child.
- Strict structured answer model, actual tool-use capture, tracing disabled,
  six-turn limit, 60-second lifecycle timeout, safe error categories, and
  child-environment isolation.
- Deterministic, network-free evaluator and synthetic dataset covering all six
  Phase 4 contract classes.
- Safe bounded Agents SDK gate and a separate subscription-backed Codex-to-local
  MCP gate; neither persists or prints answers, prompts, arguments, results,
  usage, identifiers, metrics, or private MAPIT data.

## Verification

- Offline suite at implementation acceptance: `291 passed`; current suite,
  including the Codex smoke regressions and hardening, is `302 passed`.
- Evaluator dataset: `12/12` cases passed.
- `compileall` and `git diff --check` passed.
- Clean environment installation of the `test`, `realtime`, and `agent`
  extras was verified, including dependency compatibility.

### Direct Codex E2E evidence (2026-09-29)

- The Codex CLI was authenticated with ChatGPT, not an API key.
- `gpt-6-sol` with medium reasoning launched the global `mapit-local` stdio MCP.
- The saved MAPIT session was valid.
- The agent selected `get_vehicle_status` exactly once; the MCP event completed
  with a null error and the agent returned the required grounded/safe success
  contract.
- Only safe booleans and tool/status metadata were printed. No vehicle state,
  dates, coordinates, addresses, IDs, locations, arguments, results, tokens, or
  MCP payloads were printed or persisted.
- The Phase 1 and Phase 2 live smoke scripts also passed immediately before the
  E2E run.
- The final bounded smoke output was exactly the following safe allowlisted
  metadata:

  ```json
  {"success":true,"logged_in":true,"mcp_call_ok":true,"final_safe":true,"category":"success","model":"gpt-6-sol","tool_name":"get_vehicle_status"}
  ```

This path consumes the signed-in Codex subscription allowance. It does not use
`OPENAI_API_KEY` or create separately billed OpenAI API usage.

## Limitations retained

Some Codex E2E attempts selected `get_distance` exactly once with invalid
model-generated arguments, so those tool calls failed before useful grounding;
this was model argument variation, not an MCP failure. A separate manual
attempt completed `get_distance` with the correct arguments. The reusable smoke
therefore tests the deterministic no-argument `get_vehicle_status` path, while
the offline dataset covers analytics tool selection and argument normalization.
Its parser still rejects non-null errors or any other status. The offline
dataset remains the evidence for analytics tool selection and argument
normalization; the bounded live gate intentionally uses the safer no-argument
status call.

The Agents SDK live gate remains an optional provider-adapter test using
user-supplied `OPENAI_API_KEY` and `MAPIT_AGENT_MODEL`; it was not run and is
not a prerequisite for this completed local Codex-to-MCP phase. No provider
values are recorded in this status or repository.

The evaluator's unsupported-claim policy is a versioned lexical denylist. It
intentionally rejects concrete units, realtime wording, and completeness
synonyms even when negated or called unconfirmed; it is not universal semantic
understanding. The synthetic dataset and tests pin the known contamination
regressions. See the [Phase 4 contract](phase-4-agent-contracts.md),
[evaluator](../scripts/evaluate_agent_dataset.py), and [live gate](../scripts/smoke_agent_phase4.py).
