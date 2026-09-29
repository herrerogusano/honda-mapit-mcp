# Phase 4 status

Status: **IN PROGRESS / IMPLEMENTATION ACCEPTED**. A direct Codex-subscription
E2E path is **CONFIRMED**, with one distance-query discrepancy still under
investigation.

## Delivered

- Lazy, injectable Agents SDK adapter using one bounded read-only agent run and
  one `MCPServerStdio` child.
- Strict structured answer model, actual tool-use capture, tracing disabled,
  six-turn limit, 60-second lifecycle timeout, safe error categories, and
  child-environment isolation.
- Deterministic, network-free evaluator and synthetic dataset covering all six
  Phase 4 contract classes.
- Safe bounded live-gate script; it does not persist or print answers, prompts,
  arguments, results, usage, identifiers, metrics, or private MAPIT data.

## Verification

- Offline suite: `291 passed`.
- Evaluator dataset: `12/12` cases passed.
- `compileall` and `git diff --check` passed.
- Clean environment installation of the `test`, `realtime`, and `agent`
  extras was verified, including dependency compatibility.

### Direct Codex E2E (2026-09-29)

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

This path consumes the signed-in Codex subscription allowance. It does not use
`OPENAI_API_KEY` or create separately billed OpenAI API usage.

## Pending investigation and limitations

Two preceding Codex E2E attempts selected `get_distance` exactly once but
reported tool failure. The identical requested period succeeded when invoked
directly through `MapitServices`, and the Phase 1 smoke also completed
`get_distance`. The discrepancy is therefore specific to the Codex-to-MCP
agent path and remains unexplained. Do not mark Phase 4 completed until it is
classified and a distance question passes through that path.

The Agents SDK live gate remains available as an optional provider-adapter test
using user-supplied `OPENAI_API_KEY` and `MAPIT_AGENT_MODEL`. It is no longer a
prerequisite for validating ordinary Codex-to-local-MCP usage and has not been
run. No provider values are recorded in this status or repository.

The evaluator's unsupported-claim policy is a versioned lexical denylist. It
intentionally rejects concrete units, realtime wording, and completeness
synonyms even when negated or called unconfirmed; it is not universal semantic
understanding. The synthetic dataset and tests pin the known contamination
regressions. See the [Phase 4 contract](phase-4-agent-contracts.md),
[evaluator](../scripts/evaluate_agent_dataset.py), and [live gate](../scripts/smoke_agent_phase4.py).
