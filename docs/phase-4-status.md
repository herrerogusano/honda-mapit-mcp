# Phase 4 status

Status: **IN PROGRESS / IMPLEMENTATION ACCEPTED**. The optional live gate is
**PENDING**.

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

## Pending gate and limitations

The live gate is blocked until the supervisor supplies the required
`OPENAI_API_KEY` and `MAPIT_AGENT_MODEL` process configuration. No values are
recorded in this status or repository. The gate has not been run and Phase 4
must not be marked completed from offline evidence alone.

The evaluator's unsupported-claim policy is a versioned lexical denylist. It
intentionally rejects concrete units, realtime wording, and completeness
synonyms even when negated or called unconfirmed; it is not universal semantic
understanding. The synthetic dataset and tests pin the known contamination
regressions. See the [Phase 4 contract](phase-4-agent-contracts.md),
[evaluator](../scripts/evaluate_agent_dataset.py), and [live gate](../scripts/smoke_agent_phase4.py).
