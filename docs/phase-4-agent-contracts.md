# Phase 4 conversational-agent contracts

Status: approved for implementation.

## Evidence and architecture decision

Official OpenAI documentation supports the Python Agents SDK for a local,
application-owned agent loop and `MCPServerStdio` for a private MCP subprocess.
The local host therefore owns the model call, lifecycle, limits, and approval
policy, while `mapit-mcp` remains the only path to MAPIT tools:

```text
local async host -> Agents SDK -> MCPServerStdio -> mapit-mcp -> services
```

The agent adapter is optional. Importing the base `mapit` package or starting
`mapit-mcp` must not require the Agents SDK or an OpenAI API key.

## Runtime boundary

- Use one focused agent, one MCP subprocess, and one turn. Phase 4 does not add
  handoffs, subagents, memory, sessions, UI, Telegram, AWS, or persistence.
- Start the child with `sys.executable -m mapit.mcp_server`, without a shell,
  from an explicit repository directory.
- Build the child environment from a minimal allowlist. Never pass
  `OPENAI_API_KEY`, model-provider credentials, proxy credentials, or tracing
  credentials to the MCP child. Do not inherit `PYTHONHOME` or `PYTHONPATH`;
  when a source checkout path is needed, set `PYTHONPATH` only to the explicit
  repository `src` directory. MAPIT authentication remains in the approved
  Windows credential store.
- Keep stdout reserved for MCP framing. Public failures are stable categories;
  exception text, prompts, tool results, IDs, coordinates, tokens, and URLs are
  not logged.
- Disable Agents SDK tracing for this private vehicle-data workflow. The normal
  SDK path traces model/tool activity by default, and tool outputs can contain
  location, VIN, registration, route geometry, and dealer details.
- Bound a run to six model turns and a 60-second host timeout covering MCP
  context enter, the model run, and context exit. Cancellation must close the
  MCP context. Cleanup is cooperative: a third-party `__aexit__` that suppresses
  cancellation can delay final return, but the adapter still reports a timeout
  and never starts a second agent run.
- Require a non-empty `OPENAI_API_KEY` and an explicitly configured
  `MAPIT_AGENT_MODEL` only at live-run time. Read them from the process
  environment; never persist or echo either value.

## Tool-use and answer contract

The prompt must require the agent to:

- use MCP tools for MAPIT facts and never answer such facts from prior model
  knowledge;
- prefer the four analytics tools over downloading and calculating from large
  route lists;
- use only capabilities exposed by the ten current read-only tools;
- preserve `metric_unit=mapit_native_unconfirmed` and
  `completeness=unverified` instead of claiming kilometres, km/h, or complete
  history;
- ask for clarification when a requested period lacks a deterministic date
  range, using the host-supplied current date and timezone;
- state when a capability is unavailable or a tool result is partial/error;
- treat “where is the bike?” as latest Core vehicle status only, not Phase 3
  realtime state, and never imply realtime freshness.

The model returns a strict structured object with `answer`, `caveats`, and
`needs_clarification`. The host derives `used_tool_names` from actual run items;
the model does not self-report its calls.

## Dependency decision

Phase 4 uses the optional `openai-agents==0.22.3` package. Its current metadata
requires `websockets>=15,<17`, so the project realtime extra must use the same
compatible range and be verified in a clean environment with the agent and
realtime extras installed together. This is a packaging compatibility change,
not a change to the Phase 3 wire contract.

## Deterministic offline evaluation

The mandatory gate is model-free and network-free. A versioned synthetic
dataset contains at least two cases in each class:

1. direct single-tool questions;
2. multi-tool questions;
3. period comparisons;
4. ambiguous periods requiring clarification;
5. unavailable capabilities;
6. MCP/tool errors or partial results.

Each case declares allowed/required/forbidden tool names, normalized argument
constraints, required caveats, and unsupported claims. The evaluator scores a
synthetic run record rather than exact answer wording and fails closed on
undeclared tools, missing grounding, hidden errors, unsupported unit/history or
realtime claims, excessive calls, or invalid structured output. Fixtures contain
no real vehicle/account/location data.

Tool-result failures use exact normalized caveat markers: `tool_error` for an
error result and `partial_result` for a partial result. Substrings such as
`error-free`, `No error`, or `partial-free` do not satisfy the marker. The
evaluator is deliberately conservative: any supported concrete unit mention
(`kph`, miles, metres, `m/s`, and similar forms) is rejected, including when it
is negated or called unconfirmed. The only accepted unit form is the abstract
metadata marker `metric_unit=mapit_native_unconfirmed`. Any mention of
realtime/real-time/tiempo real is rejected, including an unavailable claim;
capability unavailability must be stated without that term. Any route,
history, data, record, or records completeness claim containing complete,
full, all, exhaustive, comprehensive, every/each route, coverage of all
routes, 100% of routes, or no route missing/omitted is rejected, including
negated or unconfirmed wording. The same lexical policy covers the documented
Spanish equivalents (for example `todos los recorridos`, `todas las rutas`,
`ninguna ruta falta`, and `historial completo`). This is a versioned lexical
denylist, not universal semantic understanding; the synthetic dataset and
tests pin the known contamination regressions. The only accepted completeness
form is the abstract metadata marker `completeness=unverified`.

## Live gate

The live agent gate is optional and never runs in CI. It requires the saved
MAPIT session plus user-supplied `OPENAI_API_KEY` and `MAPIT_AGENT_MODEL`, runs
one bounded read-only question, disables tracing, and prints only booleans,
allowlisted categories, and tool names. It must not print or persist the model
answer, prompt, tool arguments/results, usage, identifiers, metrics, or private
MAPIT data.

## Exit criteria

- optional local Agents SDK adapter connects to `mapit-mcp` over stdio;
- strict structured output and actual tool-call capture;
- deterministic 12-or-more-case offline suite passes;
- dependency compatibility and subprocess environment isolation are tested;
- bounded live gate is either successful or explicitly recorded as pending its
  credential/model authorization gate.
