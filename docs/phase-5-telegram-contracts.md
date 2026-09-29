# Phase 5 private Telegram prototype contract

Status: **ACTIVE — offline prototype implemented; external gate pending**.

Phase 5 is a local, private prototype boundary around the completed read-only
MAPIT/MCP and Codex-to-MCP phases. “No polling” in this phase means no **live
polling**: the implementation and tests use synthetic updates and injected
fakes only. It is not authorization to contact Telegram, create a bot, send a
message, or deploy a webhook.

## Scope and non-goals

- Polling is local and sequential: one bounded cycle at a time, one update
  handled at a time, with no webhook, worker pool, queue, database, or durable
  state.
- MAPIT remains read-only. The prototype may use only the existing allowlisted
  read-only `mapit-local` MCP tools.
- The only future Telegram write in this contract is `sendMessage`. No other
  Telegram method, bot-management operation, chat administration, or outbound
  side effect is in scope.
- No real bot token, chat ID, user ID, message, MAPIT credential, device ID, or
  location is stored, printed, or included in fixtures.
- `python-telegram-bot==22.8` is an approved optional runtime decision, but no
  dependency or functional Telegram adapter is added in this phase's contract
  step.

## Numeric and lifecycle allowlist

All numeric configuration is fail-closed. Values not in this table, values of
the wrong type, and non-finite values are rejected before any backend call:

| Field | Fixed value or bound |
| --- | --- |
| `max_updates_per_cycle` | `1` |
| `poll_timeout_seconds` | `25` |
| `agent_timeout_seconds` | `60` |
| `agent_max_turns` | `6` |
| `max_message_chars` | `4096` |
| `max_answer_chars` | `4096` |
| `max_jsonl_line_bytes` | `1048576` |

Polling is sequential and bounded by these values. There is no retry loop for
Telegram writes, no background thread, and no persistence of an update offset.
The prototype must stop on malformed input, unknown numeric values, unknown
methods, or an exceeded limit.

## Codex CLI backend

`CodexCliBackend` is the only approved agent backend for this prototype. It
requires `codex login status` to report a ChatGPT subscription login and does
not use an API key. It starts Codex without a shell, writes the bounded prompt
to stdin, captures stdout/stderr only in memory, and uses this fixed command
policy. Codex runs from a newly-created empty temporary directory with
`--skip-git-repo-check`; the repository is only an explicit working directory
for the one local MCP subprocess and is never the Codex process cwd:

```text
codex exec --json --ephemeral --ignore-user-config --ignore-rules
  -s read-only -m gpt-6-sol -c model_reasoning_effort="medium"
  --strict-config --skip-git-repo-check --output-schema <temporary AgentAnswer schema>
  -c features.shell_tool=false -c features.unified_exec=false
  -c web_search="disabled"
  -c features.multi_agent=false
  -c features.skill_mcp_dependency_install=false
  -c approval_policy="never" -c history.persistence="none"
  -c forced_login_method="chatgpt"
  -c features.apps=false -c features.browser_use=false
  -c features.browser_use_external=false
  -c features.browser_use_full_cdp_access=false -c features.code_mode_host=false
  -c features.computer_use=false -c features.image_generation=false
  -c features.in_app_browser=false -c features.in_app_local_automation=false
  -c features.remote_plugin=false
  -c features.plugins=false -c features.skill_search=false
  -c features.view_image=false -c features.workspace_dependencies=false
  -c features.hooks=false -c features.goals=false
  -c mcp_servers.mapit-local.command=<absolute sys.executable>
  -c mcp_servers.mapit-local.args=["-m","mapit.mcp_server"]
  -c mcp_servers.mapit-local.cwd=<explicit repository root>
  -c mcp_servers.mapit-local.required=true
  -c mcp_servers.mapit-local.tool_timeout_sec=30
  -c mcp_servers.mapit-local.env={ PYTHONPATH = <repo>/src }
  -c mcp_servers.mapit-local.enabled_tools=<Phase 4 read-only allowlist>
```

The child environment is scrubbed of MAPIT credentials, provider/API keys,
provider endpoints/tokens, and proxy variables. Codex login configuration such
as `CODEX_HOME` is retained; `PYTHONPATH` is absent from the Codex process and
set explicitly only in the local MCP child's inline-table environment. No
arbitrary MCP server, command, shell fragment, provider model,
or model reasoning setting is accepted. The prompt is fixed policy with the
question delimited as untrusted data, never as a raw command. The exact
AgentAnswer schema is written to a temporary file and all temporary artifacts
are removed on exit.

JSONL is parsed structurally and fails closed on malformed lines, unknown
top-level lifecycle or action items, non-null tool errors, unexpected
servers/tools, extra calls, duplicate/unresolved lifecycle IDs, or incomplete
status. A started/updated MCP item must complete with the same ID, and exactly
one final `agent_message` is required. The only accepted MCP call is the bounded
read-only call on `mapit-local`. The final answer must be the exact
`AgentAnswer` contract already used by Phase 4: `answer` (string), `caveats`
(list of strings), and `needs_clarification` (boolean), with no extra fields.
Raw prompts, Telegram content, tool arguments/results, usage, IDs, URLs,
tokens, and exception text are never emitted or persisted. stdout and stderr
are bounded while being read; timeout, cancellation, and overflow terminate
the complete child process tree (POSIX process group or Windows `taskkill`
tree mode) without printing stderr.

The Telegram adapter reserves an update ID in memory before backend execution.
Backend rejection, validation failure, or cancellation before sending releases
that reservation; once a send starts, the reservation is retained even if the
sender fails because delivery is ambiguous. A successful backend result must
have category `success`; clarification may use zero tools, otherwise at least
one Phase 4 read-only tool is required. Before the sender, a conservative
lexical channel gate rejects UUIDs, VIN-like values, coordinate pairs, long
internal numeric IDs, and token-like strings. This is a bounded denylist, not
a semantic privacy proof; ordinary dates and single distance values remain
allowed. Coordinate labels are also rejected for both decimal separators (for
example `latitude`/`longitude` and `lat`/`lng` forms). The feature overrides
are pinned by command construction and offline TOML tests; no live Codex
feature-list validation has been performed. The lexical policy is deliberately
conservative: any coordinate-label word and compound credential names such as
`access_key`, `client_secret`, `refresh_token`, `id_token`, and `api_token` are
blocked even outside assignments, so benign prose may produce false positives.

## External Telegram gate

Before any implementation is allowed to contact Telegram, the supervisor must
authorize a separate external gate that records only safe booleans/categories:

1. approve bot creation and provide a test bot through the approved secure
   secret path;
2. approve the target test chat/user IDs through a secure, non-repository path;
3. approve network access and one bounded polling cycle;
4. approve the first `sendMessage` call and its test recipient/message;
5. review the redacted result and revoke/rotate the test credential afterward.

Until that gate is explicitly authorized, no bot is created, no Telegram token
or ID is read, no polling or `sendMessage` occurs, and no live gate is run.

## Offline acceptance

The implementation gate must use fake transports and fake Codex JSONL. Tests
must cover sequential polling, numeric allowlist rejection, environment
scrubbing, no-shell/stdin command construction, JSONL fail-closed behavior,
exact `AgentAnswer` validation, timeout/cancellation cleanup, and zero external
calls or persistence. A successful offline test does not authorize Telegram
network access or Phase 5 completion.
