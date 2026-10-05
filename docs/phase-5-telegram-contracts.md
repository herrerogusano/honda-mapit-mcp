# Phase 5 private Telegram prototype contract

Status: **COMPLETED — bounded private prototype and redacted supervisor gate**.

Phase 5 is a local, private prototype boundary around the completed read-only
MAPIT/MCP and Codex-to-MCP phases. The implementation is not a daemon, webhook,
or persistent event service. The supervisor recorded one bounded live E2E gate
with safe booleans/categories only; this does not authorize unbounded Telegram
operations or deployment.

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

The offline implementation now includes `WindowsKeyringTelegramCredentialStore`
using only the native WinVault keyring backend and one constant account,
`telegram-state-v1`. That account contains one strict canonical JSON envelope
with `format`, `version`, `token`, `pairs`, and `challenge` fields. The envelope
is limited to 2048 UTF-8 bytes and the token to 512 bytes; tokenless state has
null pairs/challenge, and a challenge always requires a token. Every mutation
validates the complete envelope and performs one bounded `set_password`; a
failed write therefore leaves the previous state untouched. `save_token`
replaces the token and clears prior pairs while creating a cryptographically
strong challenge, `save_allowlist` preserves the token and challenge, and
`delete_challenge` preserves token/pairs. `save()` writes a complete
token/pair state with `challenge: null`; runtime `load` requires both token and
pairs and a consumed (`challenge: null`) state. Partial, non-canonical,
oversized, or legacy multi-entry state fails closed. Pair IDs are accepted by
the runtime only after the exact possession-based `/start <challenge>` flow.
The token format is conservatively bounded to Telegram's numeric/base64url-ish
shape.
`scripts/telegram_setup_gui.py` stores only the masked token and shows the
challenge in a readonly selectable command field with `Copiar comando`; the
clipboard is touched only after that explicit click. It never emits the
challenge to stdout or logs. `mapit.telegram_bot` provides an injectable
stdlib Bot API transport and one sequential bounded cycle. The production seam
reads credentials only from the store; no environment/file fallback exists.

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
  --output-last-message <temporary final-message path>
  -c features.shell_tool=false -c features.unified_exec=false
  -c web_search="disabled"
  -c features.multi_agent=false
  -c features.skill_mcp_dependency_install=false
  -c approval_policy="never" -c history.persistence="none"
  -c forced_login_method="chatgpt"
  -c features.apps=false -c features.browser_use=false
  -c features.browser_use_external=false
  -c features.browser_use_full_cdp_access=false
  -c features.code_mode.enabled=false
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
AgentAnswer schema and final-message path are temporary. The schema has all
three properties (`answer`, `caveats`, and `needs_clarification`) required and
no additional properties; all temporary artifacts are removed on exit.

JSONL is parsed structurally and fails closed on malformed lines, unknown
top-level lifecycle or action items, non-null tool errors, unexpected
servers/tools, extra calls, duplicate/unresolved lifecycle IDs, or incomplete
status. A started/updated MCP item must complete with the same ID, and exactly
one final `agent_message` is required after the last completed MCP call. Bounded
inert pre-tool `agent_message` progress events are accepted, but the final
message file must match the last completed agent message semantically. The only
accepted MCP call is the bounded read-only call on `mapit-local`. The final answer must be the exact
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

The user authorized the external gate on 2026-09-29 and the bot
`@honda_mapit_mcp_bot` was created. The supervisor recorded the bounded gate as
`success=true`, `category=success`, `cycles=1`, `update_processed=true`, and
`message_sent=true`; a direct backend safe check also succeeded with the
allowlisted current-status tool. This worktree still does not read or record a
token, question, answer, message content, or real IDs.

The supervisor must retain control of the separate external gate and record
only safe booleans/categories:

1. retain supervisor control of any future live operation and secure secret path;
2. keep target IDs and credentials outside the repository;
3. review or revoke test credentials after any separately approved operation.

The implementation smoke is `scripts/smoke_telegram_live.py`; it requires both
`--allow-get-updates` and `--allow-send-message` before any Bot API operation.
It calls `getMe`, requires `getWebhookInfo.url == ""`, then performs one
`getUpdates` with `limit=1`, `allowed_updates=["message"]`, and bounded timeout.
It accepts only a private exact `/start <challenge>` from a non-bot sender,
persists that pair, consumes the challenge, and sends one fixed message to the
same chat. Invalid/group/bot/text/challenge updates never persist or send. A
send failure is ambiguous and is not retried; the challenge has already been
consumed. Its output is limited to booleans/categories and never includes
tokens, challenges, IDs, content, URLs, or response bodies. Poller offsets are
highest-update-plus-one in memory only; there are no retries.

`scripts/run_telegram_once.py` is the bounded operational seam for the query
gate. It requires `--allow-poll --allow-agent --allow-send`, reuses one
poller for at most two sequential cycles, stops on the first safe error or
`message_sent`, and emits only `success`, an allowlisted category, cycle count,
and booleans. Future invocations remain explicitly supervisor-authorized; no
Telegram token or ID is printed or persisted by this worktree.

## Offline acceptance

The implementation gate must use fake transports and fake Codex JSONL. Tests
must cover sequential polling, numeric allowlist rejection, environment
scrubbing, no-shell/stdin command construction, JSONL fail-closed behavior,
exact `AgentAnswer` validation, timeout/cancellation cleanup, and zero external
calls or persistence. A successful offline test or bounded gate does not imply
a general Telegram service, webhook, persistence layer, or universal MAPIT
behavior.
