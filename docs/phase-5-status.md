# Phase 5 status

Status: **COMPLETED — bounded private interface and redacted supervisor E2E gate**.

## Current scope

Phase 5 delivered an approved contract and an offline implementation for a
sequential, bounded local polling prototype around the completed read-only
MAPIT/MCP and Codex CLI backend. It is not a daemon, webhook, or persistent
event service. The contract is recorded in
[`phase-5-telegram-contracts.md`](phase-5-telegram-contracts.md).

The offline `CodexCliBackend`, strict `TelegramAdapter`, single-envelope
Credential Manager store, injectable Bot API transport, setup GUI, and
explicit-confirmation smoke are implemented without PTB. Bot creation was
authorized on 2026-09-29. The supervisor recorded the bounded live result only
as `success=true`, `category=success`, `cycles=1`,
`update_processed=true`, and `message_sent=true`; a direct backend safe check
also succeeded with the allowlisted current-status tool. No token, chat/user
ID, question, answer, message content, or raw response is stored or included
here. Pairing uses a one-use Credential Manager challenge and exact
private `/start <challenge>` possession validation; token, pair allowlist, and
challenge are stored only in the bounded canonical `telegram-state-v1` envelope.
The envelope is capped at 2048 UTF-8 bytes (tokens at 512 bytes); runtime
session loading requires a consumed challenge (`challenge: null`). The
challenge is consumed before the fixed send and never appears in stdout.

## Delivered bounded implementation

The bounded implementation is delivered in `src/mapit/codex_cli_backend.py`,
`src/mapit/telegram_adapter.py`, `src/mapit/telegram_credentials.py`, and
`src/mapit/telegram_bot.py`, with injectable offline tests covering numeric
fail-closed validation, sequential in-memory polling seams, Codex CLI
stdin/JSONL lifecycle, environment scrubbing, exact `AgentAnswer` validation,
dedupe, bounded process-tree cleanup, and safe category-only failures. The
offline suite currently passes 373 tests. Keep MAPIT read-only and the sole
future Telegram write limited to the explicit `sendMessage` contract.

## External gate evidence

Bot creation and the bounded query E2E gate were authorized and completed by
the supervisor on 2026-09-29. The evidence is limited to the safe fields above;
tokens and real IDs must never enter the repository, fixtures, logs, JSON
output, or durable state. Future live operations remain supervisor-authorized.

## Exit criteria

Phase 5 is complete within its bounded scope. The result is evidence for the
private local account and one query path only; it does not establish a general
Telegram service, webhook, durable polling worker, or universal MAPIT behavior.
Phase 6 is now the measure-first persistence decision gate; see
[`phase-6-status.md`](phase-6-status.md).
