# Phase 5 status

Status: **ACTIVE — private local contract/prototype only**.

## Current scope

Phase 5 has an approved contract and an offline implementation for a
sequential, bounded local polling prototype around the completed read-only
MAPIT/MCP and Codex CLI backend. “No polling” means no **live polling**: all
current tests use synthetic updates and injected fakes. The contract is
recorded in
[`phase-5-telegram-contracts.md`](phase-5-telegram-contracts.md).

The offline `CodexCliBackend` and strict `TelegramAdapter` are implemented
without PTB, bot, token, chat/user ID, polling request, message, webhook, AWS
resource, or persistence. No live gate has been authorized or run.

## Delivered bounded implementation

The bounded implementation is delivered in `src/mapit/codex_cli_backend.py` and
`src/mapit/telegram_adapter.py`, with injectable offline tests covering numeric
fail-closed validation, sequential in-memory polling seams, Codex CLI
stdin/JSONL lifecycle, environment scrubbing, exact `AgentAnswer` validation,
dedupe, bounded process-tree cleanup, and safe category-only failures. The
offline suite currently passes 334 tests. Keep MAPIT read-only and the sole
future Telegram write limited to the explicit `sendMessage` contract.

## External gate remains pending

The supervisor must explicitly authorize bot creation, a secure test token,
test chat/user IDs, network access, and the first bounded `sendMessage` before
any Telegram API call. Those values must never enter the repository, fixtures,
logs, JSON output, or durable project state.

## Exit criteria

Phase 5 is not complete. Completion requires independently reviewed offline
tests first, followed by the separately authorized external gate and a safe
redacted result. No Telegram capability should be inferred from the contract
or offline tests alone.
