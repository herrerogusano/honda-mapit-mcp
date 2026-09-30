# Project Agent Workflow

## Scope

Phase 0 (MAPIT research, API discovery, and the reusable standalone Python
client), Phase 1 (local read-only MCP core), Phase 2 (route analytics), Phase 3
(the reusable read-only realtime component), Phase 4 (the local Codex-to-MCP
conversational-agent adapter and deterministic evaluation), and Phase 5 (the
bounded private Telegram interface) are complete. Phase 6 is ACTIVE for the
approved opt-in distance ledger described in `PHASE_6_PERSISTENCE.md`
and `docs/phase-6-status.md`. On 2026-09-30 the user accepted the minimal local
distance-ledger proposal without extra encryption: local SQLite outside Git
and OneDrive, pseudonymous route aliases, UTC day/native distance, rebuildable
aggregates, retention until explicit deletion, no coordinates/streets/secrets.
Implement only that bounded opt-in ledger; no automatic collection or claim
of measured latency improvement/history completeness. Offline implementation
is accepted; the first bounded live import stopped before storage on
`complete=false`. Its meaning is unconfirmed, not evidence of an active trip.
No further live import or implicit filtering is authorized by that execution;
the next gate is the explicit treatment of those flagged routes.
Do not expand into an
agent UI, frontend, project-owned AWS
infrastructure, webhook deployment, Home Assistant, or HA integration.

On 2026-09-29 the user authorized the external gate and the bot
`@honda_mapit_mcp_bot` was created. The supervisor recorded one bounded Telegram
E2E result and one direct read-only backend check as safe booleans/categories
only; no token, message content, or real chat/user identifier belongs in the
repository. Any future live Telegram operation remains supervisor-authorized.

MAPIT remains read-only in all phases. Do not send `POST`, `PUT`, `PATCH`, or
`DELETE` requests to MAPIT except the Cognito calls strictly required for
authentication. The only Telegram write in the Phase 5 contract is the bounded
`sendMessage` operation; no persistent Telegram worker, webhook, or additional
live operation is in scope.
Never commit credentials, tokens, AWS keys, Telegram bot tokens, or real
personal/device/location/chat/user IDs.

Before expanding the MCP core, agents, tools, evaluations, or AWS integration,
read:

- `C:\Users\herre\OneDrive\Desktop\herrerogusano's vault\04 Knowledge\AI Engineering\AI Engineering.md`
- the task-relevant guides linked from that index

## Persistent Roles

Reuse these three roles across project phases. Do not create fresh agents for routine
work.

- `researcher`: investigate MAPIT, public implementations, frontend bundles,
  endpoints, payloads, history, and WebSocket behavior. Prefer primary evidence.
- `implementer`: make bounded code changes only after the relevant evidence and
  decisions are documented.
- `tester`: independently review changes, add or run offline tests, and check
  security, error handling, and regression risk.

Preferred worker configuration: `gpt-6-luna`, high reasoning. The supervisor
owns scope, sequencing, decisions, integration, and acceptance. Escalate model
effort only for a demonstrated blocker.

On 2026-09-30 the user selected GPT-6.1 Sol with medium reasoning for the
supervisor and GPT-6 Luna with high reasoning for workers. Existing workers
were checkpointed and replaced because the agent tools cannot change an
existing worker's model. Reuse the replacement researcher, implementer and
tester roles; do not silently inherit a different model or escalate to Astra.

Use this normal sequence when practical:

1. Researcher gathers and documents evidence.
2. Supervisor approves a bounded implementation task.
3. Implementer changes code and runs focused tests.
4. Tester reviews and tests independently.
5. Implementer fixes concrete defects; supervisor accepts or rejects.

Each worker report should be brief: Task, Findings, Files changed, Tests, Open
questions, and Supervisor must retain.

## Project Memory

Treat repository documentation as the durable source of truth. Update findings
incrementally, especially:

- `docs/mapit-authentication.md`
- `docs/mapit-endpoints-discovered.md`
- `docs/mapit-data-inventory.md`
- `docs/mapit-routes-investigation.md`
- `docs/phase-0-findings.md`
- `docs/phase-0-status.md`
- `docs/phase-3-status.md`
- `docs/phase-4-agent-contracts.md`
- `docs/phase-5-telegram-contracts.md`
- `docs/phase-5-status.md`

Distinguish confirmed facts, evidence found in frontend/code, hypotheses, and
open questions. Do not invent capabilities or brute-force endpoints.
