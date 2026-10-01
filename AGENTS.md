# Project Agent Workflow

## Scope

Phase 0 (MAPIT research, API discovery, and the reusable standalone Python
client), Phase 1 (local read-only MCP core), Phase 2 (route analytics), Phase 3
(the reusable read-only realtime component), Phase 4 (the local Codex-to-MCP
conversational-agent adapter and deterministic evaluation), and Phase 5 (the
bounded private Telegram interface) are complete. Phase 6 is COMPLETE for the
approved opt-in distance ledger described in `PHASE_6_PERSISTENCE.md`
and `docs/phase-6-status.md`. On 2026-09-30 the user accepted the minimal local
distance-ledger proposal without extra encryption: local SQLite outside Git
and OneDrive, pseudonymous route aliases, UTC day/native distance, rebuildable
aggregates, retention until explicit deletion, no coordinates/streets/secrets.
Only that bounded opt-in ledger is accepted; no automatic collection or claim
of measured latency improvement/history completeness. Offline implementation
is accepted. Historical gates and bounded allowances follow; the first import stopped before storage on
`complete=false`. Its meaning is unconfirmed, not evidence of an active trip.
No further live import or implicit filtering is authorized by that execution;
the next gate is the explicit treatment of those flagged routes.
On 2026-09-30 the user chose investigation first. The only additional live
research authorized is the bounded one-Core/three-monthly-variant comparison
in `docs/phase-6-route-flags-investigation.md`, after independent offline
acceptance. It does not authorize importing/filtering private history.
That one comparison is complete: all sampled routes were false-marked,
including a coherent old-end observation, and all variants returned the same
IDs/selected fact signatures. Do not repeat it automatically. The next gate
is user approval of a revised admission contract; neither the precise flag
meaning nor true active-route filter behavior is confirmed.
The user subsequently approved replacing that gate with identifier/timing/
distance validation and resuming bounded imports. Ignore `complete` for
admission; require aware coherent start/end values not in the future, keep
native units and unverified labels, and reject the entire batch on invalid
facts or conflicts (no silent exclusions). The protocol permits one current
UTC-month import, a second only after success to verify no-op deduplication,
and redacted local/offline query checks. No other month, unfiltered read,
detail, automatic sync or new external write is authorized by this gate.
The user also asked whether routes predate August 2025. One separate July
2025 availability read is authorized: one Core and one Geo logical GET,
at most two wire GETs each with existing auth recovery, 2 MiB bodies and
10,000 routes, no proxies/redirects, no persistence or month scanning.
Validate returned start timestamps belong to July before reporting presence.
An empty July response is not proof that all earlier history is absent.
That July read is complete and confirmed routes in the requested window,
using one Core and one Geo wire GET. Do not repeat or expand it automatically.
The revised-policy current-month import passed validation but stopped at
`history_permissions_failed`, with no facts committed. The conditional second
import was not executed. Diagnose local permissions without more live reads;
any further import requires a new bounded allowance.
The user has now explicitly authorized fixing local permission verification
and one additional current-month import, followed only on success by one
deduplication import and redacted local-query checks. Diagnose and verify the
local checker before consuming that new live allowance. No broader history
scan, automatic retry or increased ACL privilege is authorized.
That renewed allowance is now consumed successfully: local preflight passed,
one current-month import committed minimal facts, the second added no facts,
and day/month/year local queries passed with zero upstream attempts. The
Windows PowerShell child environment excludes inherited `PSModulePath` without
changing the parent environment or relaxing ACLs. Private SQLite/alias key
exist outside Git/OneDrive; no automatic sync or further live read is approved.
Phase 7 is at the explicit direct-only/proxy and general 2 MiB response-cap
compatibility gate in `docs/phase-7-audit-preparation.md`. Research/preparation
is accepted, not implementation of those compatibility changes. The user
requested continuing until the next gate; ask for this decision before
changing those defaults. On 2026-09-30 the user approved that gate: Phase 7
was implemented for direct-only/no-redirect transports, general 2 MiB MAPIT response
ceiling, bounded auth/discovery input, offline reliability/security review,
safe diagnostics, dependency/CI checks and synthetic portfolio demonstration.
Preserve injectable interfaces, read-only MAPIT and bounded auth recovery;
no new live MAPIT/Telegram operation or paid model call is authorized. Phase 7
is COMPLETE with independent offline acceptance and five green CI jobs on
commit `5643a36`. Phase 8
has no deployment/cost approval. The user subsequently authorized Phase 8
design, public price research, cost estimation and offline IaC preparation
after Phase 7 acceptance. Do not use AWS SDK/account inventory, create or
deploy resources, transfer credentials, or invoke paid models/APIs. Stop at
the explicit dev deployment/cost/identity gate, with prod/model gates separate.
On 2026-10-01 two separately authorized screenshot-to-API route comparisons
were completed (the second included detail). Their live allowances are consumed.
The user then approved offline additive kilometre presentation and a source
inferred-segment indicator, not road reconstruction. Preserve native fields
and ledger facts/schema; convert only explicit kilometre companions using the
UI-correlated metre-scale interpretation, with its evidence limitation. Do not
change vehicle odometer/speed units or imply physical-distance accuracy. Missing
or malformed segment flags mean unknown, not verified tracking. No new detail
reads per list route, live calls, re-imports, private data/geometry persistence,
AWS deployment or model inference is authorized by that implementation gate.
That additive presentation implementation is now independently accepted offline:
677 tests pass with 3 skipped, including synthetic MCP structured serialization.
Retain its UI-correlated conversion basis and nullable source-flag limitations;
it is not authorization for new route probes or inferred-road reconstruction.
On 2026-10-01 the user approved the next Phase 8 local-only block: synthetic
Streamable HTTP integration, cryptographic access-token verification, dev/prod
policy isolation, and bounded-request/authorization-negative tests. Require an
explicitly synthetic factory/provider; no default local MAPIT session, private ledger,
credential loading, live MAPIT/Telegram/model call, AWS account operation,
deployment or Codex configuration/login change is authorized. Keep the IaC
disabled. Real Cognito/PKCE interoperability and live upstream deadline handling
remain separate acceptance requirements before activation.
The local block is independently accepted: 35 focused HTTP tests and 712 full
offline tests pass (3 skipped), with real SDK protocol serialization but only
synthetic data. No deployment, actual OAuth login or live upstream deadline
acceptance follows from this result; stop at the separate dev gate.
Do not expand into an
agent UI, frontend, live project-owned AWS
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
