# Honda MAPIT MCP — Project Phases

## Current status

- Phase 0 — MAPIT Discovery & Client Foundation: COMPLETED
- Phase 1 — MCP Core & Read-Only Tools: COMPLETED
- Phase 2 — Route Analytics & Aggregations: COMPLETED
- Phase 3 — Realtime State & Event Layer: COMPLETED
- Phase 4 — Conversational Agent Integration: COMPLETED
- Phase 5 — Telegram Interface: COMPLETED (bounded private local interface;
  redacted supervisor E2E gate passed)
- Phase 6 — Persistence & Historical Intelligence: COMPLETED for the approved
  opt-in minimal local distance ledger; bounded import/deduplication accepted,
  no automatic sync or claim of complete history. See [status](docs/phase-6-status.md).
- Phase 7 — Hardening, Observability & Release: COMPLETED. See [status](docs/phase-7-status.md).
- Phase 8 — AWS Remote Service & Managed Agent Evaluation: ACTIVE. Closed AWS
  creation/shutdown/deletion rehearsal completed and cleaned up; runtime/OAuth
  preparation continues. No active remote MCP or real OAuth E2E acceptance yet.
  See [current evidence and gates](docs/phase-8-aws-preparation.md).

## Architecture principle

```text
Interface / Agent / Telegram
          ↓
        MCP
          ↓
      Services
          ↓
     MapitClient
          ↓
       MAPIT
```

- `MapitClient`: technical communication with MAPIT.
- Services: business logic, aggregation and reusable application behavior.
- MCP: thin tool exposure layer.
- Agent / Telegram: natural-language and user-facing interfaces.

Remote deployment is a separate concern from model hosting. Phase 8 may publish
the MCP as an always-available AWS service without embedding a language model.
Only an optional managed-agent track needs a model/provider decision and paid
inference. See `PHASE_8_AWS_REMOTE.md`.

## Persistent agent strategy

- Supervisor: user-selected model in the app; explicitly changed to Astra on
  2026-10-02. This does not authorize paid model API calls.
- Researcher: GPT-6 Luna, High reasoning.
- Implementer: GPT-6 Luna, High reasoning.
- Tester/Reviewer: GPT-6 Luna, High reasoning.

Reuse the same agents throughout the project. Create temporary specialists only for exceptional blockers.
