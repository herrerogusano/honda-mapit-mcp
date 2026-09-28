# Honda MAPIT MCP — Project Phases

## Current status
- Phase 0 — MAPIT Discovery & Client Foundation: COMPLETED
- Phase 1 — MCP Core & Read-Only Tools: COMPLETED
- Phase 2 — Route Analytics & Aggregations: COMPLETED
- Phase 3 — Realtime State & Event Layer: COMPLETED
- Phase 4 — Conversational Agent Integration: IN PROGRESS
- Phase 5 — Telegram Interface: PLANNED
- Phase 6 — Persistence & Historical Intelligence: PLANNED
- Phase 7 — Hardening, Observability & Release: PLANNED

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

## Persistent agent strategy
- Supervisor: GPT-5.6 Sol, Medium reasoning.
- Researcher: GPT-5.6 Luna, High reasoning.
- Implementer: GPT-5.6 Luna, High reasoning.
- Tester/Reviewer: GPT-5.6 Luna, High reasoning.

Reuse the same agents throughout the project. Create temporary specialists only for exceptional blockers.
