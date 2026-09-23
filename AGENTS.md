# Project Agent Workflow

## Scope

This repository is in Phase 0: MAPIT research, API discovery, and a reusable
standalone Python client. Do not implement an MCP server, MCP tools, Telegram,
an agent UI, a frontend, a project database, project-owned AWS infrastructure,
or Home Assistant integration during this phase.

Phase 0 is read-only against MAPIT. Do not send `POST`, `PUT`, `PATCH`, or
`DELETE` requests except the Cognito calls strictly required for authentication.
Never commit credentials, tokens, AWS keys, or real personal/device/location IDs.

Before implementing MCP, agents, tools, evaluations, or AWS integration, read:

- `C:\Users\herre\OneDrive\Desktop\herrerogusano's vault\04 Knowledge\AI Engineering\AI Engineering.md`
- the task-relevant guides linked from that index

## Persistent Roles

Reuse these three roles across Phase 0. Do not create fresh agents for routine
work.

- `researcher`: investigate MAPIT, public implementations, frontend bundles,
  endpoints, payloads, history, and WebSocket behavior. Prefer primary evidence.
- `implementer`: make bounded code changes only after the relevant evidence and
  decisions are documented.
- `tester`: independently review changes, add or run offline tests, and check
  security, error handling, and regression risk.

Preferred worker configuration: `gpt-5.6-luna`, high reasoning. The supervisor
owns scope, sequencing, decisions, integration, and acceptance. Escalate model
effort only for a demonstrated blocker.

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

Distinguish confirmed facts, evidence found in frontend/code, hypotheses, and
open questions. Do not invent capabilities or brute-force endpoints.
