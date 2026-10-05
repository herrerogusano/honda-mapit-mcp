# Phase 7 — Hardening, Observability & Release

## Goal
Make the project portfolio-ready and operationally reliable.

## Reliability
Review:
- authentication recovery;
- refresh lifecycle;
- API timeouts;
- retries/backoff;
- partial failures;
- WebSocket recovery;
- malformed payload handling.

## Security
Review:
- secret handling;
- Credential Manager integration;
- log redaction;
- fixture anonymization;
- MCP read-only guarantee;
- Telegram authorization;
- dependency security.

## Observability
Add lightweight:
- structured logs;
- useful request/correlation IDs;
- clear error categories;
- health diagnostics.

Never log sensitive payload values.

## CI
Maintain tests on supported Python versions and add suitable quality/security checks.

## Documentation
Final docs should cover:
- architecture;
- setup;
- authentication;
- MCP tools;
- agent;
- Telegram if enabled;
- security model;
- MAPIT limitations;
- demo scenarios.

## Portfolio demo
Demonstrate:
- current status;
- yearly distance;
- period comparison;
- longest route;
- realtime state;
- natural-language agent query;
- Telegram query if enabled.

## Exit criteria
The project is understandable, tested, secure for its intended scope, and demonstrable without exposing personal data.
