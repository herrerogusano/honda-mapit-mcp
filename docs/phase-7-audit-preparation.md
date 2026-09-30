# Phase 7 preparation — read-only audit, 2026-09-30

Phase 7 is not accepted or implemented by this audit. The Phase 6 live-ingestion
flag decision remains the current gate. No AWS, paid model, Telegram or extra
MAPIT operation was run for this review.

The researcher inspected the local auth/client/config/WebSocket/Telegram/CI
boundaries. The supervisor consulted the vault's MCP/OAuth and managed-agent
E2E guides: preserve trusted identity boundaries, reserve attempts before
dispatch, distinguish offline/live evidence, and use allowlisted metadata.
These are local hardening priorities, not authorization for remote deployment.

## Proposed bounded hardening tasks

1. Replace implicit urllib redirect behavior on signed MAPIT requests with
   fail-closed handling. Also make Cognito and Telegram redirect policy
   explicit. Current initial-host checks do not independently constrain every
   hop (`client.py`, `auth.py`, `telegram_bot.py`). Review each request method's
   actual behavior; do not claim every redirect necessarily forwards POST
   bodies or path tokens. Test external 301/302/307/308 destinations without
   real network calls.
2. Decide explicit direct-only policy or trusted-proxy configuration for each
   secret-bearing boundary. Normal urllib callers currently inherit proxy
   configuration; the WebSocket adapter omits the proxy keyword. The local
   history adapter already uses no proxies/redirects. Python documents default
   proxy/redirect handlers and `ProxyHandler({})`; websockets 15 documents its
   proxy default. See [Python urllib](https://docs.python.org/3.13/library/urllib.request.html)
   and [websockets 15 client](https://websockets.readthedocs.io/en/15.0/reference/sync/client.html).
3. Add bounded Cognito/public-discovery body reads, bundle count and a total
   discovery budget. Service-level MAPIT reads already have caps, while the
   general client permits uncapped reads if a caller omits its byte limit.
   A blocking socket timeout is not an end-to-end cancellation deadline.
4. Extend clean CI dependency compatibility coverage to the agent/realtime
   extras together and fake Windows keyring/ACL paths. Add dependency auditing
   separately from the offline application tests; installing packages/advisory
   retrieval uses network, but tests must remain secret-free and offline.
5. Keep operational diagnostics minimal: safe categories, request-count and
   latency bands. Do not put signed URLs, tokens, route IDs, payloads or exact
   private counts in structured logs merely to obtain correlation.

Existing strengths: allowlisted initial Core/Geo URLs, GET-only service calls,
bounded auth recovery, route-service body limits, safe error translation,
realtime receive limits, Telegram bounded/no-write-retry semantics and
deterministic agent evaluation. None proves a remote production deployment.
