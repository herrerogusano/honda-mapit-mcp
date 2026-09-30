# Phase 7 preparation — read-only audit, 2026-09-30

Phase 7 is not accepted or implemented by this audit. Phase 6 is now accepted
for its minimal opt-in ledger. The current Phase 7 gate is the explicit network
compatibility decision below. No AWS, paid model, Telegram or extra
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

## Current user gate: network-policy compatibility

The proposed bounded implementation preserves public signatures, injectable
transports and existing authentication recovery/write-retry rules. It would
make default secret-bearing HTTP and WebSocket connections direct-only, ignore
environment/system proxies and reject redirects. This may break networks that
require a corporate proxy; a trusted-proxy option is not silently introduced.

It would also set a 2 MiB ceiling on general MAPIT responses, matching existing
service/history limits (currently a low-level caller can omit its size bound).
Larger responses would fail explicitly, not truncate to misleading totals.
Suggested separate limits are 256 KiB for Cognito, 1 MiB public HTML, 4 MiB per
public JS bundle, 32 bundles and 16 MiB total discovery input. These remain
proposals pending implementation/review, not measured provider requirements.

The user approved direct-only defaults and the general MAPIT ceiling on
2026-09-30. Implementation may proceed with these compatibility behaviors
explicitly documented. All ensuing application tests
remain offline, with no new live Telegram/MAPIT test, model API or AWS resource.
