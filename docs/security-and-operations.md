# Security and local operations

## Architecture and trust boundaries

The local MCP exposes read-only tools over stdio. Its service layer validates
parameters and translates provider errors; the standalone client signs bounded
GET requests to allowlisted MAPIT Core/Geo endpoints. Cognito authentication
POSTs are the only exception to the MAPIT read-only boundary. The local agent
adapter and bounded private Telegram adapter reuse that backend; neither
creates an always-on service. Realtime is a separate bounded component, not a
new MCP realtime tool.

The optional distance ledger is independent of ordinary on-demand MCP reads.
It has explicit imports, scope-separated HMAC aliases and rebuildable UTC
aggregates. It does not record coordinates, streets, exact timestamps or
secrets. It is not a complete historical mirror.

## Network policy approved for Phase 7

Default HTTP transports use no environment/system proxies and reject
redirects. The WebSocket connector disables proxy discovery explicitly.
Networks requiring a corporate proxy are not supported by these defaults;
no trusted-proxy fallback is introduced. Transport callbacks are trusted
embedding/test seams, not a sandbox for untrusted plugins. Decoded objects
returned by injected callbacks do not prove a bounded wire response.

| Boundary | Input/body limit |
|---|---|
| MAPIT GET | 2 MiB ceiling, including when a low-level caller omits a limit |
| Cognito response | 256 KiB |
| Discovery HTML | 1 MiB |
| Discovery JS | 4 MiB per bundle; 32 same-origin bundle attempts |
| Total discovery input | 16 MiB; cooperative 60-second budget |
| Telegram | Existing bounded body, update and timeout contract |

Stricter MAPIT limits remain possible; larger requested limits do not bypass
the ceiling. Overflow fails explicitly rather than truncating analytics.
Discovery checks time during reads and before/after fetches, counts failed
bundle attempts and does not swallow hard budget failures. Socket timeouts
and cooperative checks are not absolute cancellation deadlines for a blocked
socket or arbitrary injected callback.

Authentication recovery remains bounded to one 401/403 recovery per logical
MAPIT GET. Redirects, invalid JSON and oversize responses do not trigger that
recovery. Telegram sends are not blindly retried after ambiguous failure.

## Secrets, storage and diagnostic output

MAPIT refresh material and the separate ledger alias key use native Windows
Credential Manager, never plaintext fallback. The ledger is outside Git and
OneDrive. Its protected ACL admits the owner, SYSTEM and local administrators;
this is not encryption or anonymity. UTC dates/distances are readable by a
privileged filesystem user. Retention and explicit deletion are described in
[the ledger contract](phase-6-ledger-contract.md).

Errors expose fixed categories/statuses rather than provider exception text,
signed URLs, payloads or tokens. `python -m mapit.health` (or `mapit-health`)
checks package metadata and the supported Python window only. It does not
touch credential stores, authenticate or contact providers; success means a
local environment check, not live service readiness. Existing bounded probes
use allowlisted categories/bands. No payload logging, real provider request IDs
or new persistent telemetry store is introduced.

## Verification and dependency maintenance

CI installs core, test, agent and realtime extras together on Linux Python
3.11–3.13 and Windows Python 3.13; the Windows job adds the keyring extra.
Credential backends/ACL subprocesses are mocked in tests. The offline suite
allows deliberate loopback fixtures but blocks external application network
access, with a regression that checks the blocker is actually loaded.

A separate networked job audits an exact installed third-party inventory with
`pip-audit`. Only this first-party project is excluded from the PyPI inventory;
its source is independently reviewed. Unknown/invalid dependency collection
and known advisories fail the audit. There are no ignored vulnerability IDs.
Installation/advisory retrieval is networked and separate from offline tests.
This checks known advisories, not malware, every source-code defect or future
resolver changes. The project does not yet have a cross-platform lockfile.

The test floor is pytest 9.1.1, covering the published tmpdir security fix and
avoiding the 9.1.0 conftest-loading regression. CI bootstrap requires pip 26.2
or newer within major 26. Primary evidence: [PyPA pip advisories](https://github.com/pypa/advisory-database/tree/main/vulns/pip),
[pytest advisory](https://github.com/pypa/advisory-database/blob/main/vulns/pytest/PYSEC-2026-1845.yaml),
[pytest changelog](https://docs.pytest.org/en/stable/changelog.html), and
[pip-audit security model](https://github.com/pypa/pip-audit#security-model).

## Remaining boundaries

No AWS deployment, managed model, automatic historical sync, public Telegram
worker or Home Assistant integration exists. MAPIT native distance units and
`complete` semantics remain unverified. Streets, exact turns and city coverage
are not established. The private GitHub plan's unenforced branch/environment
protection remains documented in [environments and CI](environments-and-ci.md).
