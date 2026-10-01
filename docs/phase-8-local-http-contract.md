# Phase 8 local HTTP contract

Status: ACCEPTED OFFLINE on 2026-10-01, with independent review. The user
approved local synthetic Streamable HTTP, authorization-negative tests,
dev/prod policy isolation and bounded requests. No account, deployment, private
data, credential handoff or model inference is authorized.

## Bounded design

Reuse the installed MCP 2.2 server's stateless JSON HTTP transport, token-verifier
interface and protected-resource metadata routes. Preserve the existing stdio
entry point. The explicitly synthetic HTTP factory constructs a fixed synthetic
provider and requires trusted public verification keys; it must not fall back to the
local MAPIT session or ledger. No runnable live-provider or AWS entry point is
introduced by this block.

Verify RS256 signatures against an injected, fixed key set, not a URL or key
supplied by a token. Require exact issuer/resource audience/client, access-token
use, finite valid expiry/time claims and the configured owner subject. Require
the narrow read scope before tool dispatch. Separate dev/prod policies and keys;
a token for one environment must not access the other. Tokens and claims are
never tool arguments or diagnostic output. No authorization server is built.

Publish canonical protected-resource metadata and an authentication challenge.
Validate Host/Origin and bound HTTP input and cooperative request processing.
Deadline cancellation does not terminate a blocking upstream thread; synthetic
deadline tests must not be described as proving MAPIT recovery fits Lambda's
budget. Real upstream deadline propagation is a separate prerequisite.

## Evidence and limits

Implementation: `src/mapit/remote_http.py` exposes `create_synthetic_http_app`
with immutable `.invalid` dev/prod presets and a fixed synthetic service provider.
There is no launcher, live-provider injection, credential loading or AWS adapter.
The stdio entry point is unchanged; authenticated server construction requires
both auth settings/verifier and an explicit provider.

All ten tools were successfully invoked through the SDK's actual HTTP protocol
using an in-process ASGI transport. Tests cover signed-token claims/key rejection,
environment crossover, metadata/401/403, no session ID, GET 405, duplicate and
oversized headers, body/response bounds, cooperative timeout buffering and
sanitized receive/downstream failures. Independent review found a receive-error
redaction gap, corrected before acceptance. Focused HTTP tests: **35 passed**.
Full Windows Python 3.13 suite: **712 passed, 3 skipped**; compilation and the
model-free evaluator's 12/12 cases pass. No listener or external application
traffic was used. CI acceptance is recorded separately in GitHub.

Limits: a valid scope must equal the synthetic narrow read scope; these fixed
policies are not an arbitrary IdP integration. Trusted keys are public-only,
bounded and copied at construction; no key discovery/rotation is implemented.
HTTP buffering bounds application input/output, not allocations already made by
an ASGI host. Sending the accepted response is subject to transport backpressure;
the cooperative processing deadline is not a hard wall-clock network deadline.

Installed SDK source confirms `MCPServer.streamable_http_app` supports
`stateless_http=True`, `json_response=True`, input limits, explicit transport
security, and a session-manager lifespan. SDK auth supports `TokenVerifier`,
`AuthSettings.validate_token_resource` and public resource metadata. Application
verification must still enforce exact claims and owner binding independently.
The SDK's secondary audience check normalizes URLs and removes a trailing slash;
the verifier must check the original signed audience string first. HTTP tests
use `httpx2.ASGITransport` with the app lifespan explicitly entered; no listener
or external network is needed. Stateless JSON must not issue a session ID.

The OpenAI Docs consultation influenced metadata discovery and the separation
between resource-server verification and provider login. See [OpenAI OAuth
guidance](https://developers.openai.com/plugins/build/auth) and [Codex MCP
configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli). Synthetic
signed tokens do not prove Cognito discovery, PKCE, callback registration,
refresh/rotation or actual Codex interoperability.

The [AWS preparation](phase-8-aws-preparation.md) and disabled IaC remain
unchanged in authority. After independent offline acceptance, stop for a
separate dev cost/duration/account/identity/credential/shutdown decision.
