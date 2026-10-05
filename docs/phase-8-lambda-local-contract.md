# Phase 8 — local Lambda composition contract

Status: INDEPENDENTLY ACCEPTED OFFLINE on 2026-10-01. After the read-only
credit review, the user requested advancing. This block adapts the accepted
synthetic HTTP app to local API Gateway HTTP API payload-v2 fixtures. It does
not authorize deployment, account inventory, real MAPIT data, credential
handoff, paid inference or activation of the disabled infrastructure scaffold.
Private account/credit identifiers and financial balances are not stored here.

## Bounded implementation

- Expose only an explicitly synthetic handler factory, taking validated fixed
  dev/prod policy and public verification keys. No environment-configured live
  handler, local session fallback, secret read or AWS SDK call.
- Parse only payload version `2.0`. Project the minimum HTTP fields into ASGI;
  do not pass raw event, authorizer claims, account IDs, source IP or cookies to
  services/tools. Existing cryptographic JWT verification remains mandatory;
  claims in an event are not proof of authorization.
- Allow only `/mcp` and the advertised protected-resource metadata path, without
  query parameters or custom-domain/stage path rewrites. Bound headers and body,
  strictly validate base64 and boolean/type fields, and reject conflicting
  paths or ambiguous security headers before dispatch.
- Preserve stateless buffered JSON, 401/403 challenges and GET 405. Use a fresh
  app/session-manager lifespan and owned event loop per invocation, so sequential
  warm-style calls cannot reuse a closed loop or leak transport sessions.
- Derive the cooperative processing budget from Lambda's remaining milliseconds,
  leaving a response/cleanup reserve. Expired/invalid remaining-time context
  fails closed. Keep input/output limits and redact all errors. Cancellation
  still cannot kill synchronous upstream threads; no live-upstream readiness
  follows from this block.
- Return an explicit v2 proxy envelope (`statusCode`, `headers`, `body`,
  `isBase64Encoded`), with bounded response material and no request diagnostics.

## Primary evidence and acceptance

AWS documents comma-combined duplicate headers in v2 and differences between
`rawPath` and custom-domain mappings; the strict adapter intentionally supports
only the draft's `$default` root mapping. See [HTTP API Lambda payloads](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html).
The processing reserve uses the documented [Lambda remaining-time context](https://docs.aws.amazon.com/lambda/latest/dg/python-context.html).

Require real SDK initialization/list/tool-call serialization through synthetic
v2 events, sequential invocations, metadata/auth/environment-negative tests,
invalid body/header/path/context tests and independent review. This remains
offline composition evidence, not AWS service acceptance, ARM packaging,
Cognito/PKCE, refresh rotation, upstream deadlines or operational shutdown.

## Accepted implementation

`src/mapit/lambda_adapter.py` exposes `create_synthetic_lambda_handler`, not a
configured live Lambda entry point. The synchronous handler owns a fresh app,
lifespan and event loop per invocation. Its cooperative budget is capped by
the configured deadline (15 seconds by default) and Lambda remaining time,
less a one-second response/cleanup reserve. This is not a hard cancellation
guarantee for synchronous upstream work or runtime shutdown.

The adapter bounds request/response headers (64 entries, 32 KiB), bodies and
the complete serialized proxy envelope. It rejects malformed base64, header
controls, ambiguous security fields, nonempty cookies, unsupported mappings,
incomplete ASGI responses, session headers and streaming content. Response
events are limited to 1,024, including after an earlier invalid event.
No raw event, authorizer claims, source IP or identifiers enter the tool scope.

The real SDK initializes, lists and calls all ten synthetic tools through v2
events; sequential warm-style invocations pass. Metadata, 401/403 challenges,
method restrictions, cross-environment token rejection, input bounds,
cooperative timeout and sanitized output failures are covered. Independent
review reproduced an event-limit bypass after an invalid first message; it was
corrected before acceptance and retained as a regression test.

Focused Lambda tests: **42 passed**, including seven independent regressions.
Full Windows Python 3.13 offline suite: **754 passed, 3 skipped** (Windows
symlink privileges). Compilation succeeds and the model-free evaluator passes
12/12 cases. These tests use no listener, AWS operation, MAPIT access or paid
inference. GitHub CI is tracked separately on the existing pull request.

Keep `infra/aws/template.json` unchanged and disabled. The next external gate
must specify short dev scope, credit/gross-spend allowance, duration, operator
and owner identity, exact OAuth resource/callback, independent shutdown and
cleanup. Real MAPIT access requires its own bounded read/secret-handling scope.
