# Geographic queries — acceptance checkpoint

## Accepted

- Frozen public IGN eight-municipality Menorca union, EPSG:4258 to EPSG:4326
  derivative without repair/simplification; attribution and exact hashes in
  [public-boundary README](../samples/public-boundaries/README.md).
- Pure small-area classifier plus optional Shapely 2.1.2 prepared exact-topology
  engine; missing/malformed source geometry is unknown, outside tangency has
  no positive-length inside interval, and crossing routes are not prorated.
- Embedded-list geographic summaries, aware start-in-interval validation,
  duplicate-conflict rejection, route/feature/coordinate/work/response guards,
  failure before another monthly read on budget exhaustion. No detail fan-out.
- Explicit opt-in MCP registration and CLI. Default/dev remain ten tools;
  opt-in adds `geographic_summary` and `summer_geographic_summary` for Menorca.
- Madrid summer window June 1 inclusive–September 1 exclusive, contemporary
  CEST convention for supported years 2002–2031; no general historical timezone
  implementation or automatic exact-trip-date requirement.
- Separate hash-locked 30-wheel ARM package, digest-pinned public asset and
  strict opt-in manifest. Default 28-wheel package excludes optional engine,
  tool module, asset and manifest flag.
- Independent engine/service/tool/runtime/builder/probe review. The optional
  ARM package passed all nineteen fixed synthetic checks in the pinned official
  image, network disabled, memory capped at 256 MiB; authorization/configuration
  negatives and warm repeat included. Local memory/repeated-line checks are
  not a Lambda performance SLA or an adversarial worst-case guarantee.
- Full offline checkpoint: 1,892 tests passed, five Windows fixture skips;
  compilation and the existing twelve-case model-free evaluator pass.
- One real read-only summer-2026 probe passed under the
  [documented protocol](geographic-query-live-protocol.md): one Core/four Geo
  logical reads, eight combined auth/MAPIT wire attempts, about 6.2 seconds.
  No route/device/account identifiers, coordinates, history database or secret
  was saved to this repository. Its live allowance is consumed, not repeatable.
- Known-advisory audit found no known vulnerabilities in the two optional
  runtime dependency versions. Separate geography CI coverage and lock audit
  are configured; all eight remote CI jobs passed on commit `5b41bd5`.
- The injected code-only production upgrade coordinator passed independent
  review and focused tests. It uses a fresh private journal, immutable session
  cutoff, exact old/new templates and code digests, independently verified
  control-plane shutdown, and one-shot update/reopen intents. The only template
  differences permitted are the content-addressed ZIP key and manifest hash.
- A separate discovery-only app-server probe passed independent review and
  23 focused tests: it requires exactly twelve tools without calling any tool
  or model. Full offline checkpoint including the coordinator: 1,904 passed,
  five Windows fixture skips. The final checkpoint, including a real-shaped
  CloudWatch double-threshold regression, passed 1,909 tests with five skips;
  compilation and model-free evaluation remain successful. All eight CI jobs
  passed on `2bf706e`.
- The private one-step operator passed static independent review and three
  fake-journal regressions. Its publication receipt must bind the exact intent,
  archive/manifest and stack/run, with successful PUT, verified HEAD and known
  outcome, both at publication and before downstream steps. Emergency closure
  verifies the exact STANDARD workflow/role/definition and derived execution ARN.
- One live **read-only** upgrade preflight passed twelve account/control reads:
  exact existing template/code, enabled API, unreserved handler, quota 10,
  stable alarm/rule/target and exact independent shutdown definition. This did
  not publish an object, close the service, request an update, reopen the API,
  invoke a Lambda handler, or make another MAPIT read.

## Remaining

Production currently retains the previous ten-tool package. A code-only upgrade
needs fresh durable intents, exact ownership/template/code readbacks, independent
closure, reviewed reopening/recovery and final endpoint/tool-discovery checks.
Do not replay initial deployment operators. Retain existing owner/MFA, IAM,
quota 10 and the USD 1/month target, not a billing hard cap.

The 13:42–15:42 UTC window was nearly exhausted when final operator acceptance
arrived. No production mutation was started; the existing service was left
unchanged and available. A renewed bounded deployment window and fresh durable
intents/readbacks are required; do not replay old initial-deployment operators
or widen the immutable cutoff of the consumed preparation journal. Discovery
and final upgrade receipt helpers remain unexecuted.

The new live probe was local against the real bounded cloud-compatible provider,
not a newly activated geographic tool call on production Lambda. A production
tool-discovery check alone would not establish live geographic Lambda output.
Any additional historical read/detail requires a new bounded allowance.

This increment does not add arbitrary place lookup, other named boundaries,
street coverage, missing-track reconstruction, persistent geography, hosted
multiuser or a Telegram worker. MAPIT coordinate semantics, route-history
completeness and physical distance accuracy remain unverified; km presentation
retains the existing UI-correlated conversion basis.
