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
  are configured; remote CI acceptance is not asserted before the run completes.

## Remaining

Production currently retains the previous ten-tool package. A code-only upgrade
needs fresh durable intents, exact ownership/template/code readbacks, independent
closure, reviewed reopening/rollback and final endpoint/tool-discovery checks.
Do not replay initial deployment operators. Retain existing owner/MFA, IAM,
quota 10 and the USD 1/month target, not a billing hard cap.

The new live probe was local against the real bounded cloud-compatible provider,
not a newly activated geographic tool call on production Lambda. A production
tool-discovery check alone would not establish live geographic Lambda output.
Any additional historical read/detail requires a new bounded allowance.

This increment does not add arbitrary place lookup, other named boundaries,
street coverage, missing-track reconstruction, persistent geography, hosted
multiuser or a Telegram worker. MAPIT coordinate semantics, route-history
completeness and physical distance accuracy remain unverified; km presentation
retains the existing UI-correlated conversion basis.
