# Phase 6 bounded evidence gate — 2026-09-30

The user requested continued work until the next decision gate and previously
authorized necessary research executions. This supervisor protocol permits
bounded measurements only. It does not approve private persistence, a database,
new MCP tools, paid inference, Telegram traffic or AWS provisioning.

## Monthly baseline measurement

Follow `phase-6-measurement-plan.md`: one logical account-summary lookup,
five repeated current UTC calendar-month reads with frontend-shaped `from`/`to`,
and one adjacent preceding-month control. Select one eligible vehicle in memory.
No unfiltered scan, pagination traversal, route-detail reads or cap increase.

Hard limits: 2 MiB per response; at most two wire Core GETs and twelve wire
Geo GETs, reserved before dispatch. Count six logical Geo operations separately.
Only the existing single 401/403 recovery may repeat a logical read; no new
retry/backoff loop. Reject redirects to prevent uncounted wire operations.
Stop on oversized/malformed responses, HTTP 429 or transport failure. The
measurement uses a 180-second deadline after secure saved-session preparation,
checked before dispatch and between bounded body chunks. Each socket read has
at most a 20-second timeout; an already in-flight read or authentication refresh
can finish after the deadline, so this is not a process-wide hard kill timer.
No subsequent wire GET may start after the deadline. Discovery/Cognito traffic
is explicitly excluded from Core/Geo
wire counts and must not be represented as zero or part of those counts.

Emit only a fixed allowlist of operation categories, bounded operational
counts, coarse latency/size buckets, control class, pagination presence and
`PARTIAL`/`UNKNOWN` history coverage. Do not output dates, route counts, IDs,
coordinates, raw bodies, URLs, headers, secrets, names or exception details.
Compare any IDs only in memory and discard; do not hash or persist them.
No cache/store is implemented, and a hypothetical cache read reduction is not
a measured performance improvement.

## Multi-LineString matching assessment

After independent offline acceptance, use one account-summary read, one
route-list read with `limit=1`, and one detail read (1 MiB), selecting one route.
Validate the complete input before sending coordinates locally. At most eight
LineStrings, 500 unchanged points per line, 2,000 points total; fixed Barcelona
box from `phase-6-barcelona-local-probe.md`. No sampling, concatenation, skipping
oversized/out-of-box lines, another route, or additional detail fetch.

Match each accepted line separately in feature order, at most eight loopback
GETs, with the existing proxy-free/no-redirect/16 KiB URL/2 MiB response/5-second
socket bounds. No invented point times, accuracy radii or bearings. Respect
the source feature's boolean `properties.inferred`; absence is unknown,
false is not independently established GPS observation. Point features remain
excluded from matching and are explicitly reported as excluded.

Output only fixed categories, booleans and coarse bands, including input-line
coverage, inferred-flag availability, gaps, confidence and matcher failure.
No ordered private trace or road labels may be retained. Matching all supplied
lines must not be called a complete/accurate route or historical city coverage.
Stop and fail closed on structural/resource/matcher failure; no retries.
Restart the owned temporary read-only/log-none/loopback OSRM container only
for this experiment and remove it afterwards. Public OSM map files may remain.

## Next user decision

Present measured limitations and a concrete minimum persistence proposal,
including which private data would be retained, deletion/retention policy,
and whether source geometry is excluded. Ask for approval before creating
the store or ingesting private data. If the evidence is insufficient, report
that limitation instead of claiming that the persistence gate passed.
