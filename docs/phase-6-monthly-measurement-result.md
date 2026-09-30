# Bounded monthly baseline result — 2026-09-30

Protocol: `phase-6-execution-gate.md` and `phase-6-measurement-plan.md`.
Runner: `scripts/probe_monthly_measurement.py`. Independent offline review
accepted the bounded live run after 43 focused tests passed. One execution
completed; no retry of the experiment or alternative account was attempted.
Later offline-only fixes refined failed-auth-refresh categories without
changing the successful-run path. Final independent acceptance passed 50
monthly tests; the integrated suite passed 506 tests. No extra live run was
made for those error-category fixes.

The saved-session login preceded the measurement window. Exactly one logical
and wire Core account-summary lookup selected one vehicle ephemerally. Five
identical current-UTC-month Geo reads used `vehicleId`, `from`, `to` and no
`limit=1`; one preceding-month control followed. Responses were bounded to
2 MiB and wire dispatch was counted before sending. No auth recovery wire
retry was observed in these Core/Geo counts. Public discovery and Cognito
traffic are outside these counters and are not asserted to be zero.

Safe output only:

```json
{"category":"success","core_logical_reads":1,"core_wire_gets":1,"coverage_class":"PARTIAL","error_categories":[],"geo_logical_reads":6,"geo_wire_gets":6,"latency_p50_bucket":"<1","latency_p95_bucket":"1-5","monthly_control_class":"disjoint","operation_class":"monthly_measurement","pagination_metadata_observed":false,"repetitions":5,"response_size_bucket":"64-256KiB","success":true,"successful_repetitions":5}
```

Latency buckets summarize the five monthly reads only, including the normal
client/signing/parse path. Core lookup, login and adjacent control are not part
of those percentiles. P95 uses the nearest-rank statistic, which with five
observations is the maximum; this small sample is not a reliability guarantee
or a production latency distribution. The response-size bucket is the maximum
successful body size among those repetitions, not total bandwidth.

Disjoint means no route IDs overlapped with the adjacent control inside this
run. Those IDs were discarded, not stored or hashed. No pagination key was
observed, but this does not prove there is no server truncation or complete
history. Coverage remains `PARTIAL`; no exact dates, route counts, names,
coordinates, URLs, bodies, headers, tokens or IDs were retained.

## Decision supported

For this bounded monthly sample, all five repetitions succeeded, their maximum
latency remained below five seconds, and no response exceeded 2 MiB. There is
no observed interactive-latency problem requiring persistence on this path.
No persisted-path workload was measured, so neither the 50% read-reduction nor
the 30%/one-second latency-improvement gate has been established. Historical
loss or additional retained-event value is also unproven.

Keep stateless as the measured performance default. The user may separately
approve a minimal local distance ledger as a product direction, with explicit
privacy/retention decisions in `phase-6-persistence-proposal.md`. Such approval
must not be reported as a passed empirical performance/history-loss gate.
