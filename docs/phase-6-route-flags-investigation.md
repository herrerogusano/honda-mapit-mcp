# Route completion flags — bounded investigation gate, 2026-09-30

The user chose investigation before importing/filtering (`investiga primero`).
This authorizes only the bounded research below, not a ledger-policy change,
private ingestion, background worker, external matcher, Telegram operation or
paid inference. The vault delegation/E2E guidance is reused: disjoint worker
files, independent safety review, pre-dispatch budgets, closed safe outputs and
separate offline/live evidence.

## Public evidence

The researcher revisited the documented
[MAPIT public entry bundle](https://app.mapit.me/assets/main-CqxnPnTm.js):
764,221 bytes; SHA-256
`2c9f33db11e524cb412fbd45b5aa920b0c820e0418f5cbf82926f0aadc445f06`.
Its route-list parser accepts ID, distance, start/end timestamps, GeoJSON and
optional `startsAtLastKnown` with a false default. The detail parser also
accepts metric/timing/geometry fields. Neither parser gives `complete` or
`merged` route semantics; unrelated library text is not evidence.

The low-level list builder forwards `includeInProgress`, but its dashboard
caller supplies only `from`/`to`. The shared query serializer applies
`String(value)` and URI encoding to defined values. Explicit booleans therefore
encode as lowercase `false` and `true`; undefined is omitted. This supports
the request forms, not backend behavior or the meaning of response flags.

Official MAPIT support explains that dashed trace segments represent areas
without coverage, and that trip statistics can differ from reality due to GPS
signal. Neither article defines the API's `complete` field or links it to
`inferred`/`startsAtLastKnown`. Those potential relationships remain hypotheses,
not a basis for changing history ingestion.
Sources: [dashed trace segments](https://faq.mapit.me/por-que-el-trazo-de-mi-trayecto-tiene-tramos-en-linea-discontinua/),
[available statistics and GPS caveat](https://faq.mapit.me/que-datos-puedo-consultar/).

## One authorized comparison

Before execution, implement and independently review
`scripts/probe_route_completion_flags.py` with offline fixtures.

- Saved native Windows session, with existing discovery/Cognito/refresh
  behavior; no password input or new ledger key/database creation.
- One account-summary Core read, one eligible vehicle selected in memory.
- Fix `now` once and use one current UTC month window for all variants.
- At most three Geo `/v1/routes` reads: omit `includeInProgress`, then `false`,
  then `true`. No `limit=1`, because this established bounded month is the
  comparison sample; no unfiltered request, different month, route detail,
  cursor following or other parameter experiments.
- Each Core/Geo body is capped at 2 MiB before decoding. Route array limit
  10,000; reject invalid envelope/items/IDs/duplicates or pagination tokens.
- At most two Core and six Geo wire GETs including one possible existing
  401/403 authentication recovery per logical GET. Reserve before dispatch;
  failed attempts consume the cap. No redirects/proxies or other retries.
- Use the accepted measurement transport: 180-second post-login window,
  chunk deadline checks and at most 20-second socket timeout. A socket/auth
  operation already in flight is not hard-cancelled by that window.
- Stop the entire comparison on the first error or ambiguous response. No
  automatic second execution; do not import or silently exclude any route.

## Allowed analysis and output

Raw response bodies, route/vehicle IDs, timestamps, native distance and any
geometry stay in memory only and are discarded. No route count, actual date,
distance, coordinate, street, signed URL, token or personal identifier is
printed, saved or committed. No geometry coordinates need to be analyzed.

The output is a fixed allowlisted structure: success/error category, operation
read counts, current-UTC-window/PARTIAL labels, and per-variant flag classes
(`empty`, `all_true`, `all_false`, `mixed`, `unknown`). It may report only
existence booleans for `complete=false` observations with valid end more than
24 hours old, start more than seven days old, positive finite native distance,
inferred feature flag or `startsAtLastKnown=true`. These are observations,
not a semantic definition of `complete`.

Compare ID sets and selected fact signatures only in memory; output
`same`/`different`/`unknown` or booleans. Equality is limited to this sample,
and non-equality could reflect normal updates between sequential reads rather
than the query filter. No match/mismatch identifies a particular route.
Missing/malformed timing/metric flags must not be interpreted as zero values
or as evidence that a trip is active. No success implies full-history coverage.

## Decision boundary

Old explicit end timestamps on false-marked routes would contradict the
assumption that the boolean simply labels currently active trips in this
sample. They still would not establish whether it measures tracking quality,
backend normalization, continuation, missing geometry or something else.
If public/live evidence cannot settle those meanings, record them as unknown;
do not create a new "complete-only" history policy by inference.

## Accepted execution and safe observations

Independent tester acceptance preceded one live execution. Focused suite:
17 passed; full local suite: 585 passed, 3 skipped (Windows symlink creation
limits). The supervisor ran the diagnostic once; no retry or import followed.
Observed operation counts were one logical/wire Core GET and three
logical/wire Geo GETs. Saved-login auth remains outside those MAPIT counts.

The approved redacted output was:

```json
{
  "category": "success",
  "complete_class": {"false": "all_false", "omitted": "all_false", "true": "all_false"},
  "core_logical_reads": 1,
  "core_wire_gets": 1,
  "coverage": "PARTIAL",
  "false_has_inferred_feature": true,
  "false_has_past_start_older_7d": true,
  "false_has_positive_native_distance": true,
  "false_has_starts_at_last_known": true,
  "false_has_valid_past_end_older_24h": true,
  "geo_logical_reads": 3,
  "geo_wire_gets": 3,
  "omitted_vs_false_id_set": "same",
  "omitted_vs_false_same_fact_signature": true,
  "omitted_vs_true_id_set": "same",
  "omitted_vs_true_same_fact_signature": true,
  "success": true,
  "window": "current_utc_month"
}
```

Existence booleans need not describe the same individual route; no per-route
cross-tabulation, counts, coordinates or exact dates were retained. The
end-age observation specifically requires aware timestamps ordered
`startedAt <= endedAt < fixed_now - 24h`.

## Conclusions and next implementation gate

Confirmed for this sample: all returned routes have `complete=false`, including
at least one with coherent old start/end timestamps. There are positive
finite native distances. Filtering on `complete=true` would exclude the entire
observed sample, not merely a currently active trip. All three query variants
returned the same IDs and selected fact signatures (ID/start/end/distance/
complete), not necessarily identical full GeoJSON or every response field.

Do **not** equate `complete=false` with a currently active trip. The precise
backend meaning remains unknown. Inferred geometry and last-known-start flags
were observed, and the public FAQ establishes that coverage gaps occur, but
those facts do not prove that `complete` is a tracking-quality flag. Similarly,
equal variants do not prove that `includeInProgress` is globally ignored: no
known currently active control was tested, and reads were sequential.

Recommended next user decision: stop using this unverified boolean as the
history admission gate; validate source identifiers, coherent start/end times
and finite nonnegative native distance instead, retain unverified-completeness
labels and transactional conflict rejection. Define explicitly how missing,
inconsistent or future end timestamps are handled before ingestion. No quality
or "finished" truth claim follows merely from an API field name.

The investigation itself did not authorize changed admission or ingestion.
The user subsequently approved the recommended revised contract. Implementation
now ignores `complete`, validates aware coherent nonfuture start/end times,
identifiers and finite nonnegative distance, and retains unverified labels.
Independent review accepted the change. The next authorized live attempt
passed validation but failed local permission verification before committing
facts; see [ledger result](phase-6-ledger-result.md). No Telegram operation or
project AWS resource was created.
