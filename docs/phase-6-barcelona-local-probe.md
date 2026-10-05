# Bounded Barcelona local matching experiment

This is a route-reconstruction research experiment, not persistence approval.
The user authorized necessary research executions and identified Barcelona.
The supervisor approved the following bounded protocol on 2026-09-30.

## Public map preparation

- Geofabrik public snapshot: `cataluna-260929.osm.pbf`, 270,829,999 bytes.
- SHA-256: `b456f79261193dbcad015ddcfa17dd7113fe9c3ab0326fd88287d75e9eb3542f`.
- Header timestamp: `2026-09-29T20:22:51Z`.
- Download ceiling: 300 MiB; transfer timeout: 180 seconds.
- Fixed public longitude/latitude bounding box: `1.8,41.2,2.45,41.65`.
  It covers a Barcelona-area rectangle, not an administrative city boundary,
  and was chosen without consulting private route coordinates.
- Local Osmium 1.16.0 `extract --strategy complete_ways --set-bounds`.
  Complete ways can extend beyond the box; the probe conservatively requires
  every input point to lie within the fixed box.
- Extract size: 67,036,234 bytes. Public OSM files stay outside the repository.
- OSRM image pinned to amd64 digest
  `sha256:c29a50d67b9be17d10773fa2b52bb045ee3fbb8f42e5f9d1c671ce0d9bb21f37`,
  version `v26.9.0-amd64-debian`.
- MLD preparation with `car.lua`, no container network, two CPUs, 6 GiB RAM.
  The car profile is a baseline and does not establish motorcycle semantics.
- Runtime: read-only map, no access logging, no restart, two CPUs, 2 GiB RAM,
  port published only at `127.0.0.1:5000`.
- Preparation completed successfully; extraction reported peak RAM about
  487 MiB, partition about 85 MiB and customization about 61 MiB. These are
  OSRM-reported peaks, not a complete host-memory benchmark.
- A public synthetic Barcelona route-to-match smoke check returned `matched`,
  all tracepoints, low confidence and steps/annotations/names present. It
  confirms the local map runs; it is not a private route accuracy test.

Map data: © OpenStreetMap contributors, [ODbL](https://www.openstreetmap.org/copyright).

## Private input and local request boundary

Use the existing saved-session flow, one bounded account-summary read, one
route-list read with `limit=1`, and one route-detail read. Existing bounded
authentication recovery may retry a read once. The selected route is not
claimed to be the latest: route ordering has not been established.

Choose one actual LineString in feature order; omit Point features and drop
the opaque third ordinate. Do not concatenate features, sample points,
invent timestamps, bearings or accuracy radii, or search other routes on
failure. Accept 2–500 original points; a larger line fails closed. The pinned
binary confirms support for `--max-matching-size`; set it explicitly to 500
(the upstream default is 100). This is a bounded experimental resource limit,
not a change in input accuracy.

Send one `/match` request only to a literal loopback HTTP address. Disable
environment proxies and redirects. Limit request size, response to 2 MiB and
socket timeout to five seconds. Keep geometry and responses in process memory
only; no request URL, body, coordinates, names, IDs or exception details may
be printed or persisted. Runtime access logging is disabled.

Retain only allowlisted categories/booleans/coarse bands. No external matcher,
paid model call, DB, worker, Telegram operation or AWS deployment is in scope.
Independent offline review and tests must pass before the real route read.

## Interpretation

OSRM confidence and tracepoint coverage are engine diagnostics, not measured
ground-truth accuracy. One LineString cannot establish full-route turns,
street coverage or city-wide completeness. MAPIT already marks some source
geometry as inferred; a successful match does not recover unobserved travel.

## Primary references

- [Geofabrik Cataluña](https://download.geofabrik.de/europe/spain/cataluna.html)
- [Osmium extract](https://docs.osmcode.org/osmium/latest/osmium-extract.html)
- [OSRM HTTP API](https://github.com/Project-OSRM/osrm-backend/blob/master/docs/http.md)
- [OSRM tools](https://github.com/Project-OSRM/osrm-backend/blob/master/docs/tools.md)

## Result

Independent tester: ACCEPT after offline review, 40 focused tests and 450
full-suite tests passing; compilation and diff checks passed.

One authorized live execution completed successfully on 2026-09-30. Safe
output only:

```json
{"annotations_present":true,"category":"matched","code_ok":true,"confidence_band":"high","engine":"osrm-local","matching_count_band":"few","names_present":true,"raw_discarded":true,"stage_category":"success","steps_present":true,"tracepoint_coverage_band":"all"}
```

This is an actual MAPIT LineString matched locally, not the synthetic fixture.
All input tracepoints matched and the lowest returned matching confidence was
in the high band. Neither identifies positional error or ground-truth streets.
The protocol did not assess the rest of the route, inferred provenance of this
particular line, feature continuity, full turns, or historical city coverage.
No private values were retained. There was no retry with a different route,
external matching service or paid call.

The temporary serving container was stopped and removed after the experiment.
Only public OSM source/derived map files remain outside the repository for
reproducibility; these do not contain the MAPIT input or output.

## Next research decision

Local matching is now a demonstrated candidate for one real MAPIT line.
Before claiming route reconstruction, define a bounded multi-line evaluation
that preserves source/inferred distinctions, handles gaps and unmatched
points, and measures ambiguity without treating engine confidence as accuracy.
City-wide percentages additionally need an administrative boundary, eligible
road definition, versioned length denominator and representative historical
coverage. This evidence does not approve private persistence or a database.

## All-LineString follow-up

The user requested continued work until the next approval gate. The bounded
protocol is in `phase-6-execution-gate.md`; the follow-up harness is
`scripts/probe_mapit_osrm_route.py`. It reuses the same three bounded source
reads, validates all features before dispatch, then checks every accepted
LineString separately (at most eight, 500 points/line, 2,000 total).
Independent offline review passed before one actual execution. No second
route was attempted; list ordering is still unknown, and the two experiments
are not claimed to use an identical immutable source snapshot.

Safe live result on 2026-09-30:

```json
{"category":"partial_lines","checked_line_coverage":"all","engine":"osrm-local","excluded_point_features":true,"inferred_flag_availability":"all","line_count_band":"few","lowest_confidence_band":"low","max_feature_boundary_gap_band":"long","max_internal_gap_band":"medium","multiple_subtraces_present":false,"raw_discarded":true,"source_inferred_class":"mixed","stage_category":"success","tracepoint_coverage":"partial","whole_route_claim":false}
```

All supplied LineStrings were assessed, but point association was partial and
the lowest matching confidence was low. Source inferred flags were available
and mixed; false is not evidence of independently observed GPS. Point features
were excluded and their role remains unknown. Feature boundary distances are
structural separations, not confirmed temporal GPS dropouts or proof that the
features form a continuous ordered trip. There was no detected OSRM split in
returned matchings, which does not establish continuity across features.

This is a stronger limitation than the earlier single-line feasibility result:
the current evidence supports experimental line-level matching, not an exact
last trip, complete turns or a trustworthy percentage of streets travelled.
The owned temporary container was stopped and removed. No private input or
OSRM payload was retained.
