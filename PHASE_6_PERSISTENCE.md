# Phase 6 — Persistence & Historical Intelligence

## Goal
Add persistence only if it provides measurable value beyond querying MAPIT on demand.

## Possible benefits
- faster long-range analytics;
- local historical snapshots;
- realtime event history;
- preserving observations MAPIT does not expose historically;
- reduced repeated API reads.

## Decision gate
Measure first.

If monthly MAPIT reads are fast and reliable enough, keep the system stateless where possible.

## Possible persisted data
- normalized route metadata;
- monthly/yearly aggregates;
- realtime state transitions;
- derived events;
- synchronization metadata.

## Requirements if implemented
- idempotent ingestion;
- deduplication;
- migrations;
- clear retention;
- separation of source data and derived data;
- no secrets in the database.

## Exit criteria
Persistence demonstrably improves capability, performance or historical coverage.
