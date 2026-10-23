# Project Agent Workflow

Read-only MAPIT (Honda) client and MCP server: local MCP core, route analytics,
realtime, Codex agent adapter, private Telegram interface, opt-in distance
ledger, geographic queries, a retained private single-owner production service
and a retained closed DEV environment for multi-user work (AWS eu-west-1).

Full chronological history and past authorizations: `docs/agent-history.md`
(verbatim pre-split AGENTS.md) — consult it before any operation that might
repeat past work. Every rule below traces to that file; dates are decision dates.

## Current state

- Newest checkpoint (2026-10-09): PR #104 merged at develop cbe749b; a closed
  owner delivery then stopped at `artifact_write_unknown` and must never be
  resumed or replayed. The offline per-operation 30-second deadline correction
  still needed independent review and full frozen source verification (git:
  PR #105, develop 4e1570a). A separate fresh owner decision, source
  CI/protections and reviewed private authority precede any new live attempt.
  No owner runtime update, API opening, MAPIT session or real E2E is accepted.

## MAPIT safety

- MAPIT is read-only in all phases. Never send `POST`, `PUT`, `PATCH` or
  `DELETE` to MAPIT except the Cognito calls strictly required for
  authentication. Do not invent capabilities or brute-force endpoints.
- Keep injectable interfaces, direct-only/no-redirect transports, the general
  2 MiB MAPIT response ceiling and bounded auth recovery (Phase 7, 2026-09-30);
  ask the user before changing those defaults.
- No MAPIT history probes, month/date scanning, unfiltered reads or per-route
  detail reads without a new bounded allowance; no automatic ledger sync.
- Distance ledger (2026-09-30): local SQLite and alias key outside Git and
  OneDrive; pseudonymous aliases, UTC day/native distance, no coordinates,
  streets or secrets; no automatic collection; ignore `complete` for admission
  and reject the whole batch on invalid facts (no silent exclusions).
- Kilometre presentation (2026-10-01): preserve native fields; do not change
  odometer/speed units or imply physical-distance accuracy; missing/malformed
  segment flags mean unknown. No inferred road reconstruction.
- Geography: public-source research only; no private geometry persistence or
  stored coordinates/IDs/history facts from probes.
- Production holds only the MAPIT session (no password/history database); do
  not migrate the local ledger to AWS (2026-10-03).

## Consumed operations: never resume, replay, re-run or re-create

General rules (all dates):
- Consumed intents, journals, windows, tokens, receipts and envelopes are
  immutable evidence, never replayable authority. Never mutate, extend, widen or
  renew an old window/cutoff; never reuse a consumed write intent.
- Interrupted, ambiguous or uncertain runs are held, never resumed or retried
  automatically. An absent object or empty/filtered read is never permission to
  replay or evidence of absence. Stop on any ambiguous write or failed login.
- No historical journal/schema/receipt may change; consumed journals are not
  migrated. Do not relax historical rollback guards, KMS denies or validators.
- Never follow or persist a CloudFormation event `NextToken`.

Owner delivery / real-MAPIT DEV (2026-10-09):
- Owner delivery after PR #104 (cbe749b) stopped at `artifact_write_unknown`.
- Owner delivery preparation after PR #102 (bb601f9) stopped at
  `private_inputs_unverified`: preserve it, do not resume; never rewrite/rebind
  historical authority or rotate keys. Preserve the unused local archive.
- Any acknowledged update held by a capsule persistence failure: never replay.
- MAPIT key publication (ca94c92, CI 37955083936, SecureString version one):
  never regenerate, overwrite, rotate, republish or replay these keys.
- Owner invitation `owner_invitation_accepted` (PR #93, ca94c92): never replay;
  never revoke/revive the owner row implicitly.
- Owner invitation attempt stopped at `bootstrap_readback` (PR #92, b7be46f):
  preserve the failed envelope.
- Real-MAPIT namespace bootstrap creation (PR #91, 0f11fee): never replay; never
  regenerate the bootstrap-authorized owner tenant key.
- MAPIT bootstrap preflight stopped at `runtime_unverified` (PR #90, bc90430):
  preserve the envelope; do not extend its window. Expired bootstrap authority
  is parsed only, never executed or renewed.
- Retained DEV owner OAuth stack creation (PR #81, 2118d9b): never replay or
  repeat creation with a fresh journal.

Synthetic multi-user DEV (2026-10-06/07):
- Binding table SSE-only update and synthetic A/B storage proof (PR #78,
  4169fa4, CI 37646210883): never replay, reset historical users, rotate or
  republish keys, delete/recreate resources or relax guards.
- Identity-binding four-resource stack creation (PRs #74–#76, d375e4e) and the
  storage probe stopped at `storage_exercise_unverified`: never replay; its keys
  journal is not permission to regenerate/overwrite keys.
- Pending identity bindings: never replay; retain any possibly published secret
  for separately reviewed reconciliation.
- Hosted multi-user DEV acceptance (PR #69, f529fd0, CI 37606627964): all its
  intents consumed. A stays terminally revoked; B keeps synthetic authorization.
- Continuation stopped at `archive_failed`/`arm_probe` (PR #68, 9421f8f) and
  attempt stopped at `runner_failed` on a566d28: do not repeat resets or delete
  the now-owned authorizer; no automatic third recurring reset. Do not propose
  login without a newly authorized reset (credentials were never persisted).
- 6b09eb2 (PRs #63/#64): DescribeKey role/boundary repair and orphan deletion;
  never repeat them. Preserve its stopped hosted journals and long-path envelope.
- 0221545 (PRs #61/#62) and 5b6c379 (PR #60): resets, KMS role repair, orphan
  cleanup, artifact publication and rolled-back updates are consumed.
- Technical users: never create an alternative A or extend its 300-second
  window (86e58bf); do not rerun the original recovery; reset journals on
  064e231, 545b7fd and a7bbd0a are terminal; never reset either user silently.
- 4d1db49 role update/setup/controls, and 79ad52e (PRs #50–#52) rolled-back
  roles update: never repeat.

Retained DEV CD and identity (2026-10-05/06):
- `honda-mapit-mcp-dev-retained` stack, created once from 5d6e31a: never replay;
  never write a new verifier source into the original creation binding.
- Readonly-proof role stack (ee0cfec), artifact bootstrap (PR #37, b8e5a23),
  four-resource CD role stack (4ae5408) and controls stack (201c07d): never
  replay their create intents/tokens or alter their source/window/token.
- Closed four-resource IAM identity stack (creation source c044f25): never
  replay; never use a distinct verification source for a write.
- Environment role-ARN metadata secrets were submitted once: do not repeat or
  overwrite these bindings implicitly.
- Claim-discovery runs, STS runs 37338161383/37338166318, dev run 37341041504,
  dev proof 37343136563 and prod proof 37344958197 are consumed; none is
  permission for another run.

Geography, Phase 6-8 and production (2026-09-30 to 2026-10-03):
- Expired geography operators and the Menorca and Barcelona production upgrade
  journals: never replay; never reuse initial-deployment write intents.
- Summer-2026 geography probe: do not repeat it, scan other dates or request
  details.
- Route-flag comparison, July 2025 availability read, current-month imports and
  the two screenshot-to-API comparisons (2026-10-01): do not repeat or expand.
- Phase 8 closed rehearsal stacks and later dev rehearsals: do not recreate
  implicitly; never reset a resource's start time or execution window.
- Production real smoke (2026-10-03): do not repeat live queries automatically.
  Interrupted OAuth callbacks are superseded, never reused.

## Standing boundaries and approvals

- Past time-boxed authorizations (work windows) are expired; any new
  AWS/production/billable action needs fresh explicit authorization.
- Region eu-west-1; regional Lambda concurrency quota stays 10 (user chose to
  keep 10, 2026-10-02; unchanged through 2026-10-09). No quota increase.
- Retained DEV gross target USD 1/month, not a hard billing cap (2026-10-06;
  real-MAPIT namespace within it, 2026-10-09). Production target USD 1/month
  gross, no hard cap (2026-10-03). Budget notification and cost-allocation tag
  activation are unapproved; do not claim a hard cap or measured monthly cost.
- Production is the permanent private single-owner service with its permanent
  Codex connection (2026-10-03). No production multi-user promotion is
  accepted; hosted multi-user DEV acceptance precedes notification for a
  separate production deployment (2026-10-06). Present the exact
  artifact/change and recovery before any production update (2026-10-05).
- Definitive owner Cognito identity/MFA (2026-10-02): never reset or delete the
  retained user, pool, domain or enrollment client; do not automate the
  personal password/MFA. The DEV-only OAuth client in that provider (2026-10-09)
  must preserve every existing client and the pool/domain/MFA.
- Telegram is owner-only (2026-10-05); expansion waits for known incremental
  cost and separate approval. Live Telegram operations are
  supervisor-authorized; the only Telegram write is bounded `sendMessage`; no
  persistent worker or webhook.
- No paid models or paid inference.
- Multi-user DEV scope (2026-10-06): isolated test pool with MFA off only there,
  two technical users, authorization table, synthetic data, bounded opening with
  armed closure. Real-MAPIT DEV namespace with independent keys/secrets and
  minimal DEV read permissions (2026-10-09); legacy synthetic bytes, tables,
  keys and consumed journals stay immutable. No IAM expansion, new authorizer,
  public signup or historical account reset/revival.
- Each new live operator needs independently reviewed source, fresh source CI
  and protections, and new exact private authority/journals.
- Dev source gate (2026-10-06) follows the production enforcement boundary:
  `validate_source_gate` reads only the fixed repository, `develop` ref, bound
  CI run/workflow/jobs and clean local source; no administration routes, writes
  or deployment. The proposed GitHub App gate is superseded: do not create or
  install an App or upload a personal token for it.
- Repository is public (2026-10-05), retaining the author email. Public source
  does not authorize OIDC/IAM activation or expose the private MCP service.
- Reuse the existing GitHub OIDC provider without mutation. Approval of a
  protected run never extends to later production updates or other runs.
- Retained DEV CD remains in progress: do not call partial components complete.
- Do not modify other projects (for example `aws-remote-mcp`) or other MCP
  servers/global Codex configuration.
- Out of scope unless separately approved: agent UI, frontend, webhook
  deployment, Home Assistant/HA integration.

## Secrets and private data

- Never commit credentials, tokens, AWS keys, Telegram bot tokens, or real
  personal/device/location/chat/user IDs.
- No key bytes or key hashes in Git, archives, environments, journals or the
  vault. Passwords/tokens stay in memory only.
- Private operator journals, receipts and identifiers stay ACL-protected outside
  Git and OneDrive. Preserve immutable evidence privately, not in public Git.
- Do not commit financial balances, account/credit identifiers or
  browser/session data; keep account confirmations categorical. Do not publish
  real owner/account bindings in GitHub artifacts.

## Testing, CI and merge practice

- `develop` and `main` require eight app-bound CI checks, strict freshness,
  PR/admin enforcement, no force-push/deletion; environments require owner
  acknowledgement. Merge PRs normally after green checks.
- Do not substitute the PR run for the integrated push CI or weaken source
  gates. Use a separate clean deployment worktree for live gates.
- Accept work on offline tests, compilation, model-free evaluation (12/12) and
  the pinned network-denied official schema checker. SDK-dependent tests are
  mandatory in the pinned SDK CI job. Synthetic/offline acceptance is never a
  cloud receipt or permission.
- Temporary wakefulness is owned: renew it explicitly when needed, remove it
  before final handoff and never change persistent power/display settings.

## Roles and workflow

Reuse three persistent roles across phases; do not create fresh agents for
routine work. The supervisor owns scope, sequencing, decisions, integration and
acceptance; escalate effort only for a demonstrated blocker. Use the
provider/model currently selected by the user; earlier model assignments are
historical (see history).

- `researcher`: investigate MAPIT, public implementations, frontend bundles,
  endpoints, payloads, history, and WebSocket behavior. Prefer primary evidence.
- `implementer`: make bounded code changes only after the relevant evidence and
  decisions are documented.
- `tester`: independently review changes, add or run offline tests, and check
  security, error handling, and regression risk.

Use this normal sequence when practical:

1. Researcher gathers and documents evidence.
2. Supervisor approves a bounded implementation task.
3. Implementer changes code and runs focused tests.
4. Tester reviews and tests independently.
5. Implementer fixes concrete defects; supervisor accepts or rejects.

Each worker report should be brief: Task, Findings, Files changed, Tests, Open
questions, and Supervisor must retain.

## Project Memory

Treat repository documentation as the durable source of truth. Update findings
incrementally, especially:

- `docs/mapit-authentication.md`
- `docs/mapit-endpoints-discovered.md`
- `docs/mapit-data-inventory.md`
- `docs/mapit-routes-investigation.md`
- `docs/phase-0-findings.md`
- `docs/phase-0-status.md`
- `docs/phase-3-status.md`
- `docs/phase-4-agent-contracts.md`
- `docs/phase-5-telegram-contracts.md`
- `docs/phase-5-status.md`

Distinguish confirmed facts, evidence found in frontend/code, hypotheses, and
open questions.

Before expanding the MCP core, agents, tools, evaluations, or AWS integration,
read:

- `C:\Users\herre\OneDrive\Desktop\herrerogusano's vault\04 Knowledge\AI Engineering\AI Engineering.md`
- the task-relevant guides linked from that index
