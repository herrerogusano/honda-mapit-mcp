# Project Agent Workflow

## Scope

Phase 0 (MAPIT research, API discovery, and the reusable standalone Python
client), Phase 1 (local read-only MCP core), Phase 2 (route analytics), Phase 3
(the reusable read-only realtime component), Phase 4 (the local Codex-to-MCP
conversational-agent adapter and deterministic evaluation), and Phase 5 (the
bounded private Telegram interface) are complete. Phase 6 is COMPLETE for the
approved opt-in distance ledger described in `PHASE_6_PERSISTENCE.md`
and `docs/phase-6-status.md`. On 2026-09-30 the user accepted the minimal local
distance-ledger proposal without extra encryption: local SQLite outside Git
and OneDrive, pseudonymous route aliases, UTC day/native distance, rebuildable
aggregates, retention until explicit deletion, no coordinates/streets/secrets.
Only that bounded opt-in ledger is accepted; no automatic collection or claim
of measured latency improvement/history completeness. Offline implementation
is accepted. Historical gates and bounded allowances follow; the first import stopped before storage on
`complete=false`. Its meaning is unconfirmed, not evidence of an active trip.
No further live import or implicit filtering is authorized by that execution;
the next gate is the explicit treatment of those flagged routes.
On 2026-09-30 the user chose investigation first. The only additional live
research authorized is the bounded one-Core/three-monthly-variant comparison
in `docs/phase-6-route-flags-investigation.md`, after independent offline
acceptance. It does not authorize importing/filtering private history.
That one comparison is complete: all sampled routes were false-marked,
including a coherent old-end observation, and all variants returned the same
IDs/selected fact signatures. Do not repeat it automatically. The next gate
is user approval of a revised admission contract; neither the precise flag
meaning nor true active-route filter behavior is confirmed.
The user subsequently approved replacing that gate with identifier/timing/
distance validation and resuming bounded imports. Ignore `complete` for
admission; require aware coherent start/end values not in the future, keep
native units and unverified labels, and reject the entire batch on invalid
facts or conflicts (no silent exclusions). The protocol permits one current
UTC-month import, a second only after success to verify no-op deduplication,
and redacted local/offline query checks. No other month, unfiltered read,
detail, automatic sync or new external write is authorized by this gate.
The user also asked whether routes predate August 2025. One separate July
2025 availability read is authorized: one Core and one Geo logical GET,
at most two wire GETs each with existing auth recovery, 2 MiB bodies and
10,000 routes, no proxies/redirects, no persistence or month scanning.
Validate returned start timestamps belong to July before reporting presence.
An empty July response is not proof that all earlier history is absent.
That July read is complete and confirmed routes in the requested window,
using one Core and one Geo wire GET. Do not repeat or expand it automatically.
The revised-policy current-month import passed validation but stopped at
`history_permissions_failed`, with no facts committed. The conditional second
import was not executed. Diagnose local permissions without more live reads;
any further import requires a new bounded allowance.
The user has now explicitly authorized fixing local permission verification
and one additional current-month import, followed only on success by one
deduplication import and redacted local-query checks. Diagnose and verify the
local checker before consuming that new live allowance. No broader history
scan, automatic retry or increased ACL privilege is authorized.
That renewed allowance is now consumed successfully: local preflight passed,
one current-month import committed minimal facts, the second added no facts,
and day/month/year local queries passed with zero upstream attempts. The
Windows PowerShell child environment excludes inherited `PSModulePath` without
changing the parent environment or relaxing ACLs. Private SQLite/alias key
exist outside Git/OneDrive; no automatic sync or further live read is approved.
Phase 7 is at the explicit direct-only/proxy and general 2 MiB response-cap
compatibility gate in `docs/phase-7-audit-preparation.md`. Research/preparation
is accepted, not implementation of those compatibility changes. The user
requested continuing until the next gate; ask for this decision before
changing those defaults. On 2026-09-30 the user approved that gate: Phase 7
was implemented for direct-only/no-redirect transports, general 2 MiB MAPIT response
ceiling, bounded auth/discovery input, offline reliability/security review,
safe diagnostics, dependency/CI checks and synthetic portfolio demonstration.
Preserve injectable interfaces, read-only MAPIT and bounded auth recovery;
no new live MAPIT/Telegram operation or paid model call is authorized. Phase 7
is COMPLETE with independent offline acceptance and five green CI jobs on
commit `5643a36`. Phase 8
has no deployment/cost approval. The user subsequently authorized Phase 8
design, public price research, cost estimation and offline IaC preparation
after Phase 7 acceptance. Do not use AWS SDK/account inventory, create or
deploy resources, transfer credentials, or invoke paid models/APIs. Stop at
the explicit dev deployment/cost/identity gate, with prod/model gates separate.
On 2026-10-01 two separately authorized screenshot-to-API route comparisons
were completed (the second included detail). Their live allowances are consumed.
The user then approved offline additive kilometre presentation and a source
inferred-segment indicator, not road reconstruction. Preserve native fields
and ledger facts/schema; convert only explicit kilometre companions using the
UI-correlated metre-scale interpretation, with its evidence limitation. Do not
change vehicle odometer/speed units or imply physical-distance accuracy. Missing
or malformed segment flags mean unknown, not verified tracking. No new detail
reads per list route, live calls, re-imports, private data/geometry persistence,
AWS deployment or model inference is authorized by that implementation gate.
That additive presentation implementation is now independently accepted offline:
677 tests pass with 3 skipped, including synthetic MCP structured serialization.
Retain its UI-correlated conversion basis and nullable source-flag limitations;
it is not authorization for new route probes or inferred-road reconstruction.
On 2026-10-01 the user approved the next Phase 8 local-only block: synthetic
Streamable HTTP integration, cryptographic access-token verification, dev/prod
policy isolation, and bounded-request/authorization-negative tests. Require an
explicitly synthetic factory/provider; no default local MAPIT session, private ledger,
credential loading, live MAPIT/Telegram/model call, AWS account operation,
deployment or Codex configuration/login change is authorized. Keep the IaC
disabled. Real Cognito/PKCE interoperability and live upstream deadline handling
remain separate acceptance requirements before activation.
The local block is independently accepted: 35 focused HTTP tests and 712 full
offline tests pass (3 skipped), with real SDK protocol serialization but only
synthetic data. No deployment, actual OAuth login or live upstream deadline
acceptance follows from this result; stop at the separate dev gate.
After a read-only console credit review, the user requested advancing. The next
approved implementation is the offline synthetic Lambda/payload-v2 composition
in `docs/phase-8-lambda-local-contract.md`, now independently accepted with 42
focused and 754 full offline tests passing (3 skipped). Keep infrastructure disabled and
unchanged; no account SDK operation, deployment, private-data transfer, live
MAPIT/Telegram/model call or credential handoff is implied. Do not commit
private financial balances, account/credit identifiers or browser/session data.
The user subsequently approved a bounded dev gate on 2026-10-01: eu-west-1,
synthetic tools only, resources for at most one hour, endpoint active at most
five minutes, USD 1 gross allowance (not a guaranteed billing hard cap), and
shutdown/deletion of newly created resources. No prod, MAPIT data/session,
Telegram or paid model call is included. The initial preflight made one STS
identity read and one Lambda account-settings read, with one CLI attempt each
and only categorical/count outputs. Authentication succeeded with a non-root
identity; regional concurrency limit and unreserved pool were both 10.
No resource was created or activated. Provisioning is suspended: positive
reserved concurrency is unavailable under the documented unreserved-pool rule.
Do not remove reserved concurrency 0, increase quotas, or switch region/runtime
without the user's next decision. A shared-pool fallback would lose an exact
per-function concurrency cap and needs explicit approval plus tested independent
shutdown. Runtime Cognito configuration, ARM packaging, exact callback/owner
binding and cleanup still require preparation and review before creation.
The user then authorized gates of the agreed work for a two-hour window on
2026-10-01, ending about 17:53 Europe/Madrid. Maintain the dev-only/synthetic,
USD 1 gross, five-minute endpoint and one-hour resource limits; no prod,
MAPIT/session migration or paid inference. Coordinate a regional increase only
after independent project controls are reviewed; no shared-pool fallback.
The `aws-remote-mcp` owner chat completed its own offline concurrency preparation;
do not modify that repository here. A single Service Quotas read confirmed
applied quota 10 and adjustable=true; no increase request was made.
The dev-only Cognito/public-key synthetic factory and fail-closed environment
entrypoint are independently accepted locally with 830 tests (3 skipped),
compilation and evaluator 12/12. The exact generated-fixture ZIP passed all ten
tools and negative authorization/configuration cases in the pinned official
ARM image with networking disabled. Immutable `.invalid` factories remain closed;
no arbitrary/live provider, runtime key discovery or local credential lookup.
See `docs/phase-8-aws-preparation.md`. Additional read-only inventory confirmed
both other-project MCP handlers have reserve 0 and both default HTTP endpoints
are disabled; shutdown reservations and intended billing-account binding remain
unverified. Two MCP reserves plus two dedicated DEV shutdown reserves would
require a structural floor of 104, not yet requested. Actual public-key retrieval,
final deployment packaging, callback/owner binding, shutdown/IaC/cleanup wiring
and cloud interoperability remain separate reviewed prerequisites. No resource
has been created, quota requested or function invoked.
The two-hour external authority has expired. Subsequent resumed work is local
only: immutable 300-second maximum execution-window guards and the injected-client
shutdown core are independently accepted with 896 tests passed (3 skipped),
compilation and model-free evaluator 12/12. The shutdown core has no SDK/network
construction and its tests use fake clients. Real shutdown packaging/IAM/triggers,
independent capacity and crash-safe cleanup remain open; no cloud authority is
renewed by that acceptance. See the resumed-preparation section in the AWS doc.
On 2026-10-02 the user renewed the same bounded dev authority for two hours,
09:32:29–11:32:29 UTC (11:32:29–13:32:29 Europe/Madrid), including temporary
display/system wakefulness. Retain synthetic-only eu-west-1, USD 1 gross,
five-minute endpoint and one-hour resource limits; no prod or paid inference.
One regional increase request for 104 was rejected as below the default 1,000;
no larger request was made or quota changed. The user explicitly chose keeping
10 and continuing. Prepare the bounded dev shared-pool alternative without
changing project IAM/OAuth/data isolation or the other repository. Independent
control-plane closure must not depend on obtaining another Lambda execution
slot. Fresh quota/unreserved 10/10, reviewed/armed closure and cleanup, exact
owner/callback and first login remain prerequisites before activation.
The dedicated SDK shutdown entrypoint/minimal ZIP/component are independently
accepted offline; actual botocore Stubber and exact ARM ZIP probes passed with
networking disabled. The component Lambda remains reserve 0, unused by the
shared-pool approach, and is not a complete deployable shutdown system.
No resources have been created or activated. See the renewed-authority section
of docs/phase-8-aws-preparation.md; renewal is not perpetual authority.
The pure fixed-target Step Functions shutdown definition is independently
accepted offline and one account-side ValidateStateMachineDefinition call
returned OK with zero error diagnostics. No workflow execution, schedule or
resource was created; IAM/closure/cleanup and interactive owner login are still
prerequisites. Control-stack deletion cannot be assumed automatic or guaranteed.
The disabled five-resource Step Functions/Scheduler control component generator
is independently accepted with the final local suite at 1013 passed, 4 skipped
(Windows symlink fixtures), compilation and model-free evaluator 12/12. Exact
API/function/IAM/trust scopes are tested; PATCH requires disable=true, schedule
is DISABLED, date validation is syntax-only and no deletion wiring is included.
The original application scaffold remains unchanged/disabled. The user can do
first login/MFA, but the available AWS session's match to the intended credit
account remains unconfirmed. Do not create resources until that binding and
complete reviewed cleanup/timing/owner/callback prerequisites are satisfied.
The user subsequently confirmed the available AWS session is the intended
account. Keep that confirmation categorical; no account number/balance in Git.
Owner/callback, first login and complete reviewed cleanup/timing wiring remain
open before creation. No quota increase or other-project change is authorized.
The user also approved a temporary Codex OAuth connection only for this dev MCP,
with its own callback/listener/client and removal after the test. Preserve other
servers and global defaults. One synthetic loopback CLI URL-preparation probe
made no login/code exchange/model call or persistent config edit; actual callback
binding remains open. Do not infer undocumented callback suffixes or persist
authorization URLs/state/verifiers/tokens in Git. First-login readiness alone
does not authorize resource creation before the remaining reviewed prerequisites.
The offline runtime ZIP builder and fixed-app disabled cleanup component are
independently accepted, with 1062 full-suite tests passed and 4 Windows symlink
skips, compilation and model-free evaluator 12/12. The builder pins 28 ARM wheels
and fourteen source modules, includes public JWKS/manifest beside the entrypoint,
and rejects repository/OneDrive/business-OneDrive external inputs/output. Two
concrete packaging defects were fixed and independently regression-tested; no
real Cognito snapshot or login is implied. Control DefinitionString preserves
ASL ResultPath null and passed one bounded CloudFormation syntax check; cleanup
also passed syntax only. Runtime IAM, tripwire alarm/EventBridge, reviewed timing,
owner/callback, real ARM artifact acceptance and cleanup orchestration remain
separate before deployment. No resources have been created, activated or invoked.
The renewed two-hour external authority ended at 11:32:29 UTC on 2026-10-02.
No resources were created or activated during it. Subsequent work is local/public
research only; no further account reads, deployment or quota mutation without
renewal. Commit 021cbb7 has six green CI jobs. A new isolated cfn-lint schema
check has unresolved metadata interpolation findings and a Stage Tags schema/
documentation discrepancy; do not treat that check or ARM packaging as accepted
until the specific failures are resolved and independently reviewed.
Subsequent local ARM acceptance passed the exact builder-produced synthetic ZIP
in the pinned official ARM image with network disabled: all ten tools, warm
repeat, authorization negatives and prod/missing-config denial. The original
failed harnesses used an expired startup window and ZIP rather than JWKS digest;
runtime guards were unchanged. No real Cognito login is implied.
The additional static schema checker is independently accepted with 24 focused
tests. The offline app draft changed only metadata prose and tag placement:
ambiguous optional Stage Tags were omitted and identical project/environment
tags placed on the API parent, with no inheritance claim, ignored rule, runtime,
IAM, throttle or disabled-default change. All four drafts passed the isolated
pinned cfn-lint checker with Python socket/DNS denied. A reusable ARM probe and
the request-tripwire contract remain separate local preparation; no renewed
account authority or deploy-ready claim follows.
The reusable ARM probe is accepted and saved in `fda78fb` with seven green CI
jobs. Subsequent local work adds the disabled request alarm/EventBridge trigger
to the independent shutdown workflow and composes its eight resources with the
three cleanup resources. Independent review passed 100 focused tests; the full
local checkpoint passed 1136 tests, four Windows symlink skips, compilation and
the 12/12 evaluator. Five fixed synthetic templates passed schema checks.
Timing uses explicit positive UTC epochs, a 120–300 second arming lead, runtime
expiry at activation +300 seconds and scheduled close 120 seconds before expiry.
App deletion is requested at first resource +45 minutes, leaving a nominal
15-minute cleanup tail; no SLA or automatic control-stack deletion is claimed.
Bootstrap-generated API/pool/client/subject values are verified after closed
creation and before activation; requiring generated IDs before creation is
circular. Callback is resolved before configuring the client. A closed bootstrap
and exact deletion-role/artifact procedure remain preparation work, with AWS
authority still expired. No resources have been created or activated.
The subsequent closed-rehearsal preparation is independently reviewed: the
six-resource dev-only bootstrap rejects inherited integrations and remains
endpoint-disabled/reserve-zero. Its twelve-resource control bundle retains
eight shutdown/tripwire resources and adds four exact-stack cleanup resources,
including a dedicated deletion role explicitly passed to CloudFormation.
The local checkpoint passed 1197 tests (five Windows symlink skips), compilation,
the 12/12 model-free evaluator and eight fixed synthetic schema checks. See
`docs/phase-8-closed-rehearsal.md` for the next concrete renewed-authority gate.
Actual scheduled shutdown, deletion permissions and final cleanup still require
closed AWS acceptance; no OAuth login or endpoint activation is part of it.
On 2026-10-02 the user renewed two hours of bounded dev authority, conservatively
13:29–15:29 UTC (15:29–17:29 Europe/Madrid), with temporary display/system wakefulness.
Proceed through the closed rehearsal and in-scope gates without waiting for the
absent user. Preserve eu-west-1, quota 10, synthetic-only, USD 1 gross allowance
and one-hour resource target; no production, private MAPIT/Telegram operation,
paid model inference or bypass of human OAuth/MFA. Cleanup remains mandatory.
The one-step closed-rehearsal runner is independently accepted (35 focused,
1232 full-suite tests, five Windows symlink skips). Live preflight passed with
two stacks and 17 named targets absent. At about 14:03 UTC the supervisor
requested the six-resource closed app stack. Do not treat it as cleaned up or
repeat creation: consult the private journal and the final live result section
in `docs/phase-8-closed-rehearsal.md` before any further operation.
That rehearsal is now COMPLETE: scheduled control-plane closure passed with one
execution, scheduled exact-role application deletion passed, and final removal
of all six app plus twelve control resources was verified at about 14:27 UTC.
Capacity stayed 10/10. No endpoint activation, handler invocation, human OAuth,
MAPIT/Telegram/private-data or model operation occurred. No app-deletion fallback
or IAM expansion was needed. AWS audit/deleted-pool retention is distinct from
operational resource removal. Do not recreate those stacks implicitly.
Subsequent work in that window remained offline. Private runtime binding-file
input, conditional exact-key S3 publication, a closed 16-resource OAuth/runtime
composition, exact observed-child cleanup policy and guarded artifact retirement
are independently accepted. The final synthetic artifact lifecycle test also
passed independent review; its app-deleted flag is simulated, not a cloud receipt.
The checkpoint has 1436 passing tests, five Windows
skips, twelve valid synthetic schema fixtures and model-free evaluation 12/12.
No bucket/object was created or deleted; these operator helpers are not MCP tools.
Keep the original rehearsal runner restricted to its six-resource bootstrap.
Expanded-app integration/readbacks, optional Cognito-provider deletion branches,
actual callback/owner enrollment/MFA, real-bound ARM package and synthetic cloud
OAuth interoperability remain pending. Do not treat local/schema acceptance as
permission or evidence of activation. See current preparation and rehearsal docs.
Do not expand into an
agent UI, frontend, live project-owned AWS
infrastructure, webhook deployment, Home Assistant, or HA integration.

On 2026-09-29 the user authorized the external gate and the bot
`@honda_mapit_mcp_bot` was created. The supervisor recorded one bounded Telegram
E2E result and one direct read-only backend check as safe booleans/categories
only; no token, message content, or real chat/user identifier belongs in the
repository. Any future live Telegram operation remains supervisor-authorized.

MAPIT remains read-only in all phases. Do not send `POST`, `PUT`, `PATCH`, or
`DELETE` requests to MAPIT except the Cognito calls strictly required for
authentication. The only Telegram write in the Phase 5 contract is the bounded
`sendMessage` operation; no persistent Telegram worker, webhook, or additional
live operation is in scope.
Never commit credentials, tokens, AWS keys, Telegram bot tokens, or real
personal/device/location/chat/user IDs.

Before expanding the MCP core, agents, tools, evaluations, or AWS integration,
read:

- `C:\Users\herre\OneDrive\Desktop\herrerogusano's vault\04 Knowledge\AI Engineering\AI Engineering.md`
- the task-relevant guides linked from that index

## Persistent Roles

Reuse these three roles across project phases. Do not create fresh agents for routine
work.

- `researcher`: investigate MAPIT, public implementations, frontend bundles,
  endpoints, payloads, history, and WebSocket behavior. Prefer primary evidence.
- `implementer`: make bounded code changes only after the relevant evidence and
  decisions are documented.
- `tester`: independently review changes, add or run offline tests, and check
  security, error handling, and regression risk.

Preferred worker configuration: `gpt-6-luna`, high reasoning. The supervisor
owns scope, sequencing, decisions, integration, and acceptance. Escalate model
effort only for a demonstrated blocker.

On 2026-09-30 the user selected GPT-6.1 Sol with medium reasoning for the
supervisor and GPT-6 Luna with high reasoning for workers. Existing workers
were checkpointed and replaced because the agent tools cannot change an
existing worker's model. Reuse the replacement researcher, implementer and
tester roles; do not silently inherit a different model or escalate to Astra.

On 2026-10-02 the user explicitly changed the supervisor to Astra. This changes
only the supervisor selected in the app; keep the existing GPT-6 Luna/high
workers. It does not authorize paid model API calls or extend any AWS gate.

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
open questions. Do not invent capabilities or brute-force endpoints.
