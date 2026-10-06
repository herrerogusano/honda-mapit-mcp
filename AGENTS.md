# Project Agent Workflow

Superseding live checkpoint (2026-10-07 Europe/Madrid): PRs #63/#64 and final
develop `6b09eb2` passed eight checks. The exact-key/account DescribeKey CFN
role/boundary update was acknowledged and fully read back; its new fifteen-field
private binding is accepted. Crypto conditions and executor remain unchanged.
The first metadata preflight stopped locally before any intent because its lock
path exceeded the effective Windows path limit; an empty standard short journal
passed preflight and was used instead. Keep the unused long-path envelope.
The exact new orphan deletion completed with HTTP 204/empty readback (14 calls).
These write allowances are consumed and must never be replayed. The hosted
attempt then stopped at user_preflight_failed: second-recurring preparation
selected the latest pair instead of the first B-creation pair. Offline readback
confirms the real historical chain is valid and all new users/reset/recovery/
artifact/runtime/window/tenant journals are absent: no password reset/login,
publication, runtime update, endpoint opening or E2E followed. DEV remains
closed and multiuser is not yet functional. Correct the runner selector and
positive composition regression offline; a new one-attempt owner decision is
requested before another hosted execution. No new IAM or orphan cleanup is
needed. Preserve production/MFA/MAPIT/quota ten and all historical journals.
The selector correction and actual preparer regression are independently
accepted offline: original B-creation provenance succeeds with two reads and
zero writes; the wrong recent window fails with no fresh state. Full suite
passed 3,482 tests with twelve environment skips, compilation and model-free
evaluation 12/12. Six final read-only AWS checks confirmed exact identity,
closed API/Lambda, original eleven app resources and the completed metadata
role stack. New hosted execution still requires the pending owner decision;
do not repeat the role repair or authorizer deletion.

Latest consumed DEV attempt (2026-10-07 Europe/Madrid): PRs #61/#62 merged
normally to develop `0221545`; all eight develop checks passed. Exact orphan
cleanup completed with HTTP 204 and empty readback (14 calls). One fresh reset
and real signed-token login per same A/B account succeeded. The private ARM
artifact was published, but the acknowledged runtime update rolled back fully:
the exact CFN assumed role was denied `kms:DescribeKey` on the already bound
AWS-managed Lambda key. DEV API/Lambda remain closed with the original eleven
resources; no E2E, tenant publication or production/MFA/MAPIT operation occurred.
This allowance is consumed, including both resets. One new unused authorizer
was retained by this failed update; its exact create/delete-skipped lineage is
separate from the authorizer already deleted. Never replay prior journals.
The owner now approves only the separate exact-key CFN metadata permission and
boundary repair, deletion of that new exact orphan, and one new same A/B attempt
after independent review and fresh CI. Keep crypto-context restrictions and
executor permissions unchanged. `DescribeKey` has no encryption context;
metadata permission must be separate. Second recurring-reset provenance must
bind both prior reset journals, original A and first B creation. This new
allowance has not been executed. Temporary wakefulness is currently active and
must be removed before handoff.

On 2026-10-07 Europe/Madrid the owner approved deletion of only the exact unused
retained DEV JWT authorizer and one fresh bounded deployment/E2E attempt with
one reset/login of each same confirmed A/B technical account. Implement and
independently review exact closure/lineage/intent/readback guards and terminal
PAIR-reset provenance before executing. Do not replay any prior operation,
relax KMS context, expand IAM, touch production/MFA/MAPIT or raise quota ten.
Use fresh source CI/private immutable authority; stop on any ambiguous write
or failed attempt without another automatic reset/retry. This allowance is
not yet consumed at this historical preparation checkpoint (consumed above). Temporary wakefulness must
be removed before handoff.

Latest live checkpoint (2026-10-06 UTC): PR #60 merged normally to develop
at `5b6c379`, with eight green checks on source and develop. The exact-key KMS
CFN-role repair passed real readback; executor permissions remained unchanged.
One reset/login per same confirmed technical A/B account and both signed-token
checks succeeded. These allowances are consumed. The private ARM artifact was
published; the runtime update was acknowledged then rolled back completely:
JWT authorizer creation failed with AlreadyExists. Read-only evidence matched
the retained authorizer to the prior create and DELETE_SKIPPED events; exact
audience/issuer matched, with zero route references. Dev is closed (API disabled,
Lambda reserve zero), with its original eleven-resource stack. No hosted E2E,
tenant publication, production/MFA/MAPIT operation or quota change occurred.
Deletion of that exact orphan and a fresh bounded pair-reset/deployment attempt
were requested, not authorized or executed at this checkpoint. Never replay
consumed writes. The latest terminal reset journal is PAIR-kind, not accepted
by the older A-only rollback validator; retain original B-creation provenance.
The strict KMS context remains untested. DEV multiuser is not yet functional.
See docs/dev-multiuser-hosted-contract.md.
Offline API-child prevention passed independent review and 3,442 full tests
(twelve environment skips), compilation and model-free evaluation 12/12. The
owned temporary wakefulness helper was stopped before handoff; original power
scheme was unchanged. No persistent display setting was modified.

Latest DEV checkpoint on 2026-10-06 supersedes the first-password gate below:
develop 86e58bf passed eight checks and the separately bound read-only recovery.
A's first permanent password was acknowledged and journaled, then Managed
Login failed before token exchange; B remains pending. A's creation and first
password allowances are consumed. Do not rerun the original recovery, reset
the password implicitly or create another A. DEV remains closed; no artifact,
runtime delivery, tenant authorization or endpoint opening occurred. Bounded
existing audit projections matched login/authorize but no token event and do
not identify the cause. Add safe diagnostics offline; a fresh explicit bounded
same-user reset/login allowance and independently reviewed recovery are required
before another live attempt. See docs/dev-multiuser-hosted-contract.md.
The owner subsequently approved one new bounded password reset/login for the
same technical A, then B and DEV E2E. This is a new reset intent, not replay of
the first-password write. Require separate reset provenance, exact historical
journal/sub/account/pool binding, fresh source checks and independent recovery
review; stop on an ambiguous write or failed login. No production approval is
included. That new allowance was subsequently consumed on develop 064e231
after eight green checks and fresh protections/readbacks. A's reset was
acknowledged and confirmed, then login failed at login_post with cookie_invalid.
B remains pending; no artifact/runtime/table/opening step followed. Four bounded
read-only account/app/API/Lambda checks confirmed the original eleven-resource
setup, API disabled and reservation zero. Never replay this reset journal.
Further work may diagnose/repair standards-based cookie handling offline; a
subsequent same-user reset/login allowance was explicitly granted: one new
attempt only after standards-based cookie repair, independent review and fresh
CI. Use the latest consumed attempt's confirmed-user journal as provenance,
preserve every historical reset journal, and stop on any unknown write/login.
That subsequent allowance was consumed on develop 545b7fd after eight checks,
fresh protections and the reviewed native-cookie increment. A's reset was
confirmed; its login reached the token endpoint and failed at token_post with
token_invalid. B remained pending; no publication/runtime/table/opening step
followed. The reset journal is terminal, not a replay candidate. The integrated
local suite passed 3,358 tests with twelve environment skips (two unrelated
packaging-fixture read failures in an earlier run passed isolated and on the
complete rerun). The native token parser incorrectly requires response-body
scope, absent in official Cognito examples; this is a documented incompatibility,
not confirmation of the exact failed live field. The owner granted one new
same-A reset/login allowance after this correction, independent review and
fresh CI; JWT-signed scope verification must remain mandatory and unchanged.
That new allowance was subsequently consumed on develop a7bbd0a, after eight
green source checks and fresh protections. Both technical users authenticated;
signed JWTs, pinned ARM package and private artifact publication passed. The
recurrent IAM narrowing was accepted, but the runtime update was acknowledged
then rolled back: McpHandler failed with kms:Encrypt denied explicitly by its
permissions boundary. B is now confirmed; neither user's write allowance may
be replayed. No endpoint opening, tenant publication or HTTP E2E occurred.
Read-only checks confirmed UPDATE_ROLLBACK_COMPLETE, original eleven resources,
API disabled and reservation zero. Preserve all consumed journals and the
verified private artifact. Further KMS permission repair/update and renewed
authentication require a separately reviewed bounded recovery; do not silently
reset either user or replay the acknowledged runtime update.
The correction passed independent review,
3,374 offline tests with twelve skips, compilation and model-free evaluation
12/12. Body scope omission preserves unknown metadata; real RSA/JWKS tests
confirm that signed JWT scope and signature remain mandatory. Fresh source CI
is still required before the single new live attempt.
Temporary wake helper PID 49340 (start 2026-10-06T21:03:09Z) was verified and
removed before this gated handoff; no persistent power settings changed, and
the original HP Recommended active scheme was reverified. A future continuation
must explicitly renew temporary wakefulness rather than assume this helper runs.

The owner then approved the exact existing AWS-managed-key DEV repair and one
fresh reset/login per same confirmed technical A/B, followed only on success
by bounded hosted E2E. This does not authorize user creation, customer keys,
unlisted IAM permissions, production/main, owner MFA, quota or MAPIT changes.
Read-only key/event projections match the alias key to the failed handler event
and the prior request token to the completed rollback root. Audit parameters
were absent and do not prove encryption context. The KMS factory and separate
two-confirmed-user recovery passed initial independent offline review; integration,
fresh source CI and live proof are pending. The optional KMS CFN role retains
its boundary/key/service/context denies; the unlisted-action explicit deny is
in its sole inline policy to respect distinct IAM size limits. Executor unchanged.
No historical write/window is replayable. New temporary wake helper PID 27508,
start 2026-10-06T21:25:22Z, has a two-hour automatic cutoff and must be removed
before handoff; persistent display/power settings remain unchanged.

The integrated recovery is now accepted offline: 3,424 tests passed with twelve
environment skips, compilation and deterministic evaluation 12/12. Independent
review accepted strict completed-reset/original/latest-pair provenance and the
one-intent KMS repair CLI, including pending IAM update readbacks and exclusive
private accepted-binding publication. HTTP checks now pace at least 1.1 seconds
and fail immediately on invalid initialization/discovery. A fresh read verified
the exact current app CFN role and termination protection. The bounded original
setup-window Encrypt lookup returned zero events; environment-encryption context
is still unconfirmed, not established by ZIP/filter documentation. Keep the
approved exact FunctionArn condition fail-closed. Source CI/promotion and the
new live allowances remain pending and unconsumed at this offline checkpoint.

On 2026-10-06 the owner authorized retained isolated DEV multi-user acceptance:
two technical users, an exclusive test Cognito pool with MFA off only there,
and a durable authorization table. Shared Lambda quota remains 10, no real
MAPIT credentials/data or paid inference, and production/owner MFA are unchanged.
The compacted role update, closed eleven-resource setup and timed controls
passed actual AWS readbacks on develop 4d1db49 after eight green checks. Their
acknowledged intents are consumed; never replay them. Hosted acceptance then
stopped at read-only bucket compatibility preflight before technical-user
creation or any runtime/publication/opening operation. Preserve the closed DEV
state; resource creation is not functional acceptance. A fresh source envelope
and independently accepted SDK-shape compatibility are required to continue.
The subsequent SDK/form compatibility passed independent review and eight
checks on develop 6bf4ce8. Actual hosted acceptance then created only technical
A and stopped on a local RFC subject restriction before password assignment.
Read-only reconciliation found A enabled in FORCE_CHANGE_PASSWORD with a
Cognito lowercase hexadecimal subject that has non-RFC version/variant bits.
Keep A's creation intent consumed and the original user journal immutable;
never create an alternative A, replay its creation, or extend its 300-second
window. A separately bound recovery may perform A's first password assignment
and B's original-name creation/password only after fresh source/readback gates.
No runtime publication/update/opening, real MAPIT or production operation occurred.

Latest hosted DEV checkpoint, 2026-10-06: PRs 50–52 merged normally to
develop; all eight source checks passed on 79ad52e. The independently reviewed
operators passed 3,273 offline tests (12 environment skips), compilation and
model-free evaluation 12/12. SDK mapping and durable-journal integration defects
were fixed before any AWS write. One fresh roles update was acknowledged, then
AWS rejected the CloudFormation boundary policy size and rolled back completely.
A subsequent exact 14-read verifier accepted the original roles/boundaries.
No pool, table, technical users, runtime artifact or opening has been created.
The consumed acknowledged intent must never be repeated. Policy compaction
must preserve permissions, fit the 6,144-character managed-policy limit, pass
independent review/source CI, and use a new private envelope/journal. Stable
rollback status is not enough: require exact prior template, closed runtime and
original role readback before a new intent. Production, owner MFA, Telegram and
regional quota ten remain unchanged; hosted DEV E2E is still pending.

The 2026-10-06 isolated multi-user DEV scope is owner-approved: retained test
pool with MFA off only there, two technical users, authorization table, bounded
opening, unchanged regional Lambda quota ten and no real MAPIT/paid models.
PR 49 merged to develop at 242411d after eight green checks; source push CI
37512182212 passed. Actual role preflight stopped before write intent because
IAM returned exactly the four matching application tags, without CloudFormation
system tags. Bounded read-only diagnostics confirmed that shape. The strict
four-tag verifier correction is local pending fresh source CI; no AWS resource
update, user creation, opening or hosted acceptance has occurred at this point.
Production/main, owner MFA and Telegram remain unchanged. A separate clean
deployment worktree prevents in-progress tooling from contaminating source gates.

On 2026-10-06 the owner explicitly approved updating the existing retained DEV
with an isolated admin-only Cognito test pool (MFA OFF only there), two technical
users, and a retained DynamoDB authorization table. Keep production/main,
definitive owner/MFA, owner-only Telegram and regional Lambda quota 10 unchanged.
Use synthetic business data only, no MAPIT credentials/history or paid models.
The incremental small-test estimate is about USD 0.03/month plus variable
storage/logs, within the existing USD 1/month gross DEV target, not a hard cap.
Open DEV only during bounded tests with independently armed closure. The user
requires hosted functional multi-user DEV acceptance before notification for a
separate production deployment; offline components are not that acceptance.
The current opt-in identity proof, DynamoDB reader/CAS, durable DEV Lambda
composition and manifest-bound synthetic entrypoint passed independent offline
review. The new closed setup preserves the five original runtime resources and
adds only six identity/table resources; subsequent closed runtime has nineteen.
Do not weaken or replay historical bootstrap/updater journals for these phases.
Two fresh read-only AWS checks confirmed the original non-root DEV operator and
ready retained stack; its CloudFormation service-role association is absent.
No AWS mutation or hosted E2E acceptance has occurred in this increment yet.

On 2026-10-06 the user requested continuing multi-user MCP development.
The opt-in local durable authorization increment is independently reviewed:
explicit SQLite connection/schema, opaque tenant key/status/revision only,
transactional CAS, 16-record capacity including terminal revoked tombstones,
authority-bound sealed snapshots and fresh checks surrounding provider/business
access. Synthetic ASGI tests verify A/B isolation, suppression after in-call
revocation and rejection after database reopen. The default no-guard router
behavior, deployed single-owner builders and owner-only Telegram are unchanged.
This is not hosted multi-user acceptance: verified MAPIT account identity and
refresh continuity, onboarding, shared durable cloud state, exact tenant secret
publication/IAM and separately reviewed deployment remain pending. No AWS,
MAPIT, Telegram or paid model operation follows from this offline increment.

The separate retained-dev readonly-proof factory, private bootstrap/CAS runner,
identity-only OIDC runner and initial-code direct-TLS downloader are accepted
offline after independent review (102 focused tests). The factory is included
in the network-denied official schema checker (38 templates). This is not live
role creation, STS acceptance, code download/publication or complete dev CD.
The preflight/update/S3-journal integration remains unaccepted preparation.
Keep production/main and historical consumed intents unchanged.

The retained-dev readonly-proof bootstrap subsequently passed fresh source CI
and dev/develop protections on ee0cfec (CI 37485087411). Five preflight reads,
one acknowledged CreateStack and eleven final readback calls accepted the exact
two-resource role/boundary stack. The create intent is consumed; never replay
it or alter its original private source/window/token. This is configuration
acceptance, not an STS exchange, GitHub secret binding or runtime deployment.
The shared provider, production, owner/MFA, MAPIT and quota 10 are unchanged.

## Scope

On 2026-10-06 the owner approved permanent retained dev, with an additional
gross USD 1/month target (not a hard billing cap), synthetic owner-access-only
runtime and independent closure outside bounded tests. Preserve eu-west-1,
regional Lambda quota 10, working single-owner prod, definitive owner/MFA and
MAPIT data/session. No paid models, real guests or Telegram expansion follows.
The new five-resource honda-mapit-mcp-dev-retained stack was created once from
5d6e31a and accepted with 15 exact readbacks. It is closed: disabled API,
reserve-zero inline Lambda, no routes/invocation permission/OAuth/environment
or business/secret path. Its private original creation source/window/token/
journal is immutable and consumed; never replay it or write a new verifier
source into the original creation binding.
PR #36 subsequently merged the independently reviewed exact retained-dev
executor/service-role drafts, deterministic private bucket, closed synthetic
runtime and read-only CloudFormation resource-binding helper to develop at
befbb9f. Eight PR CI checks passed; local acceptance is 2,654 passed, eleven
environment skips, compilation, model-free evaluation 12/12 and 37 pinned
synthetic schema fixtures. The fixture client now validates against the real
CognitoDevPolicy, not only CloudFormation shape. Runtime resource bindings
alone do not prove current closure or out-of-band drift absence. No dev CD
roles, S3/control resources, runtime update, activation or multiuser hosting
were created by this increment; full dev CD remains IN PROGRESS. Production
main remains unchanged. Subsequent artifact bootstrap work is preparation only
until fresh source/CI/authorization/intents/readbacks are independently accepted.
PR #37 and its eight develop checks then accepted the one-shot artifact
bootstrap at b8e5a23 (CI 37469969070). A fresh private authorization fenced its
two-read preflight and one acknowledged CreateStack. That write is consumed;
never replay it. The stack reached CREATE_COMPLETE, but exact acceptance is
pending SDK readback compatibility. PR #38 passed eight checks and merged at
88eb2b7 (develop CI 37471949535): optional exact NOT_CHECKED resource metadata
and the actual S3 encryption Rules/ApplyServerSideEncryptionByDefault shape.
A separate read-only verification preserved the creation binding and stopped
at S3's optional SSE-C blocking field. Bounded diagnostics confirmed every
remaining bucket control without raw/private output. The narrow optional
BlockedEncryptionTypes acceptance still requires fresh full readback;
diagnostics are not an acceptance receipt. See the artifact status document.
The injected four-resource IAM bootstrap is independently accepted offline
with 29 focused tests, exact separate IAM/application stack bindings, strict
provider host/audience, policy parsing, tags, pagination, boundary metadata,
token-event ownership and immutable journal state. Parent checkpoint excluding
the separate unaccepted controls draft: 2,725 passed, eleven environment skips;
compilation/model-free evaluation 12/12 and actual network-denied SDK client
construction passed. No IAM role or service-role association, runtime ZIP,
controls stack, dev delivery workflow or hosted multiuser activation follows
from this acceptance; full dev CD remains in progress. Main/prod is unchanged.
Subsequently, eight develop checks on 4ae5408 (CI 37473406548) passed.
The artifact verifier completed fourteen exact readbacks with read-only client
facades, preserving the original creation binding and storing its verification
source separately. Its private receipt is accepted; no runtime ZIP was uploaded.
After fresh GitHub controls and four application resource-binding reads, a new
immutable IAM authorization fenced seven preflight reads, one acknowledged
CreateStack and seventeen complete readback calls. The separate retained-dev
four-resource CD role stack is accepted. That creation write is consumed and
must never replay. Shared provider/identity-only roles, prod, owner/MFA and
quota 10 are unchanged. No web-identity exchange, GitHub secret, application
CFN-role association, controls stack or delivery activation occurred. The
separate controls and closed-delivery drafts still require independent/source
acceptance and fresh live gates; full dev CD remains IN PROGRESS.
The separate controls coordinator/runner is subsequently independently
accepted offline with 36 focused tests, strict resolved IAM/EventBridge
comparisons and named-IAM acknowledgement validation. No controls AWS write
has occurred; this does not accept the separate delivery preflight prototype.
Before any controls write, offline SDK inspection identified lowercase
Step Functions tags. A separate narrow repair is independently accepted with
40 focused tests; it also binds the entire initial app template. No controls
write has occurred; fresh repaired-source CI is required before creation.
The separate actual retained-dev ZIP builder, sealed build receipt, conditional
CAS publisher and initial byte-exact prior-code capture are independently
accepted offline (34 focused tests). Historical builders/publishers and prod
are unchanged. No object was published, prior ZIP downloaded, CFN service-role
associated, runtime updated or workflow activated. The delivery preflight,
proof-role factory and update prototypes remain separate pending acceptance.
The repaired controls source 201c07d subsequently passed eight develop checks
(37479419359) and fresh repository/dev protections. One fresh immutable private
authorization fenced nine preflight calls, one acknowledged controls creation,
two pending readbacks and a complete 27-read acceptance. Its five resources
are accepted; never replay the consumed create token or alter its window/source.
Dev remains endpoint-disabled/reserve-zero; prod, owner/MFA and quota 10 are
unchanged. No runtime update, invocation, artifact publication or workflow
activation followed. Full retained-dev CD remains IN PROGRESS.

On 2026-10-05 the user explicitly authorized PR promotion to develop then main
and preparation/creation of the narrowly scoped AWS OIDC connection for CD in
eu-west-1. Present the exact artifact/change and recovery before a production
update; preserve owner/MFA, quota 10, MAPIT data and single-owner production.
Both target branches now have exact eight app-bound CI checks, strict freshness,
PR/admin enforcement and no force-push/deletion. Both environments require the
owner's acknowledgement, their exact target branch and verified administrator
bypass disabled. The API field is empirically supported despite documentation
omission; no manual UI change is needed. See docs/cd-github-protections.md.
This supersedes the earlier unprotected-state observations, not the remaining
OIDC/IAM/private-artifact/executor gates. PRs 1 and 3 subsequently passed all
eight checks and were merged to develop; PR 2 subsequently merged to main.
PR 4 integrated the closed identity factory into develop after eight green
checks. Read-only AWS checks verified a non-root identity, the existing
owned production stack in eu-west-1, and a compatible existing account-wide
GitHub OIDC provider. Reuse that provider without mutation; both proposed CD
roles were absent. IAM uses its canonical global endpoint/signing region, not
a switch of the application's region. No AWS mutation occurred; expired
geography journals remain consumed.
The separate manual cd-identity workflow is independently accepted offline:
one bounded runner-issued token, exact target/ref/SHA/repository-ID binding and
safe subject-format/digest output, with no AWS exchange or deployment. Synthetic
fixtures are not a trust receipt. The local checkpoint is 2150 passed, ten
Windows/POSIX-environment skips, compilation and evaluator 12/12; the protection
commit 2112683 has eight green CI checks. Actual run/approval, OIDC trust, IAM
and a fresh code-only executor were pending at that checkpoint. The two approved
claim-discovery runs subsequently succeeded on exact develop/main commits;
both emitted immutable environment subjects whose digests matched fresh
repository/owner binding. Their approval allowance is consumed. This is not
an AWS trust exchange or deployment. See docs/cd-oidc-claims.md.
The identity bootstrap factory is independently reviewed offline: exactly four
dev/prod role/boundary resources, exact observed subject digest binding and
caller-identity-only permission with explicit deny of other actions. Real
templates embed supplied account/provider/repository bindings and must remain
private. Both synthetic subject formats are registered in the network-denied
schema CI checker; all 25 synthetic schemas passed CI, alongside the other
seven required checks. Actual CloudFormation/IAM acceptance is still pending.
See docs/cd-identity-bootstrap.md. The user separately authorized approving only
the two no-deployment identity-discovery runs after their source checks pass;
this does not authorize approval of later production updates.
The injected closed-identity bootstrap coordinator is independently accepted
offline, including crash-after-intent reconciliation without write replay and
exact role/boundary/provider readbacks. Its 32 focused tests pass; the pinned
SDK CI job includes its model-shape regression. Actual role creation, STS
exchange and deploy-capable permission/executor acceptance remain separate.
The STS proof contract is preparation only; approval of the two consumed
claim-discovery runs does not authorize approving additional STS runs.
One new closed four-resource IAM identity stack creation was acknowledged after
fresh private-journal preflight and eight source checks. Never replay its create
intent. Initial readback stopped on the service's boundary type `Policy`;
bounded diagnostics confirmed both exact boundary documents/default versions.
AWS documentation uses conflicting type spellings. A narrow two-literal
compatibility repair and separate read-only verifier source binding have passed
55 independent/focused tests; full repaired cloud acceptance is still pending.
Keep creation source/hash/window/token unchanged and never use a distinct
verification source for a write. No production update or STS exchange occurred.
The separate STS proof core, runner and manual workflow are independently
accepted offline: no ambient credential chain, direct TLS/single-attempt
regional clients, unsigned exchange and explicit returned credentials only,
exact context/identity checks, no exports or artifacts. Actual environment
secret binding and the two new protected-run approvals were pending at that
offline checkpoint;
never treat the two consumed claim-only approvals as permission for these runs.
The repaired IAM readback subsequently passed two complete 16-read checks,
after eight green source checks on 3df301a. Both exact closed roles/boundaries
and the unchanged shared provider are accepted as configuration, not STS trust
exchange or deployment. Original creation source c044f25/template/window/run
and consumed token are preserved; verifier source is recorded separately.
Local checkpoint is 2251 passed, ten environment skips, compile and evaluator
12/12. Production, owner/MFA, MAPIT data and quota 10 were not changed.
Both environment role-ARN metadata secrets were subsequently submitted once,
after fresh owner/repository/environment verification and prior private intents.
GitHub acknowledged both writes and their metadata presence was read back;
secret plaintext is not readable through that API. No credential/key/token was
uploaded. Do not repeat or overwrite these bindings implicitly. The two new
STS approvals/exchanges are still pending; their earlier claim-only allowance
remains consumed.
The user subsequently approved exactly two new identity-only STS runs. Fresh
source CI/protections and a separate sixteen-read closed-role/provider check
passed; both runs received normal environment approval but failed with the
fixed `proof_failed` category (dev 37338161383, prod 37338166318). This does not
establish successful trust exchange and does not identify the failing stage.
That allowance is consumed. The user approved offline diagnostic improvements,
not automatic repetition: retain exact validation/IAM and add only allowlisted
failure stages/categories before requesting a new bounded live proof allowance.
See docs/cd-sts-proof-contract.md. No deployment or MAPIT operation occurred.
The offline diagnostic increment passed independent review, 46 focused tests,
the full 2256-test checkpoint and eight CI jobs; PR #9 merged to develop at
bae697e. After a new one-attempt dev authorization and fresh exact controls/IAM
readbacks, run 37341041504 failed at assume_role_response_validation with
identity_mismatch. AWS exchange returned HTTP 200; caller-identity was not reached.
The failing field remains unknown. This dev allowance is consumed; no prod
attempt or blind format repair is approved. A bounded existing-audit-event read
is proposed as the next gate, not performed or authorized.
That audit gate was subsequently approved and completed: one regional account
identity read plus two bounded, single-attempt lookups of the same dev job-time
interval, without pagination or another token exchange. Both matched one exact
event. Audience/subject/role/session checks matched; provider matched the exact
owned OIDC-provider ARN rather than URL/host. Only booleans were emitted, no raw
audit payload retained. AWS's CloudTrail OIDC example confirms ARN representation;
the actual SDK payload was not retained. A strict URL-or-exact-owned-ARN repair
is proposed, not implemented/approved by that read-only gate; another dev proof
requires a new bounded allowance. See docs/cd-sts-proof-contract.md.
The user subsequently approved the strict Provider URL-or-owned-ARN correction,
offline validation and one new dev-only proof. The ARN must use the already
validated expected account and fixed GitHub issuer host; no normalization,
other account/provider, bare host, IAM expansion or prod proof is included.
Require independent review and fresh eight-check/protection/closed-role gates
before the single normally approved dev attempt. Older allowances stay consumed.

The strict compatibility increment is now independently accepted with 75 focused
tests; the integrated offline suite passed 2295 tests with ten environment skips,
compilation and model-free evaluation 12/12. Dev proof 37343136563 succeeded on
7a6dbe4 after fresh CI/protection/IAM readbacks. During the user's renewed hour,
2026-10-05 16:40:52–17:40:52 UTC, PR #12 synchronized ancestry without a tree
change and PR #11 promoted normally to main at 0244907. All eight main CI checks
passed; one fresh, normally approved prod proof 37344958197 also succeeded,
verifying exact account/role. Both one-attempt allowances are consumed. Identity
roles remain caller-identity-only; no deployment, IAM expansion, MAPIT operation
or new spending occurred. The independently reviewed offline next delivery
proposal is docs/cd-production-next-gate.md, not implemented CD. It requires
review of a persistent CloudFormation service-role association, fresh bounded
executor/permissions, private artifact binding and exact closed recovery before
any live production update. Temporary wakefulness must be removed before handoff.

The user then explicitly required complete CD, not an identity-only handoff.
Implementation is IN PROGRESS: fresh opt-in ProdDeliveryAuthorization preserves
historical default windows/journals and binds new source/service-role context;
the pure two-role delivery draft and injected S3 CAS metadata journal passed
independent offline review. No roles, association, journal objects or deployment
workflow were activated. The specific permanent CFN role association and private
30-day journal-storage decision is pending owner response. See
docs/cd-delivery-implementation.md for integration/live gates. Do not call these
components complete CD, replay historical writes or broaden another project.

On 2026-10-05 the user authorized public portfolio visibility and explicitly
retaining the existing author email. GitHub visibility was changed to public
and read back as `isPrivate=false`; no history rewrite, merge or AWS change
occurred. Pre-publication review covered reachable source/history and retained
Actions logs plus PR/issue surfaces, with no confirmed sensitive finding.
Numeric-only log heuristics are not proof of AWS account bindings; the review
is not a guarantee of secret absence. The earlier private-plan capability gate
is historical: public protection features are now available, but branch and
environment protections still need separate configuration and readback. Public
source does not authorize OIDC/IAM activation or expose the private MCP service.

On 2026-10-05 the user requested preparing CD alongside AWS deployments.
The separate manual `cd-readiness.yml` checks dev/develop or prod/main at the
exact dispatched commit, with read-only repository permission and no AWS/OIDC,
secrets, runtime artifact upload or deployment. It is preparation, not accepted
continuous delivery. The default branch is main; both target branches were
observed unprotected. Actual required checks/environment approvals, narrowly
bound OIDC/IAM, private artifact packaging and a fresh deployment/recovery
executor remain prerequisites. Never replay the expired geography operators or
publish real owner/account bindings in GitHub artifacts. Production is unchanged;
see `docs/cd-contract.md`.

The subsequent read-only hosted capability review found the repository private:
rulesets and main branch protection were rejected with HTTP 403 and GitHub's
upgrade-or-public message. Existing dev/prod environments have no protection
rules or branch policy. Pro alone does not supply required private-environment
reviewers under the consulted GitHub documentation. Stop before OIDC/IAM/CD
activation for the user's delivery/plan/visibility decision; a free private
manual operator path would be a separately approved contract change, not an
equivalent GitHub-enforced approval. No account/configuration operation follows.

On 2026-10-05 the user selected multi-user MCP access and owner-only Telegram.
Telegram expansion to other users is deferred until incremental cost is known
and separately approved. Continue bounded offline MCP composition/testing; no
renewed external-operation window, hosted signup/storage/IAM expansion or live
Telegram/MAPIT operation follows from the continuation request. Preserve the
single-owner production runtime until separately reviewed hosted acceptance.

The separate opt-in HTTP/MCP composition in `src/mapit/invited_mcp.py` is now
independently accepted offline. SDK-authenticated context supplies a private,
sealed invitation grant per operation; the router must be tied to the exact
authority and common issuer/resource/client/scope. No grant/provider is cached
globally or in an escaping proxy. Actual ASGI/MCP synthetic A/B dispatch and
authorization/revocation/provenance negatives passed, with 2,014 full-suite
tests and five Windows skips, compilation and model-free evaluator 12/12.
The production builder/entrypoints and owner-only Telegram are unchanged.
Real onboarding/MAPIT identity proof, durable invitation/revocation state,
tenant secret publication/IAM and hosted Lambda composition remain pending.

The separate opt-in Lambda payload-v2 composition in `invited_lambda.py` is
now independently accepted offline, not deployed or included in the production
builder. It reuses the unchanged payload adapter with copied invitation/key
snapshots, one authority/router and a fresh app per invocation. Each operation
gets a request-local provider; atomic provider-instance claims reject reuse
across warm or concurrent calls. Its immutable deadline starts before the one
original Lambda-context getter, debits latency, clamps router/provider budgets
and rejects late/invalid-clock results. It does not promise thread termination.
Full checkpoint: 2,038 passed, five Windows fixture skips, compilation and
model-free evaluator 12/12. Real onboarding/MAPIT identity proof, durable
invitation/revocation state, secret publication/IAM, packaging and cloud
acceptance remain separate work. No guests or credentials are needed for these
synthetic tests; owner-only Telegram and single-owner production are unchanged.

On 2026-10-03 the user renewed a two-hour work window, 15:51:57–17:51:57 UTC,
with temporary display/system wakefulness and restoration before final handoff.
Scope: extend geographic queries across Spain if practical, otherwise Barcelona
and surrounding municipalities, then develop Telegram and multiuser support.
Reuse the persistent researcher/implementer/tester roles and canonical guides.
The pending single-owner production geographic code upgrade may proceed with
fresh reviewed journal/intents and a new immutable window; never mutate the old
window/journal or replay its writes. Keep region eu-west-1, quota 10, owner/MFA,
independent stop and USD 1/month target; no paid models or MAPIT history probes.
Geographic public-source research is allowed; no private geometry persistence.
Telegram/multiuser work starts with bounded offline isolation and invitation-only
design. Do not infer public signup, migrating subscription credentials to AWS,
new paid inference, third-party MAPIT credentials, unbounded polling, or an
expanded hosted identity/IAM/storage scope from this request. Preserve the
working single-owner service until those prerequisites are reviewed.

The renewed-window Menorca production upgrade is COMPLETE: fresh publication,
independent shutdown, exact closed update/readbacks and reopening passed.
Codex discovery verified twelve tools with four protocol requests and zero
tool/model calls. Parent private runtime receipts now bind the deployed Menorca
artifact; old journals/intents must not be replayed. Barcelona/AMB assets and
registry subsequently passed independent review and a fresh-artifact update:
exact shutdown/update/reopen checks and Codex twelve-tool discovery passed,
without MAPIT history/tool/model calls. The parent receipt now binds Barcelona;
neither consumed geography upgrade journal may be replayed. The same-manifest
ZIP-only guard adjustment is independently accepted; every other template field
remains exact. Synthetic ARM 22 checks and real-bound offline ARM eight checks
passed; prior artifacts are retained for separately reviewed recovery.
The invitation-only tenant router is independently accepted offline (28 tests),
not connected to production, Telegram identity linking or real credential storage.
No new live history probe or production multiuser capability follows.

The deterministic geographic Telegram dispatcher and bounded local linking/
delivery libraries are independently accepted offline. Dispatcher output must
match the exact requested area and normalized period; it supports `/ayuda`,
`/verano` and `/kms` without a model. Invitation links are five-minute, hash-only,
one-use, bounded and exact-private-pair; consumed digests remain tombstoned for
their lifetime. Every delivery requires fresh verified authorization and the
exact linked pair before business access and again before its one sender attempt.
The 64-update in-memory receipt batch does not promise durable delivery; no
daemon, webhook, hosted signup, new IAM/session store or live Telegram operation
was created. Keep production single-owner until real account linking, tenant
secret isolation, persistent update receipts and hosted identity/cost controls
are independently accepted.

The injected tenant session reader and A/B provider pipeline are independently
accepted offline (82 focused tests). Exact opaque tenant namespace/version,
original response name/ARN/account, atomic one-attempt budget and grant checks
around the call are required. The existing owner reader and deployed artifact
remain unchanged. No tenant parameter, HMAC key, third-party session, IAM role,
durable link/update store or bot transport was created. Before hosted activation,
resolve fresh application-session renewal/delegation, real human onboarding and
stable MAPIT identity proof, durable revoke/idempotency state and exact regional
cost/transport controls per `docs/telegram-multiuser-expansion-contract.md`.

On 2026-10-03 the user approved the geographic-query increment and two hours
of temporary display/system wakefulness, 13:42–15:42 UTC. Reused Luna/high
researcher, implementer and tester roles; canonical MCP/delegation guides were
consulted. The fixed IGN eight-municipality Menorca union, exact prepared
topology, bounded embedded-list service path, two opt-in MCP tools and local
CLI flag are independently accepted offline. Default/dev still expose ten
tools; geographic opt-in exposes twelve. No street reconstruction, persistence,
Telegram, multiuser, paid model or IAM/quota change is included.
The 30-wheel opt-in production package passed nineteen synthetic checks in the
pinned official ARM image with network disabled and 256 MiB memory limit.
One new real summer-2026 geography probe, defined before execution in
`docs/geographic-query-live-protocol.md`, passed: one Core/four Geo logical
reads, eight total auth/MAPIT wire attempts, approximately 6.2 seconds. The
allowance is consumed; do not repeat it, scan other dates or request details.
No coordinates/IDs/history facts were persisted. Source geometry and native
distance/units/history limitations remain explicit; crossing routes are not
prorated. Production still runs the earlier ten-tool package pending separate
reviewed code-only update/readbacks. Never reuse initial-deployment write
intents, change owner/MFA, expand IAM or increase regional quota 10.
The code-only upgrade core and private single-step publication/recovery wrapper
are independently accepted. Final local checkpoint: 1,909 passed, five skips;
eight CI jobs passed on `2bf706e`. One read-only account preflight passed twelve
exact ownership/code/API/quota/tripwire/workflow reads. No artifact publication,
closure, update, reopening or geographic prod discovery was executed: final
operator review left insufficient safe margin in the two-hour window. The old
production service remains unchanged. A renewed bounded window with fresh
intents and readbacks is needed; never extend the old immutable cutoff or replay
consumed operators. See `docs/geographic-query-status.md`.

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
Evening continuation after the 15:29 UTC expiry is local only. A ten-resource
OAuth setup factory is independently accepted: six unchanged bootstrap resources
plus four Cognito resources, with no invented client/owner binding, routes,
runtime environment, users or activation. It prepares the intermediate owned
bootstrap update needed before the final sixteen-resource runtime composition.
Thirteen synthetic templates pass schema checks. The original runner remains
six-resource-only; exact setup readbacks, expanded cleanup/update orchestration
and actual human OAuth/MFA are still pending. No external authority was renewed.
The injected setup readback core is now independently accepted offline: at most
ten fixed reads, exact stack/run ownership and ten resource types, closed API,
empty routes/users, reserve zero, and exact generated client/scope/callback/domain
configuration. It creates no clients or sessions and exposes the private client
ID only after full success, excluded from safe diagnostics and repr. Full local
checkpoint: 1473 passed, five Windows skips, evaluator 12/12; prior setup CI had
seven green jobs. The original rehearsal runner remains six-resource-only.
No cloud call was made; expanded update/cleanup orchestration remains pending.
The subsequent local setup integration is independently accepted: setup-only
Cognito cleanup policy, twelve-resource control bundle and a separate five-step
injected coordinator. It saves update intent/token before a single write, rejects
blind replay after ambiguity, verifies exact owned templates/resources and actual
IAM/Scheduler readbacks, and preserves the original shutdown/resource clocks.
Only its transient control template arms cleanup at first-resource epoch +2700;
static factories remain disabled. Final readbacks recheck external authority
before committing verified state/private client ID. Full offline checkpoint:
1489 passed, five Windows skips; fifteen schema fixtures, compilation and
model-free evaluator 12/12 pass. No cloud call/login or renewed external authority.
The six-resource rehearsal runner is unchanged. Actual expanded setup deletion,
absence verification and the bounded operator execution path still precede a new
cloud gate; this result does not accept real deletion permissions or OAuth/MFA.
On 2026-10-02 the user approved retaining a separate definitive Cognito identity
and MFA for later production use. The protected four-resource identity stack
and owner TOTP enrollment/login were created and read back successfully; the
same owner subject was confirmed through authenticated UserInfo. Do not reset
or delete that retained user, pool, domain or enrollment client during dev cleanup.
See `docs/phase-8-persistent-identity.md`; production activation and MAPIT session
migration are not accepted by identity enrollment alone.

The user renewed bounded synthetic-dev authority for two hours starting at
21:36:42 UTC, ending at 23:36:42 UTC on 2026-10-02. Preserve eu-west-1, quota 10,
USD 1 gross allowance, endpoint at most five minutes, temporary resource lifetime
at most one hour, no paid inference and no live MAPIT/Telegram or production.
Keep the display awake temporarily, without permanent power-policy changes.
The shared-identity dev rehearsal reached and verified a closed fourteen-resource
runtime and twelve scoped controls, including exact trust/inline policies for
five roles. It missed the immutable arming lead and was never activated: no
successful MCP E2E follows. Compute, its three retained dev-only Cognito children,
runtime object/bucket and controls were deleted and read back; all 21 final
rehearsal absence checks passed. Owner subject/TOTP preservation and full Codex
configuration preservation outside the removed temporary connection were verified.
Another activation requires the reviewed complete executor, exact owned bindings,
all independent closures armed, an available human login if requested, and time
remaining in that renewed authority. Never reset an existing resource's start time
or execution window to extend the test. No credential, token or real binding
belongs in Git/vault; private journals remain ACL-protected outside OneDrive.

On 2026-10-03 Europe/Madrid the user renewed the same bounded authority again:
23:01:29 UTC on October 2 through 01:01:29 UTC on October 3. No scope or spending
limit changed. A fresh activation failed before login at `api_enable_failed`;
finally verified endpoint off and concurrency zero. Its owned resources were
removed with 21 absence checks, and owner/MFA preserved. A subsequent close-only
owned API probe observed UpdateApi HTTP 201 with exact ID, unlike the modelled
HTTP 200. The independently accepted core now accepts 200/201 only for that
write acknowledgement, permits an omitted acknowledgement ApiId but rejects a
present incorrect value, and retains strict HTTP-200 exact-ID enabled-state GET
readback and unconditional closure. No successful cloud MCP E2E is implied.
Each new rehearsal keeps its own immutable first-resource and execution times;
never reuse consumed write intents or widen a prior window.

The next fresh activation succeeded: actual owner OAuth/PKCE/MFA, Codex synthetic
tool discovery and two successful fixed calls, six app-server requests, no model
turn or live MAPIT/Telegram. Real UpdateApi enable acknowledgement was HTTP 201
with matching ID and exact GET readback. Core reported activation and shutdown
verified (endpoint off, reserve zero), then owned compute, three dev-only Cognito
children, package/bucket and controls were removed; all 21 final absence checks
passed, with owner subject/TOTP and unrelated Codex configuration preserved.
The permanent identity remains protected. Source passed 1559 offline tests (5
skipped), 45 focused independent tests and seven green CI jobs on dc44ae3.
This accepts synthetic dev cloud interoperability only: production, real MAPIT
session migration/live-data acceptance, always-on operations and hosted multiuser
isolation remain separate gates. See docs/phase-8-persistent-identity.md.

On 2026-10-03 the user explicitly approved permanent private single-owner
production hosting in eu-west-1, retaining its resources, securely transferring
only the MAPIT session (no password/history database), and bounded real checks
of vehicle status and current-month distances. Monthly gross spending target:
USD 1, controls/alerts but no guaranteed billing hard cap; exact regional pricing
remains pending. Keep regional Lambda quota 10 and exclude paid model calls.
This overrides the earlier no-production gate only for that scope. Technical
acceptance of secure handoff/IAM, real-provider deadline handling, owner binding,
independent shutdown and cost controls is still required before activation.
Do not migrate the local ledger, store geometry, scan other months, make live
Telegram calls or modify other projects. Retain the definitive owner/MFA.
See docs/phase-8-aws-preparation.md for the accepted scope and remaining work.

That permanent-production preparation has advanced: session-only Standard SSM
publication/readback and ownership metadata passed; the retained prod compute
bootstrap, five-resource independent stop controller, private artifact bucket
and three-resource OAuth child stack exist and were read back. The real closed
shutdown rehearsal succeeded. The production ZIP contains no session/password;
its real bindings passed offline ARM metadata/negative guards and identical
runtime source passed twelve independently reproduced synthetic ARM checks.
Full offline suite: 1,777 passed, five skipped; evaluator 12/12. A closed runtime
stack update is requested; activation/login/real MAPIT smoke remain unaccepted.
Project cost-allocation tag is inactive; no project monthly Budget alert or hard
cap is claimed. Keep private operator journals/identifiers outside Git/OneDrive.

The retained production runtime update, exact package/configuration readbacks,
five real-bound offline ARM guards and twelve independently reproduced synthetic
ARM checks passed. Request-pressure shutdown controls were armed before opening
the service. The definitive owner OAuth/PKCE login completed successfully with
the existing MFA; the interrupted callback was superseded by a fresh bounded
login, not reused. The single authorized model-free real smoke passed with six
app-server requests and two successful calls: vehicle status and current UTC
month distance. Keep the retained private single-owner service and its permanent
Codex connection; preserve other MCP/global configuration and owner/MFA. No paid
model turn, Telegram call, history scan or ledger migration occurred. Full local
checkpoint is 1,777 passing tests, five skips and evaluator 12/12; seven CI jobs
passed on 992d9a1. Monthly Budget notification and activation of the inactive
Project cost-allocation tag remain unapproved; do not claim a billing hard cap,
measured monthly cost or hosted multiuser acceptance. This smoke allowance is
consumed: do not repeat live queries automatically.

Do not otherwise expand into an
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

On 2026-10-06 the owner decided that the dev source gate follows the existing
production enforcement boundary. `validate_source_gate` therefore reads only
the fixed repository, `develop` ref, bound CI run/workflow/jobs, and clean
local source; it does not request branch-protection, environment, or
administrator-bypass routes. Those controls remain enforced by GitHub and are
not silently reimplemented by the gate. The normal source transport rejects
administration routes; the separate diagnostic probe retains an explicit
diagnostic-only adapter for capability checks. The gate remains credential-free
apart from its injected temporary read token, uses direct TLS and bounded
reads, and performs no writes, workflow activation, deployment, AWS operation,
or production change. Foreign workflow-run repository projections are
rejected. This is a source-gate parity increment, not a claim that continuous
delivery is complete.
The obsolete automatic protection-permission diagnostic workflow was removed;
its historical results and separately callable read-only code remain in Git.
The previous proposed GitHub App gate is superseded; do not create/install an
App or upload a personal token as part of this dev source gate.
