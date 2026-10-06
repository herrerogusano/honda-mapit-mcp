# CD readiness workflow contract

## Retained dev increment — 2026-10-06

Production CD is operational; see [live delivery acceptance](cd-delivery-implementation.md).
This document's earlier preparation observations are historical. `develop` does
not yet deploy a retained application. The user requested a separate dev
environment followed by multiuser development, with no real invited users yet.

The bounded implementation sequence is:

1. A new closed five-resource `honda-mapit-mcp-dev-retained` bootstrap: HTTP API,
   stage, logs-only execution role, seven-day log group and disabled Lambda.
   Every physical name and log permission belongs to the new dev namespace.
   It has no routes, invocation permission, OAuth resources, secrets or data.
   Keeping a stack does not require `DeletionPolicy: Retain` on compute; explicit
   retirement remains possible. This scaffold is not a usable MCP or completed CD.
2. Separately reviewed private artifacts, dev-only OAuth client/resource/branding,
   and independent control-plane shutdown. The definitive identity/MFA may be
   reused only through verified existing-pool bindings; never recreate its pool,
   domain or owner. Keep eu-west-1 and regional quota 10. Dev uses the shared pool
   only during bounded tests, not a reservation that AWS cannot provide.
3. A distinct protected `develop` delivery path, exact dev OIDC subject, scoped
   dev deployment/service roles, immutable metadata journal and artifact bindings,
   closed update/readbacks, recovery and separately authorized test activation.
   The identity-only dev role is not a deployment role. Do not parameterize the
   accepted prod runner into dev or overwrite prod environment bindings.
4. Network-disabled A/B multiuser composition and endpoint/client isolation
   checks, then synthetic cloud validation. Real invitations, account linking,
   durable revocation and tenant-secret publication remain distinct acceptance
   requirements; fictitious tenants do not prove real MAPIT account ownership.

The default dev target is synthetic, owner-access-only and closed outside test
windows. No MAPIT session/ledger transfer, business probe, public signup, Telegram
activation or paid model is included. The old dev factories and expired journals
retain their original lifetimes and must not be reused for the new stack.

The owner approved retaining dev with an additional gross budget target of
USD 1/month on 2026-10-06; this is not a billing hard cap. Pricing research must
include retained alarms, logs, artifacts, workflow transitions and authentication,
not just Lambda execution. A closed endpoint does not make those charges zero.
No AWS resources have been created for this increment.

The separate offline OAuth setup factory composes the unchanged closed five
resources with exactly three retained children of the existing identity pool:
resource server, public authorization-code client and managed-login branding.
It uses distinct retained-dev names and exact dev API audience/callback values;
it creates no pool/domain/user, changes no MFA and adds no routes or invocation
permission. This draft is not part of the first five-resource bootstrap and
does not authorize or prove an actual OAuth update/login. Real binding and
closed update/readbacks remain required before use.

Offline foundation acceptance: the closed scaffold, independent controls,
private artifacts, OAuth draft and injected/bootstrap CLI have independent
review. The parent environment passed 2,587 tests with eleven dependency/OS
fixture skips, compilation, model-free evaluation 12/12 and all 33 pinned
CloudFormation schema fixtures without findings. A real Windows-only synthetic
file proof verified strict owner/SYSTEM directory and inherited-file ACLs.
No AWS call, deployment or OAuth login is implied by those offline results.
The first live gate requires a clean exact `develop` commit with all eight CI
jobs, verified workflow identity/protections, a new private authorization and
journal, and a fresh at-most-one-hour bootstrap window. One create intent only;
an ambiguous outcome requires read-only reconciliation, never another create.

Public eu-west-1 price lists were checked on 2026-10-06. An illustrative
low-use subtotal is about USD 0.118/month: 1,000 HTTP/Lambda requests, 256 MiB
ARM at one billed second/request, one standard metric alarm, 0.01 GB log
ingestion/storage, 100 MB-month S3, one PUT/GET, 200 workflow transitions and
20 Scheduler invocations. This is not a measured bill or an all-in estimate.
It assumes no incremental MAU for the existing user pool; no new authentication
identities or paid models are created. Transfer, taxes, extra requests/logs,
additional retained packages, metrics and configuration-dependent charges are
excluded; the exact control composition still needs acceptance before activation.
The regional AmazonStates price list confirms USD 0.000025 per standard state
transition (publication 2026-09-11); its global free-tier SKU is not used in this
gross estimate. Sources: [regional Lambda prices](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/current/eu-west-1/index.json),
[regional API Gateway prices](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonApiGateway/current/eu-west-1/index.json),
[regional CloudWatch prices](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/current/eu-west-1/index.json),
[regional S3 prices](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/current/eu-west-1/index.json),
[regional Step Functions prices](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonStates/current/eu-west-1/index.json), and
[Scheduler pricing](https://aws.amazon.com/eventbridge/pricing/).

## Current visibility — 2026-10-05

The user selected public portfolio publication and explicitly allowed the
existing Git author email to remain visible. After the publication review,
repository visibility was changed and verified as public. History and the open
PR were preserved; no merge or AWS operation occurred. The private-plan gate
below is historical, not the current visibility. Public-repository protection
features can now be configured, but availability is not enforcement: `main`
was still unprotected on the post-change readback, and no environment approval
or deployment permission was configured by this visibility change.

`.github/workflows/cd-readiness.yml` is a manually dispatched readiness check,
not a deployment workflow. GitHub only offers `workflow_dispatch` for a
workflow present on the default branch, so the workflow must first reach the
verified default branch (`main`) before operators can dispatch it. The selected
target is limited to `dev` or `prod`; `dev` is accepted only from
`refs/heads/develop`, and `prod` only from `refs/heads/main`. It checks out the
exact dispatched `github.sha`, uses read-only repository permission, disables
persisted checkout credentials, and serializes runs by target without
cancelling an active run. After checkout it verifies that `HEAD` is exactly the
40-character dispatched commit.

The workflow rejects provider credentials, AWS credential-source variables,
and conventional AWS profile files before installing public test dependencies.
It performs compilation, the full offline test suite, and the model-free
12-case evaluator. Its summary contains only the selected target, source commit,
and readiness result. It does not build a runtime ZIP, upload artifacts, request
OIDC, read AWS state, assume a role, create a deployment candidate, or deploy.
Passing is evidence only that those source checks passed for that commit.
In particular, the production runtime manifest and package bind account/owner
identifiers and public-key metadata; neither the real manifest nor its ZIP may
be uploaded as a workflow artifact or exposed in job output. This workflow does
not run the separate dependency-advisory audit or isolated CloudFormation
schema-check jobs, and does not certify those gates as passing.

## Separate future deployment gates

### GitHub controls accepted — 2026-10-05

After public publication, the exact eight-check branch protections and
owner-approved, target-branch-restricted `dev`/`prod` environments were applied
and verified. Administrator bypass is disabled on both environments. See
[the settings receipt](cd-github-protections.md). Historical unprotected-state
observations below do not describe this new readback. The user also explicitly
authorized promotion through PRs to `develop` then `main`, and preparation and
creation of the narrow AWS OIDC connection for CD in eu-west-1. Before any
production update, present the exact change and recovery procedure. Preserve
owner/MFA, quota 10, MAPIT data and single-owner production; this approval does
not authorize hosted multiuser or paid inference. Operational CD still requires
actual claim discovery, separately accepted IAM/update wiring and a real
approved release-branch proof; readiness alone is not deployment. The two
owner-approved claim-discovery runs subsequently passed on the exact promoted
develop/main commits. They establish observed claim shape only, not AWS STS
acceptance; see [the bounded receipts](cd-oidc-claims.md).

Read-only AWS preflight under that approval matched a non-root session to the
existing owned production stack in eu-west-1 and verified the existing GitHub
OIDC provider with the STS audience. The provider will be reused without edits;
the proposed target CD roles were absent. No IAM policy/role/provider or runtime
was mutated. A separately reviewed identity-only bootstrap is prepared, not
deployed; its real generated template must remain private. See
[the bootstrap contract](cd-identity-bootstrap.md).

This workflow intentionally does not implement any deployment path. A future
proposal requires separate review and approval of all of the following before
adding a deploy-capable workflow:

At the time of preparation, `main` is the verified default branch and GitHub
reports both `main` and `develop` as not protected. The readiness workflow does
not change repository settings. Required checks and branch protections must be
configured and verified as a separate prerequisite; an allowed source ref is
not evidence of branch protection.

- an immutable ARM candidate bound to this exact source SHA, with package
  digest, manifest/JWKS bindings, dependency lock and independent package
  acceptance;
- fresh, immutable operator authorization and journal for the specific target;
  previously consumed or expired write intents are never replayed;
- exact GitHub OIDC issuer, audience, repository and branch/environment subject,
  narrowly scoped to the selected target; inspect the actual emitted claims
  rather than assuming a subject format, and use no broad branch or repository
  wildcard;
- required same-commit CI checks and branch protection, plus separately
  configured `dev`/`prod` deployment environments with target-branch
  restrictions and explicit approval requirements;
- a separately reviewed deployment role and permission boundary, with a strict
  split between code-only update and infrastructure/IAM changes;
- reviewed cost, shutdown, cleanup, ownership and rollback/recovery procedures,
  including fail-closed handling of ambiguous writes and exact readbacks;
- a deployment-specific approval gate and post-update closed-state checks before
  any separately authorized reopening, with an explicit close → code-only update
  → exact readback → separately authorized reopen sequence;
- no automatic rollback or replay after an ambiguous write; recover only through
  a separately reviewed, ownership-bound readback procedure.

Production remains owner-only. This readiness check does not approve production
deployment, hosted multi-user access, MFA or identity changes, MAPIT session
migration, live data queries, Telegram operations, paid inference, or a rollback
that blindly replays an earlier write. Existing operators with expired hardcoded
windows are not reusable deployment candidates. No OIDC trust, GitHub
environment, secret, AWS role, or repository setting is created or changed by
this work.

Primary GitHub references: [manual workflow dispatch](https://docs.github.com/en/actions/reference/events-that-trigger-workflows#workflow_dispatch),
[OIDC claim formats](https://docs.github.com/en/actions/reference/security/oidc),
and [deployment environment protections](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments).

## Hosted protection capability gate — 2026-10-05

Read-only repository inspection confirmed a private repository with default
branch `main`. Both the rulesets listing and `main` branch-protection read
returned HTTP 403 with GitHub's explicit upgrade-or-public-repository message.
This is a capability rejection, not evidence that a protection configuration
was applied. Existing environments named `dev` and `prod` were readable; both
had empty protection rules and no deployment branch policy. Their existence
alone is not an approval boundary. No settings were changed.

GitHub documents protected branches for private repositories on paid plans.
However, required environment reviewers on Free, Pro and Team are documented
as public-repository-only: upgrading to Pro alone must not be represented as
solving the private production-approval requirement. See
[protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [environment protection availability](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

Stop before enabling OIDC/deployment permissions. The user must choose between
retaining private/free CI with a separately approved external manual delivery
procedure, or reviewing a different hosting/plan/visibility option. External
operator approval is not equivalent to enforced GitHub branch/environment
protection, and choosing it revises the earlier deployment contract. Do not
silently replace a required approval with `workflow_dispatch`, make the
repository public, purchase a plan, attach AWS credentials to a self-hosted
runner, or add a deploy-capable IAM role as a workaround. No AWS account read,
role creation, OIDC token request, merge or deployment occurred in this review.

## Current delivery distinction

The historical hosting capability gate above was superseded by the separately
authorized public portfolio publication and exact protection readbacks in
[the GitHub protection contract](cd-github-protections.md). Identity bootstrap,
bounded STS evidence and consumed attempts are tracked in
[the identity proof contract](cd-sts-proof-contract.md). These receipts do not
grant deployment permissions or establish completed CD.

The actionable offline [next production delivery gate](cd-production-next-gate.md)
describes private artifact handoff, the proposed executor/service-role split,
its persistent CloudFormation consequence and exact closed-update/recovery
requirements. Actual roles, a fresh delivery executor and a dev deployment
target are not implemented by that proposal.
