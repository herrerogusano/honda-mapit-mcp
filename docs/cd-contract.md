# CD readiness workflow contract

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
