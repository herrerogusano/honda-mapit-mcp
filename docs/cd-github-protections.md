# GitHub CD protection payloads and readbacks

`scripts/github_cd_protections.py` is a pure helper for preparing and checking
future repository protection settings. It has no GitHub client, token reader,
network path, or settings mutation. Fixtures use a synthetic owner ID. Nothing
in this module or its tests reads actual user/repository settings.

The repository is fixed as `herrerogusano/honda-mapit-mcp`. Only `main` and
`develop` are accepted: `prod` maps to `main`, and `dev` maps to `develop`.
Branch protection requires the eight named CI checks from the checked-in
workflow, each bound to the observed GitHub Actions app ID `15368`. Readback
requires strict up-to-date checks, admin enforcement, stale-review dismissal,
conversation resolution, no force pushes or deletions, no restrictions, and no
unreviewed bypass or additional reviewer. The PR approval count is deliberately
zero because the repository currently has a sole owner; this is not independent
human review. Code-owner and last-push approval are explicitly disabled.
The branch-protection write payload uses the app-bound `checks` form only; it
omits the deprecated `contexts` input to avoid GitHub's mutually-exclusive
`oneOf` schema. A GET readback may include both `contexts` and `checks`, and the
validator requires both to match the same exact eight-check set.
For an unrestricted repository, branch-protection GET may omit `restrictions`;
the validator treats that omission as neutral, while rejecting any nonempty
restriction object.

Each environment payload binds one supplied positive integer user ID, has no
wait timer, disables administrator bypass, does not prevent self-review, and
accepts only its exact deployment branch policy (`develop` or `main`). The environment REST readback helper checks
the exact reviewer ID/type, reviewer rule, branch policy, and absence of extra
protection rules. GitHub's response may omit a zero-valued wait-timer rule; if
the rule is present, it must explicitly be zero. The separate deployment
branch-policy readback must contain exactly one literal target branch.

## Administrator bypass

The current documentation for the environment request endpoint does not list
`can_admins_bypass`. However, one bounded PUT using `false` succeeded on the
dev environment, and the subsequent GET returned the exact boolean `false`.
Accordingly the payload emits this field, and `validate_admin_bypass_disabled`
accepts only an explicit `false` from the actual readback. Missing, `null`,
integers, strings, or `true` fail closed for this control; the general
environment validator accepts the field only as a strict boolean and does not
mistake absence for disabled. This is empirical support for the observed API
behavior, not a claim that the request schema documents the field.

The sole owner can approve their own environment deployment because
`prevent_self_review` is false and there is no second reviewer. This is an
operational constraint, not a two-person approval guarantee.

Primary API references: [protected branch REST API](https://docs.github.com/en/rest/branches/branch-protection),
[deployment environment REST API](https://docs.github.com/en/rest/deployments/environments),
and [deployment branch policy REST API](https://docs.github.com/en/rest/deployments/branch-policies).

## Applied and verified — 2026-10-05

The operator configured and independently read back both branches and both
environments against the pure validators. `main` and `develop` require the exact
eight GitHub Actions checks, strict freshness, PRs and admin enforcement; force
pushes and deletion are disabled. `dev` accepts only `develop`, and `prod` only
`main`; both require the authenticated repository owner's approval and return
`can_admins_bypass=false`. No owner identifier was persisted here.

Two initial branch requests were rejected with HTTP 422 because they combined
the mutually exclusive `contexts` and `checks` input forms. Absence of protection
was read back before the corrected request. Successful writes were not replayed.
Actual readbacks also established neutral omitted `restrictions`, optional zero
wait rules, and the additional typed user metadata. Compatibility changes were
independently reviewed and covered by 68 focused tests.

This is GitHub setting acceptance, not OIDC trust, a merge, an AWS operation,
deployment or operational CD acceptance. The earlier requested manual UI bypass
change is unnecessary: the actual API write and false readback succeeded for
both targets. Environment approval is a sole-owner acknowledgement, not
independent two-person review.
