# Retained-dev IAM bootstrap

Status: independently accepted offline, then created once and accepted live.

On 2026-10-06, exact develop source
`4ae54080636428e5b8a8dad13bd51b40143c14fd` passed eight source CI jobs
(run `37473406548`) and fresh repository/dev-protection checks. Four bounded
application resource-binding reads and the strict factory validated the private
inputs, including the accepted artifact receipt. A fresh private authorization
and journal then fenced seven preflight reads, one acknowledged CreateStack
and seventeen complete readback calls. The new four-resource role stack and
both exact policies/boundaries are accepted. Its original source/window/run/
template/token are immutable and the creation write is consumed.

The existing shared OIDC provider and identity-only roles were unchanged.
No STS web-identity exchange, GitHub secret binding, persistent application
service-role association, runtime publication or endpoint opening occurred.
This is accepted IAM configuration, not completed dev CD.

The injected coordinator derives the unchanged retained-dev role factory from
strict private bindings. It creates only the separate
`honda-mapit-mcp-dev-retained-cd-delivery` stack: two delivery roles and two
boundaries. The executor's update target remains the existing application
stack `honda-mapit-mcp-dev-retained`, never the IAM bootstrap stack.

The private runner validates clean develop/source CI, exact account/caller,
ACLs, separate bounded duplicate-safe bindings and a fresh immutable one-hour
authorization. Each step has a 30-second/32-attempt budget. Preflight verifies
the four named IAM resources and stack are absent and checks the existing
GitHub provider's exact host/audience. Creation persists one token before its
single CloudFormation write; acknowledged or uncertain writes cannot replay.
Readback reconciles exact stack/token events, original template, resource
identities, role trust, inline policies, empty managed-policy attachments and
exact permissions-boundary documents/default version/usage.

IAM uses its global TLS endpoint and us-east-1 signing; the application remains
eu-west-1. The provider is read only. Policy JSON parsing bounds encoded and
decoded input, rejects malformed percent encoding and duplicate keys. Role
tags are unique/order-independent; only exact factory tags and exact optional
operator/CloudFormation metadata are allowed. Journals reject impossible
states; no write or success receipt may escape the authorized deadline.

Future live delivery prerequisites remain fresh independently accepted artifact/application
bindings, source CI/protections, exact private identity provenance, cost/scope
and one new journal. No production workflow, existing identity role/secret,
MFA, quota, MAPIT operation, runtime publication or endpoint activation is
changed by this offline increment. It is not completed dev CD.

Independent core/runner regressions pass 29 focused tests. Parent integrated
offline verification, excluding the separate unaccepted controls draft, passed
2,725 tests with eleven environment skips. Compilation and the 12-case
model-free evaluator passed. Actual STS/CloudFormation/IAM SDK clients were
constructed with fake credentials and Python networking denied: TLS,
one-attempt retries, 2/3-second timeouts, empty proxies and exact IAM global
signing were verified. These synthetic checks are not live trust or deployment
receipts.
