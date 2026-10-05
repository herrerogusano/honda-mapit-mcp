# GitHub OIDC claim-shape discovery

`.github/workflows/cd-identity.yml` is a manual, no-AWS observation workflow.
It accepts only `dev` from `develop` or `prod` from `main`, checks out the
dispatched commit, and requests one token for `sts.amazonaws.com`. It does not
exchange the token, call AWS, or deploy anything.

The local validator checks the token's bounded, duplicate-free JWT header and
claims against the runner's repository, owner, ref, SHA, environment, audience,
and issuer. Repository and owner IDs come directly from GitHub's default runner
environment, not explicit workflow `env` entries that Actions prints in step
setup logs. It recognizes only the documented legacy and immutable environment
`sub` shapes. GitHub notes that the immutable shape depends on repository age or
explicit opt-in, so discovery accepts either exact shape and reports only its
category plus a SHA-256 digest of the subject.

Important: this is claim-shape inspection, not JWT signature, expiry, or signing
key verification. Its `claims_match_unverified` result is not an authenticated
trust receipt: synthetic local fixtures must never be used to configure IAM.
Before any trust policy is considered, independently retain and review the
actual successful workflow run identity (repository and owner IDs, exact
source SHA/ref, target environment, and environment-protection readback), then
compare the observed subject format/digest with the expected repository-bound
claim. The observation still does not verify the JWT cryptographically; AWS
STS must perform that verification when a separately authorized trust flow is
eventually tested. The raw runner request token and JWT are never emitted or
persisted by this workflow.

## Actual bounded observations — 2026-10-05

The two specifically authorized approvals were completed through the normal
environment-review API after verifying the exact source checks and protections:

- [dev run](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37310999818),
  source `cd4501d45ccd22d73ec1029fef21732197941497`, succeeded.
- [prod run](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37311005240),
  source `fcc01036fa38cb28609cf3be44d1220f1cf70c06`, succeeded.

Both reported the immutable environment-subject format. The safe digests were
independently compared in memory with freshly retrieved repository/owner
bindings. No raw token or actual numeric binding was persisted in source.
The two-run approval allowance is consumed; it does not authorize approving
later STS verification or deployment runs. No AWS call or deployment occurred
in these runs, and no cryptographic trust-exchange success is implied.

References:

- [GitHub Actions OIDC reference](https://docs.github.com/en/actions/reference/security/oidc) — claim definitions, environment subjects, immutable subject format, token request permissions and methods.
- [GitHub OIDC security hardening](https://docs.github.com/en/actions/concepts/security/openid-connect) — configuring cloud trust conditions.
