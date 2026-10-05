# Environments and CI

## Branch promotion

The project uses this promotion flow:

```text
feature/* -> develop -> main
```

`develop` is the development integration branch. `main` is the production
branch. Pull requests and pushes to either branch run the same offline CI
workflow across Linux Python 3.11, 3.12, and 3.13 plus Windows Python 3.13.
Core/test/agent/realtime extras are installed together; Windows also installs
the Windows-auth extra. Feature branches are checked when
they open or update a pull request targeting one of those branches.

The GitHub `dev` and `prod` Environments are project environments for future
workflow/deployment coordination. They are not additional MAPIT endpoints and
do not imply that CI can authenticate to MAPIT.

## CI security boundary

CI has read-only repository permissions and does not use GitHub secrets or
environment secrets. The workflow deliberately performs no deployment, login,
or live MAPIT request. The test suite blocks application network access, and a
job guard fails if MAPIT, model API, Telegram or AWS credential variables are present in its
environment. Dependency installation still requires access to the Python
package index; "offline tests" means no application/MAPIT network, not an
air-gapped CI runner.

The test extra requires `pytest>=9.1.1,<10`, including the known tmpdir security
fix and conftest-loading regression fix. CI updates its isolated pip to
`>=26.2,<27` before installation. A separate networked dependency-audit job
exports installed third-party pins and runs strict `pip-audit==2.10.1`, without
ignored advisories. Only the first-party source project is excluded; unknown
dependencies or audit failures block acceptance. This is not a claim of
complete security, and resolver changes remain possible without a lockfile.
The synthetic model-free evaluator and offline environment diagnostic also run.
Actions are referenced by immutable commit SHA in `.github/workflows/ci.yml`.

## Protection-rule history and current state

On 2026-10-05 the user authorized public portfolio publication after a
source/history and GitHub-surface review. Public visibility was verified;
the author email was retained with explicit consent. This makes the public
protection features available, but does not configure them. The post-change
`main` readback still reported no protection. See the current
[CD contract](cd-contract.md); there was no merge or AWS deployment.

The repository's prior private GitHub plan did not allow configuring the
desired Environment protection rules or deployment branch policies (GitHub
returned HTTP 422). It also rejected branch protection for `develop` and `main`
with HTTP 403 and requires GitHub Pro or a public repository. The `dev`/`prod`
Environment names exist, but they are not presented as enforced approvals or
deployment gates.

Until protection rules are configured and read back, promotion remains a repository convention
verified by the CI checks above, not an asserted platform guarantee. Do not push
feature work directly to `develop` or production work directly to `main`; use
pull requests even though GitHub cannot currently enforce that policy.
