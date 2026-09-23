# Environments and CI

## Branch promotion

The project uses this promotion flow:

```text
feature/* -> develop -> main
```

`develop` is the development integration branch. `main` is the production
branch. Pull requests and pushes to either branch run the same offline CI
workflow across Python 3.11, 3.12, and 3.13. Feature branches are checked when
they open or update a pull request targeting one of those branches.

The GitHub `dev` and `prod` Environments are project environments for future
workflow/deployment coordination. They are not additional MAPIT endpoints and
do not imply that CI can authenticate to MAPIT.

## CI security boundary

CI has read-only repository permissions and does not use GitHub secrets or
environment secrets. The workflow deliberately performs no deployment, login,
or live MAPIT request. The test suite blocks application network access, and a
job guard fails if `MAPIT_EMAIL` or `MAPIT_PASSWORD` is present in its
environment. Dependency installation still requires access to the Python
package index; "offline tests" means no application/MAPIT network, not an
air-gapped CI runner.

The test extra is pinned to `pytest>=8,<9` for a stable major-version range.
Actions are referenced by immutable commit SHA in `.github/workflows/ci.yml`.

## Protection-rule limitation

The repository's current private GitHub plan does not allow configuring the
desired Environment protection rules or deployment branch policies (GitHub
returned HTTP 422). It also rejected branch protection for `develop` and `main`
with HTTP 403 and requires GitHub Pro or a public repository. The `dev`/`prod`
Environment names exist, but they are not presented as enforced approvals or
deployment gates.

Until the plan supports those rules, promotion remains a repository convention
verified by the CI checks above, not an asserted platform guarantee. Do not push
feature work directly to `develop` or production work directly to `main`; use
pull requests even though GitHub cannot currently enforce that policy.
