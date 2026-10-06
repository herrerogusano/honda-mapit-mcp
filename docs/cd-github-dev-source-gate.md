# Read-only `develop` source gate

`scripts/github_dev_source_gate.py` is an offline-testable, read-only gate for
the future retained-dev promotion operator. It has no AWS, credential, write,
workflow-activation, or deployment behavior. Local Git and GitHub reads are
injected, bounded, and return only a safe category projection.

The typed payload is fixed to repository `herrerogusano/honda-mapit-mcp`,
`develop`, environment `dev`, a non-zero owner/repository/run identity, and a
40-character source SHA. The gate rejects non-read-only payloads and validates:

- clean local `develop` checkout, exact `HEAD`, and no tracked or untracked
  worktree changes;
- exact repository owner/IDs and `refs/heads/develop` SHA;
- one completed successful push CI run at that SHA, active workflow
  `.github/workflows/ci.yml`, and exactly the eight required job names;
- the existing shared branch/environment protection validators, including the
  `dev` reviewer/branch policy and disabled administrator bypass.

The module intentionally does not add a workflow. A later CD design can use a
bounded `push`-to-`develop` workflow that waits for the protected CI run and
then invokes this gate before any separately authorized AWS action. The
`workflow_run` default-branch constraint is therefore not hidden or bypassed.

Offline coverage is synthetic only; no live GitHub read has been performed by
this implementation.

The separate `github_dev_source_transport.py` adapter is independently accepted
offline. It uses direct verified TLS to `api.github.com`, fixed repository GET
routes, no redirects/retries/pagination, a 256 KiB decoded-body limit, strict
declared-length/framing checks, duplicate/non-finite JSON rejection, and a
45-second overall monotonic deadline. Local Git commands are allowlisted,
bounded, have inherited `GIT_*` overrides removed, disable the fsmonitor hook
and optional locks, and never emit raw responses or supplied tokens. The caller
must supply one temporary GitHub token and exact successful CI run binding;
there is no ambient CLI authentication, run discovery, workflow activation,
AWS exchange, or output-file writer.

`run_github_dev_source_gate.py` adds strict runner context validation and a
safe result projection. The separate path-filtered develop-only
`cd-dev-read-permissions.yml` performs three bounded protection metadata reads
with the ephemeral Actions token. It contains no AWS/OIDC/secrets/artifacts or
deployment and reports failure unless the complete existing protections are
actually read and validated. This diagnostic is not a ninth required CI job.
The endpoint's documented Administration-read permission may not be available
to the Actions token; live capability is not inferred from offline tests.
See [GitHub branch-protection permissions](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection).

PR 44 merged normally to develop at `f033045`, with eight green checks. The
develop push CI run `37490482878` also passed all eight jobs. The separate
diagnostic run `37490483138` failed closed: environment and deployment-branch
policy reads succeeded, but branch protection was unavailable and complete
protection validation was false. No raw HTTP response/status was retained, so
the result does not independently distinguish a permission denial from another
transport rejection. The documented Administration-read requirement makes a
limited repository-only GitHub App a proposed solution, not an activated one.
Owner authorization for that additional credential/install scope is pending.
No AWS operation, new STS exchange, runtime delivery, or production/main change
followed from this diagnostic.
