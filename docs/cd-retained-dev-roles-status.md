# Retained development CD roles — status

The permanent retained-development bootstrap is accepted as a closed,
read-only-reviewed configuration boundary after 15 bounded readbacks.  This
record contains no account identifiers, role ARNs, credentials, or provider
payloads.

The offline role factory in
[`build_cd_retained_dev_roles.py`](../scripts/build_cd_retained_dev_roles.py)
is review material only.  It creates two narrowly scoped roles and their
permission boundaries for the `honda-mapit-mcp-dev-retained` namespace.  The
executor can perform only the fixed development delivery/readback controls;
the CloudFormation service role can update only the retained handler and pass
only its exact existing Lambda execution role.

This acceptance does not mean runtime or continuous delivery is active.  No
role creation, artifact publication, stack update, endpoint activation, or
AWS account operation is performed by the factory or its tests.  Independent
runtime, private-artifact, service-role association, and CD executor gates
remain required before any live use.

Parent offline verification passed 2,652 tests with eleven environment skips.
All 37 synthetic templates passed the real pinned `cfn-lint` 1.57.1 checker
with its Python network guard and no findings; compilation and the model-free
evaluator also passed (12/12).
The runtime draft uses only public synthetic configuration and preserves
reserved concurrency zero and the disabled API. `AWS_REGION` is supplied by
Lambda, not configured by the template, as required by
[AWS's reserved-variable contract](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html).
The new reader returns private resource bindings only; it makes no activation
or current-runtime-closure claim.
