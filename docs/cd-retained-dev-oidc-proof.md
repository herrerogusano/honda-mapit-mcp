# Retained-dev OIDC proof runner (offline preparation)

This is a separate, read-only identity proof for the new retained-development
proof role. It is not the production CD runner, does not modify the existing
bootstrap/preflight, and has not been executed against AWS.

The runner accepts only the `herrerogusano/honda-mapit-mcp` repository at
`refs/heads/develop`, with a lower-case 40-character `GITHUB_SHA`, matching
owner/repository IDs, `TARGET=dev`, the exact audience `sts.amazonaws.com`, and
the exact retained proof-role name. The expected account ID and role ARN are
explicit inputs; neither is discovered from ambient configuration.

The bounded sequence is:

1. validate the runner context and reject AWS profiles, config files,
   credential variables, custom endpoints and metadata sources; both HTTP
   transports disable proxy discovery rather than inheriting proxy settings;
2. request one OIDC token and validate its claims in memory;
3. make one unsigned `AssumeRoleWithWebIdentity` call through the fixed
   regional STS endpoint; and
4. create one explicitly credentialed STS client and make one
   `GetCallerIdentity` read.

Clients use TLS verification, no proxy, one SDK attempt and bounded timeouts.
Temporary credentials, token, subject, account/role values and provider
responses are never printed, exported, persisted or placed in artifacts.
Output is limited to status, target, source SHA, stage/category and boolean
verification fields. This proves identity trust only; it does not grant or
exercise Lambda, CloudFormation, S3, IAM, MAPIT or deployment operations.

Offline coverage is in
`tests/test_run_aws_retained_dev_oidc_proof.py`. No live token request, AWS
client call or workflow activation is part of this increment.
