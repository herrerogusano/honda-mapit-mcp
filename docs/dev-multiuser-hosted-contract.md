# Retained-dev multi-user hosted candidate

Status: hosted DEV scope authorized on 2026-10-06; implementation and
independent offline validation in progress. Not yet deployed or activated.

`scripts/build_aws_retained_dev_multiuser.py` deep-copies the closed
five-resource retained-dev scaffold and adds a separate, opt-in development
composition. It performs no AWS SDK calls, credential lookup, user creation,
password handling, or network operation.

## Fixed inventory

The candidate retains the existing API, stage, ARM Lambda, execution role and
log group, and adds:

- an administrator-created-only Cognito user pool with MFA disabled, managed
  login v2 domain, resource server with only the `use` scope, public PKCE
  client, and Cognito-provided managed-login branding;
- a JWT authorizer, one `POST /mcp` JWT route, and two unauthenticated metadata
  GET routes (`oauth-protected-resource/mcp` and
  `oauth-authorization-server`) targeting the existing Lambda integration;
- exact API Gateway invoke permissions for those three routes; and
- `honda-mapit-mcp-dev-tenants`, an on-demand DynamoDB table matching the
  existing reader's single string `key` primary key and `status`/`revision`
  item shape. The table uses AWS-owned default encryption and has no PITR,
  TTL, streams, indexes, backups, or customer-managed KMS key. New resources
  use explicit retain policies and require owner-directed deletion.

The table ceiling is ten read units/second and one write unit/second. Each
business operation deliberately rechecks authorization several times, so one
read unit/second would throttle the safety checks themselves. This is not a
Lambda quota increase; its regional ceiling remains ten concurrent executions.
The table charges requests, not this configured capacity. A five-minute test
at ten read units/second would be about USD 0.000425 of reads at the verified
regional rate, before burst behavior; this is not a billing hard cap.

The Lambda remains ARM64, 256 MiB, 20 seconds, reserved concurrency zero, and
uses an addressable `runtime/<sha256>.zip` object. Its proposed handler is
`mapit.aws_dev_multiuser_entrypoint.handler`, now separately implemented and
independently tested offline. Its role keeps the existing log writes and adds
only `dynamodb:GetItem` on the exact table ARN with the two supplied opaque
leading-key values. There is no scan, list, write, SSM, Secrets Manager, KMS,
network, MAPIT, or token permission.

The builder requires a lowercase observed API ID, content-addressed artifact
and source/JWKS/manifest digests, an exact loopback callback, an expected
12-digit account binding, and a positive execution window of at most 300
seconds. It also requires exactly two distinct canonical Cognito UUID subjects
and `tenant-<sha256>` keys. The Lambda environment is fixed to `MAPIT_MCP_ENV=dev`
and synthetic mode, and binds the manifest digest, account, and window. User
passwords, tokens, and MAPIT credentials are not placed in
CloudFormation. The generated real-bound template/manifest is private; technical
subject identifiers are private bindings, not portfolio examples. The resource identifier, pool, client, and callback values
are constrained parameters rather than guessed generated IDs.

The manifest contract is schema 1 and records the builder name, `dev`/
`synthetic` mode, source/API/pool/client/JWKS/table bindings, and exactly two
labelled tenant entries containing canonical UUID subjects and opaque keys.
Pool, client, and table identifiers are
CloudFormation references in the draft and require actual readback before an
operator can materialize or use a manifest.

## Gates still required

The owner accepted preserving the isolated pool/table and two technical users,
MFA off only in that pool, quota 10, no real MAPIT data or paid inference, and
bounded DEV opening. Before any account write, implementation must pass a
fresh V2 preflight/readback, dev-only IAM role and permission review, closed CD
and recovery design, artifact provenance, and the real Lambda entrypoint. At
most two technical users would be created in a journaled private operator step;
CloudFormation creates no users or passwords. This draft does not prove pool,
API, callback, Cognito, DynamoDB, or runtime interoperability and does not
change the production stack, quota, owner identity, Telegram, or MAPIT paths.

The first closed setup adds only six resources to the original five and leaves
all runtime properties unchanged. This obtains actual Cognito identifiers
before the private runtime artifact can be built. The second closed phase has
nineteen resources, with the endpoint disabled and Lambda reservation zero.
Opening and shutdown acceptance are separate from these closed updates.
