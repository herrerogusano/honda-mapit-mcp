# Phase 8 — AWS preparation and next gate

Status: LOCAL SYNTHETIC HTTP/AUTH AND LAMBDA COMPOSITION ACCEPTED;
bounded dev gate approved, provisioning suspended at concurrency decision.
The user authorized design, public price research and offline infrastructure as
code on 2026-09-30, then the bounded local HTTP/auth tests on 2026-10-01; see
[local HTTP contract](phase-8-local-http-contract.md). Phase 7 is complete. A later
user-authorized read-only billing-console review confirmed active credits and
eligibility of core proposed services; exact balances and private identifiers
are not recorded in Git. The Free Tier view had no usage data, which is not
proof of eligibility or zero charges. Before the dev gate below, no account
SDK/inventory operation, resource creation, deployment, credential transfer or
paid inference occurred.
The local [Lambda composition block](phase-8-lambda-local-contract.md) is now
independently accepted offline: 42 focused tests and 754 full tests pass (3
skipped), compilation succeeds and the model-free evaluator passes 12/12.
Phase 8 exit criteria remain open.

## Approved dev gate and preflight — 2026-10-01

The user approved dev in `eu-west-1`, synthetic data/tools only, resources for
at most one hour, endpoint active at most five minutes, a USD 1 gross allowance
expected against credits (not an AWS-enforced billing cap), and shutdown plus
deletion of newly created resources. Prod, real MAPIT data/session migration,
Telegram and paid model inference remain excluded. The window has not opened;
the resource-lifetime clock starts only with the first resource creation.

Two bounded read-only CLI operations were made: one STS identity check and one
Lambda account-settings read, each with one attempt and short timeouts. Only
booleans/categories and quota counts were emitted, not identities or credentials.
Authentication succeeded with a non-root identity. Lambda reported regional
concurrency limit **10** and unreserved concurrency **10**. No resources,
identities, alarms or schedules were created, and no function was invoked.

AWS currently documents positive reserved concurrency as at most the unreserved
pool minus 100. The observed reduced quota therefore offers no positive reserve
for the intended one-execution cap. This is a documented-rule inference; no
concurrency mutation was attempted. See [reserved concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html)
and [reduced account quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html).

Provisioning is suspended pending reviewed independent controls and a coordinated
quota decision; the user selected separate project limits, not shared-pool fallback.
Removing reserve
0 during activation would use the shared account pool rather than enforce one
execution per function. Stage throttling is not an equivalent concurrency cap.
Do not silently remove the reserve, request a quota increase or change region.
A fallback, if approved, still needs bounded requests, independently armed
shutdown, restoration of reserve 0, post-close verification and complete cleanup.
The historical vault example's retained pool of 10 must not be treated as AWS's
currently documented general rule of 100; recheck effective settings before any
activation.

Other prerequisites remain: a separate synthetic-only runtime policy for real
Cognito issuer/resource/owner (no weakening of the accepted `.invalid` factories),
Linux ARM Python 3.13 package/import tests, exact client callback and owner
binding, reviewed creation/cleanup orchestration and independent shutdown.
The existing inline-503 template remains unchanged and must not be deployed as
if it were a working MCP artifact. No CloudFormation validation or OAuth E2E
was performed by this preflight.

## Proposed minimal service

### Time-bounded coordination and next offline runtime block

On 2026-10-01 the user authorized proceeding through gates of the agreed work
for two hours, ending about 17:53 Europe/Madrid. This does not extend the dev
endpoint's five-minute limit, the one-hour resource lifetime or USD 1 gross
allowance. Prod, MAPIT data/session migration and paid inference remain outside
this work. Authorization must be rechecked after that time before new external
actions. No resource-creation window has begun.

The existing `aws-remote-mcp` owner chat was explicitly authorized to prepare
and independently review its own offline switch from shared-pool dependence to
reserved concurrency. It reported its local preparation complete with 280 tests,
fixed MCP reserve 1, fail-closed capacity preflight, independently armed shutdown
and post-close audit. No commit, deployment or AWS operation was performed there.
The historical quota/pool-10 fallback remains explicit opt-in in that project;
it is not selected here. Honda must not mutate that repository or activate its service.
An additional single-attempt Service Quotas read confirmed applied quota 10,
adjustable=true. No increase request was submitted. Do not use a shared-pool
fallback; review independent project controls before any coordinated increase.

Approve the next bounded offline implementation: a separately named dev-only
Cognito policy and synthetic runtime composition, with injected public keys
and strictly derived/bounded JWKS parsing. Keep immutable `.invalid` public
factories closed. Reuse private transport helpers where necessary without
adding general provider injection. Always construct `SyntheticServicesProvider`;
no local credential/session/ledger lookup, AWS SDK, secret read or MAPIT client.
Require exact eu-west-1 Cognito issuer, owner/client/access-token claims,
canonical execute-api `/mcp` audience and its `/use` scope. For this five-minute
synthetic test, use a fixed public-key snapshot; unknown/rotated keys fail closed
rather than trigger unbounded discovery. Tests use generated keys/JWKS fixtures
only, never contact Cognito. Real JWKS retrieval, env entrypoint, ARM artifact,
runtime IAM and independent shutdown are separate reviewed steps, not implied
by this factory. Do not wire or activate the disabled scaffold yet.

The supervisor's final local tree passes **800 tests, 3 skipped**; compilation
and the model-free evaluator (12/12) succeed. Independent review accepted the
final tree with 110 focused tests and the same 800-test full result. The new factory is an offline
composition, not a Lambda environment entrypoint or proof of Cognito interoperability.
It checks identifier format, not whether a shaped identifier exists in AWS.

A local dependency-only packaging probe used the official Lambda Python 3.13 ARM
image pinned to digest `sha256:69b91b6e0b637c459f80bc103c2e566be76cbeb934f32bf2d8c14e028ce57719`.
Linux ARM wheels installed successfully. A subsequent container with networking
disabled imported MCP, cryptography, pydantic-core, JWT and httpx2 on `aarch64`:
38,257,691 dependency bytes, four native shared objects, no Windows `.pyd` files.
This is not a final artifact, dependency vulnerability acceptance or deployed test.
`httpx2` is a core dependency of the pinned MCP SDK, not an optional extra to remove.

For two one-execution MCP reservations, the structural regional floor is
`Q >= R + 2 + max(100, C + S)`, with other allocated reservations `R`, bounded
shared workload demand `C` and shutdown demand `S`. A floor of 102 only applies
when `R=0` and `C+S<=100`; no present workload bound has been established.
Shutdown Lambdas in the shared pool are not guaranteed capacity under saturation.
Fresh allocation inventory, explicit shutdown-capacity review and intended-account
verification must precede a precise increase request. No request has been submitted.

Sources: [Lambda packaging](https://docs.aws.amazon.com/lambda/latest/dg/python-package.html),
[reserved concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html),
[concurrency metrics](https://docs.aws.amazon.com/lambda/latest/dg/monitoring-concurrency.html).

One private, single-owner read-only MCP per environment in `eu-west-1`
(Ireland): HTTP API Gateway, ARM Lambda, Cognito authorization-code/PKCE login,
and short-retention redacted CloudWatch logs. No hosted LLM, Bedrock, persistent
Telegram worker, remote ledger, realtime worker, database, NAT gateway, purchased
domain or frontend. Codex supplies the conversational client; hosting tools does
not require a project-owned inference API.

Dev and prod would have separate stacks, pools, app clients, IAM roles, logs,
secrets and canonical resource URLs. Isolation is designed, not demonstrated in
an account. GitHub environment names do not substitute for enforced protection;
the known GitHub-plan limitation remains documented in environments-and-ci.md.

The offline [template](../infra/aws/template.json) is a guardrail scaffold, not
a deploy-ready MCP. Its Lambda is a constant unavailable response, concurrency
is zero, and the default execute-api endpoint is disabled. It contains no MAPIT
session or IAM access to one. It must not be deployed as a way of testing it:
creating even disabled resources can have costs. Local template tests and the
separately bounded synthetic HTTP/auth block are within the current approval.

## Transport feasibility, not interoperability acceptance

The installed MCP SDK exposes stateless Streamable HTTP with JSON responses.
This suggests a buffered Lambda adaptation, without an always-running process.
The local synthetic stateless JSON handshake and all ten tool calls are now
accepted, with cryptographic token verification and negative tests; see the
local contract. The synthetic Lambda/payload-v2 adapter is independently
accepted locally, not in AWS. No actual OAuth login E2E has been accepted.
HTTP API integration timeout is at most 30 seconds; the proposed
Lambda budget is 20 seconds. Existing upstream timeout/recovery can exceed that
combined budget, so an end-to-end deadline is a prerequisite, not something the
scaffold fixes. HTTP API response streaming is not assumed: API Gateway's
documented response transfer streaming is for REST APIs. If tested clients need
SSE/session continuity, reconsider the runtime before provisioning.

Sources: [HTTP API quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html),
[API Gateway streaming](https://docs.aws.amazon.com/apigateway/latest/developerguide/response-transfer-mode.html),
[MCP Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Identity and credential design

Codex documents Streamable HTTP and stored OAuth with a pre-registered client
ID. This lets us propose Cognito without building a dynamic-client-registration
server. The actual callback URI must be obtained from the intended Codex
configuration, then registered exactly. Cognito's HTTP loopback exceptions are
for testing and accept custom ports; an arbitrary ephemeral port is not assumed
to match the allowlist. Configure and verify a fixed listener port and the exact
client callback path/query before dev activation. No client settings were changed
or account login attempted during preparation.

Sources: [Codex MCP/OAuth documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli),
[Cognito app-client callbacks](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html).

Admin-only signup, a public client without a client secret, code-only PKCE,
Managed Login v2 and narrow resource-bound scope are proposed. No owner user is
created by the scaffold. Managed Login branding is included; account ownership,
password setup/recovery and the draft's mandatory TOTP MFA require a deliberate
operator workflow and acceptance at the dev identity gate.
The future implementation must publish OAuth protected-resource metadata,
bind access tokens to the canonical resource URI and scope, verify claims at
the gateway AND enforce owner subject/issuer/audience/expiry/token-use in the
application. An audience check alone is not single-owner authorization.
Unrecognized identities must never inherit the local default MAPIT session.

Sources: [resource-bound access tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html),
[OAuth guidance](https://developers.openai.com/plugins/build/auth).

Proposed MAPIT refresh-session storage: a separate Standard SSM SecureString
per environment, encrypted using the AWS-managed SSM KMS key; no email/password
in infrastructure parameters or model-visible arguments. CloudFormation's SSM
Parameter resource does not support SecureString, so a future approved secure
out-of-band provision/rotation flow is required. Exact secret/key ARNs and
least-privilege read/decrypt permissions must be verified before adding them.
Refresh-token rotation, concurrent refresh ownership, expiry, revocation and
re-authentication are unresolved operational requirements. Windows Credential
Manager and the local SQLite/alias key are not silently migrated or uploaded.

Sources: [SSM parameters](https://docs.aws.amazon.com/systems-manager/latest/userguide/what-is-a-parameter.html),
[CloudFormation SSM limitations](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-parameter.html),
[SSM encryption](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html).

## Offline scaffold boundaries

- Resource names derive from an explicit dev/prod parameter. Placeholder resource
  URI and callback must be replaced only through a reviewed future patch.
- The protected POST `/mcp` route has JWT audience and required resource scope.
  There is no anonymous MCP route or default wildcard route. GET handling/405 and
  public OAuth metadata are locally tested but remain unwired in the AWS scaffold.
- Reserved concurrency is literally zero; there is no activation toggle. Lambda
  cannot currently read secrets or MAPIT, and its code does not log request data.
- Seven-day application log retention is proposed. No payload/token/location
  logging is permitted; future error paths and API access logging need review.
- Offline tests can check JSON relationships and security invariants, not AWS
  service-side acceptance, OAuth security or remote availability.

## Cost estimate — illustrative gross subtotal, not a cap

Independent offline review accepted the disabled scaffold. Its seven focused
tests pass; the full Windows Python 3.13 suite has **638 passed, 3 skipped**,
compilation succeeds and the model-free evaluator passes 12/12 synthetic cases.
No CloudFormation service validation or AWS interoperability test was run.

Public regional price lists checked on 2026-09-30, published Sep 11–25, 2026.
No account lookup, credits, free tier or currency conversion assumed. USD,
before taxes. Example: 10,000 total requests/month (not conversation count),
256 MiB ARM Lambda, 1 billed second/request, 1 Cognito Essentials MAU,
0.01 GB log ingestion and 0.01 GB-month storage, 20,000 standard symmetric KMS
operations. These are assumptions, not measured usage.

| Component | Regional rate | Example USD/month |
| --- | --- | ---: |
| HTTP API | $1.11/million requests | 0.0111 |
| Lambda requests | $0.20/million | 0.0020 |
| ARM Lambda compute | $0.0000133334/GB-second | 0.0333 |
| Cognito Essentials | $0.015/MAU | 0.0150 |
| Standard log ingestion | $0.57/GB | 0.0057 |
| Standard log storage | $0.03/GB-month | 0.0003 |
| Standard symmetric KMS | $0.03/10,000 operations | 0.0600 |
| **Listed subtotal** | | **0.1274** |

At 20 billed seconds/request, the same listed subtotal becomes about $0.76.
Neither number is a total bill estimate or spending guarantee. Excluded costs
include outbound transfer, extra retries/protocol/auth calls, alarms, extra log
queries, any chosen budget features, packaging/storage and configuration-dependent
charges. Provisioning/teardown verification must quantify these before approval.
No private route payload size or latency measurement was performed for AWS.

Source files: [API Gateway](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonApiGateway/current/eu-west-1/index.json),
[Lambda](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSLambda/current/eu-west-1/index.json),
[Cognito](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCognito/current/eu-west-1/index.json),
[CloudWatch](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/current/eu-west-1/index.json),
[KMS](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/current/eu-west-1/index.json).

Budget alerts are delayed, not a hard spending cap. Future activation must
combine bounded upstream work, throttling, tested shutdown/teardown and alarm
ownership. Zero reserved concurrency prevents Lambda execution but not every
stack charge; disabling execute-api alone would not disable a custom domain.
Regional reserved-concurrency quotas must be checked under a later account-read
approval; do not silently drop the kill switch if the chosen account rejects it.

Sources: [budget latency](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html),
[Lambda concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html),
[execute-api endpoint setting](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html).

## Next gates

1. **Bounded dev deployment/cost/identity gate**: the short synthetic dev window
   above is approved but suspended at the concurrency decision. Before creation,
   finish the runtime/package/shutdown prerequisites and confirm the intended
   account/operator and exact owner/callback binding. For any later live-data
   expansion, approve region, minimal service
   scope, account read/provisioning authority, a defined gross spend envelope and
   test duration, operator/owner identity, exact callback/resource URI, secret
   handoff/rotation and cleanup. First complete synthetic transport/deadline,
   authorization-negative tests and deployment validation; a disabled stub is
   not permission to activate or a successful service test. No production,
   MAPIT credential migration or live MAPIT call is implied by preparing IaC.
2. **Prod gate**: only after accepted bounded dev interoperability/security,
   operational controls, measured costs and independent review. Decide production
   retention, monitoring, ownership, credential rotation and recovery explicitly.
3. **Optional managed-agent/model gate**: a separately selected provider/model,
   evaluation scope and explicit inference spend approval. Not required to use
   this MCP from Codex. No paid model evaluation is currently approved.

Do not ask for credentials pasted into chat or Git. Implementation remains
offline; the separately authorized billing-console review was read-only. The
next user decision precedes provisioning or any billable AWS operation.
