# Phase 8 — AWS preparation and next gate

Status: PREPARATION ONLY. The user authorized design, public price research and
offline infrastructure as code on 2026-09-30. Phase 7 is complete. No AWS
account was queried, resources created, deployment performed, credentials
transferred, or paid inference invoked. Phase 8 exit criteria remain open.

## Proposed minimal service

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
creating even disabled resources can have costs. Only local template tests are
within the current approval.

## Transport feasibility, not interoperability acceptance

The installed MCP SDK exposes stateless Streamable HTTP with JSON responses.
This suggests a buffered Lambda adaptation, without an always-running process.
However, no remote adapter, synthetic client handshake or OAuth E2E has yet
been accepted. HTTP API integration timeout is at most 30 seconds; the proposed
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
  public OAuth metadata remain future transport-interoperability work.
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

1. **Bounded dev deployment/cost/identity gate**: approve region, minimal service
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

Do not ask for credentials pasted into chat or Git. Preparation remains entirely
public/offline; the next user decision precedes any billable AWS operation.
