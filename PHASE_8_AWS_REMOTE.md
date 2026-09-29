# Phase 8 — AWS Remote Service & Managed Agent Evaluation

## Goal

Make the read-only MCP available as a secure, reliable AWS-hosted service, using
the owner's AWS credits deliberately and without coupling the MCP runtime to a
particular language-model provider.

## Architecture boundary

The remote MCP and the agent are separate deployable concerns:

```text
Codex or another MCP client
          |
          v
Remote MCP transport + OAuth on AWS
          |
          v
Services -> MapitClient -> MAPIT

Optional managed agent on AWS
          |
          +---- calls the same remote MCP
          +---- uses a separately selected model/provider
```

Publishing the MCP does not itself require an LLM call. Model inference is
needed only if an always-on conversational agent is also deployed.

## Prerequisites

- Phases 4–7 are accepted for the capabilities included in the remote service.
- Remote transport, user isolation, secret storage, and operational ownership
  are documented before provisioning.
- Current AWS capabilities, quotas, and prices are rechecked against primary
  documentation; historical vault notes are guidance, not live inventory.
- A cost envelope and explicit deployment gate are approved before creating
  billable resources or making paid model calls.

## Track A — Remote MCP service

Design and evaluate:

- Streamable HTTP transport and interoperability with the intended MCP clients;
- OAuth authorization code with PKCE, exact resource audience, narrow scopes,
  and no credentials or bearer tokens exposed to the model;
- an AWS runtime chosen from measured traffic, latency, streaming, timeout,
  concurrency, and cold-start requirements;
- secret storage and refresh-token lifecycle with least-privilege IAM;
- dev and prod isolation, infrastructure as code, deployment gates, rollback,
  throttling, alarms, redacted logs, and a hard operational kill switch;
- bounded offline, dev, and production smoke tests with complete cleanup.

The default remains read-only. Remote deployment does not authorize MAPIT
writes or expand the tool set.

## Track B — Optional managed agent and model evaluation

Run this track only if an agent must operate independently of Codex or another
MCP client. Compare candidates using the project's fixed evaluation suite and a
pre-approved spend cap. At minimum measure:

- tool selection and grounded-answer accuracy;
- MCP/tool-calling compatibility and structured-output reliability;
- latency, context limits, regional availability, and operational complexity;
- input, output, and tool-loop cost for representative requests;
- data-handling, retention, observability, and vendor-lock-in implications.

AWS credits make Bedrock a natural candidate, but not an automatic choice. The
decision may be Bedrock, another provider, or no hosted agent at all. The MCP
must remain provider-neutral.

## Security and cost rules

- Never place MAPIT email/password, refresh tokens, temporary AWS credentials,
  OAuth tokens, vehicle identifiers, or location data in Git, prompts, logs, or
  model traces.
- Separate operator credentials, application roles, end-user identity, and
  MAPIT session material.
- Treat budgets as alerts, not hard caps. Use throttles, concurrency limits,
  bounded requests, disabled-by-default environments, and explicit teardown or
  shutdown controls.
- No live deployment or paid inference is implied by this plan. Each requires a
  separate user-authorized gate with the expected maximum spend stated first.

## Evidence ladder

1. Offline infrastructure and policy tests.
2. Local remote-transport integration with synthetic data.
3. Short-lived dev deployment with synthetic tools and no model.
4. Authorized dev MCP interoperability test.
5. Optional bounded model bake-off using fixed cases.
6. Production deployment and post-deploy audit.

Passing an earlier level does not count as evidence for a later one.

## Exit criteria

- The remote MCP is reachable by the approved clients through a verified OAuth
  flow and exposes only the intended read-only tools.
- Dev and prod are isolated, reproducible from infrastructure as code, observable
  without sensitive data, and have tested rollback and shutdown procedures.
- Actual cost controls and residual cost risks are documented.
- If Track B is enabled, the chosen model/provider passes the fixed evaluation
  threshold and its measured quality, latency, and cost justify the choice.
- If Track B is not enabled, the service works with external MCP-capable clients
  and incurs no project-owned model-inference cost.
