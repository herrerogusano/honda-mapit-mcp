# Retained-dev delivery sequence (offline prototype)

Status: bounded offline design only. This document records a possible
`develop` delivery path; it is not evidence of an AWS readback, a deployed
workflow, or a successful service-role association. It must remain separate
from the production `main`/`run_cd_release` path.

## Reusable pieces and hard boundary

The following pure or injected components are suitable building blocks:

| Component | Reuse decision |
| --- | --- |
| `scripts/build_aws_retained_dev_runtime.py` | Use for the synthetic closed runtime template and deterministic `runtime/<sha256>.zip` binding. |
| `scripts/build_cd_retained_dev_roles.py` | Use as the fixed dev executor/CloudFormation-role factory after private OIDC, stack, bucket, and handler readbacks. |
| `scripts/cd_retained_dev_delivery_contract.py` | Use for the immutable private binding and intent model, subject to the prior-inline-template recovery gap below. |
| `scripts/aws_retained_dev_delivery_preflight.py` | Use as a read-only preflight starting point; it is not a publisher or updater. |
| `scripts/aws_dev_runtime_artifact.py` | Reuse its conditional content-addressed ZIP publication semantics and tests through an injected S3 client. |
| `scripts/run_cd_release.py` / `src/mapit/aws_prod_geography_upgrade.py` | Do not import or parameterize. They hard-code prod names, prod journal fields, production source context, and production reopen semantics. |
| `src/mapit/aws_cd_journal.py` | Do not reuse directly: its schema and validation are permanently `prod_cd_delivery` and prod ARNs. Create a separate retained-dev journal adapter with the same CAS safety rules. |

The current `cd-readiness.yml` is read-only preparation. The current
`cd-release.yml` is `main`/`prod` only; there is no functional `develop`
delivery workflow yet.

## Proposed closed sequence

1. **Source gate.** Trigger only after the exact successful CI run for
   `develop`. Verify repository, workflow path, run SHA, branch, required check
   names/conclusions, and checked-out SHA. Use a protected `dev` environment;
   never put the private binding, ZIP, manifest, or journal body in GitHub
   artifacts or logs.

2. **Private binding and preflight.** Load a fresh, ACL-protected binding for
   the exact account, app stack, artifact stack, controls stack, artifact
   bucket, handler, OIDC provider, executor role, and persistent
   `honda-mapit-mcp-dev-retained-cfn-update` role. Read back the application as
   closed (API disabled, routes empty, Lambda reserved concurrency zero) and
   the exact control/artifact security receipts. The preflight must also read
   `DescribeStacks.RoleARN` and require the exact CloudFormation service role;
   IAM-role existence alone is not an association proof.

3. **Build.** Build only the synthetic runtime with the retained-dev builder
   and network-disabled ARM checks. No MAPIT session, OAuth secret, real user,
   or private data is allowed. Derive the bucket from the private account and
   fixed `eu-west-1`, then bind the template to
   `runtime/<zip-sha256>.zip` and the synthetic fixture hashes.

4. **Publish.** Save a publish intent before the single S3 write. Use the
   existing conditional semantics (`If-None-Match: *`, expected owner,
   SSE-S3, checksum, bounded `HeadObject`). A matching pre-existing object is
   idempotent only after exact size/checksum/encryption readback. Any ambiguous
   PUT permanently fences that journal; it is never retried by the same run.

5. **Associate the CloudFormation role, if not already bound.** This is a
   separate, explicitly journaled write with the exact stack ARN and
   `RoleARN`/`RoleArn` value, followed by bounded status polling and
   `DescribeStacks.RoleARN` readback. The implementation must first establish
   with an SDK-shape fixture (and later a separately authorized semantic gate)
   whether `UpdateStack` with `UsePreviousTemplate=True` and `RoleARN` is a
   valid no-template-change association. A `No updates are to be performed`
   response is not proof of association. Do not infer persistence from a
   successful IAM `PassRole` check.

6. **Update once.** Save an update intent before one `UpdateStack` call on the
   exact existing app stack. Supply the synthetic template, the exact
   `RoleARN`, `Capabilities=["CAPABILITY_NAMED_IAM"]`, and a unique request
   token. Poll only bounded `DescribeStacks`; no retry follows an uncertain
   response. The target remains closed: API endpoint disabled, routes empty,
   and Lambda reserved concurrency zero.

7. **Read back and finish closed.** Require `UPDATE_COMPLETE`, exact
   `RoleARN`, template/resource ownership, handler S3 key/checksum/configuration,
   API closure, Lambda reservation, and control/artifact invariants. Record
   only categorical status, call count, source SHA, and public digests. There
   is no reopen step in retained-dev delivery.

8. **Recovery.** A failed or ambiguous update is read-only reconciled first.
   Recovery uses a fresh bounded intent and exact previously closed template
   and artifact; it never replays the old write token. Mixed state, unknown
   stack status, missing service-role association, or unverifiable artifact
   causes a closed failure requiring operator review.

## Recovery blocker: the initial inline ZIP

The original retained-dev scaffold uses inline Lambda `ZipFile` code. The
current `RetainedDevDeliveryBinding` stores a prior-template hash and code
digest, but not the prior template body or inline ZIP bytes. A hash cannot
reconstruct the old `ZipFile`; therefore first-migration rollback is not
implementable from the current binding alone.

Before live delivery, choose one narrowly bounded design and test it offline:

- retain an exact private snapshot of the initial closed template/inline body,
  outside GitHub artifacts, logs, OneDrive, and the runtime journal; or
- explicitly declare first migration non-recoverable until a separately
  supplied exact snapshot is present, while allowing later S3-key recoveries.

After the first successful S3-backed update, recovery can bind the prior
content-addressed key and template digest. It must still reject a digest-only
or factory-reconstructed substitute.

## Delegated IAM and current permission gap

The retained-dev role factory correctly separates an OIDC executor from the
CloudFormation service role. The executor has fixed `UpdateStack` plus
`iam:PassRole`, runtime-prefix conditional publication, journal CAS/tagging,
and scoped read/write controls. The service role is the only role allowed to
update the Lambda code/configuration and read the runtime object.

The current executor policy does **not** grant the IAM reads used by
`RetainedDevDeliveryPreflight` (`iam:GetRole`, boundary `iam:GetPolicy`/
`iam:GetPolicyVersion`, role-policy/list/tag reads). Either a separate,
independently authorized private preflight identity must perform those reads,
or the dev executor factory needs a narrowly scoped reviewed read grant. Do
not broaden it to IAM mutation, role creation, policy attachment, listing, or
resource discovery.

The role factory also does not itself prove the persistent CloudFormation
association; that remains a required receipt and coordinator check. No
production role, workflow, policy, or binding should be parameterized for
this dev path.

## Implementation tasks after the offline IAM increment

1. Resolve the inline-ZIP recovery contract and extend the private binding
   schema without storing secrets or public workflow artifacts.
2. Add a separate retained-dev CAS journal and injected coordinator with
   `preflight`, `associate`, `publish`, `update`, `check-update`, and
   `recover` steps; preserve no-write replay fencing.
3. Close the IAM-read permission decision and add exact synthetic fixtures for
   `DescribeStacks.RoleARN`, `UpdateStack` association, S3 CAS, and both
   `CAPABILITY_NAMED_IAM` and unknown-response recovery.
4. Add a separate `develop` workflow with exact source gating and `dev`
   environment approval. Keep it disabled until source checks, role/bucket/
   artifact readbacks, service-role association, and fresh recovery tests are
   independently accepted.

No implementation or cloud activation is implied by this prototype.

## Subsequent offline checkpoint — 2026-10-06

The separate injected preflight, recovery ZIP/template publisher, update and
recovery coordinators, S3 CAS journal and five concrete phase validators are
now independently accepted offline. Actual SDK-shaped fixtures cover Lambda
tag maps, exact original creation-tag propagation, resolved IAM policies and
dynamic alarm readbacks. Both update cores reject altered persisted envelopes,
invalid phase/state transitions and clock rollback; ambiguous writes remain
fenced and require the exact top-level stack completion event, not child events.
The integrated suite passed 3,055 tests with twelve environment skips;
compilation and model-free evaluation passed 12/12.

This checkpoint does not implement an operational AWS client/receipt collector,
automatic delivery workflow, persistent CloudFormation role association,
artifact upload, live update or recovery. It does not establish acceptance for
every CloudFormation failure status. The earlier sequence is a design proposal,
not a list of cloud steps already executed.

GitHub's ephemeral Actions token was denied the branch-protection read in the
bounded diagnostic run `37493152388`. A repository-only read-only GitHub App
is awaiting the owner's separate credential/install decision; no personal token
was copied, no App was created and the source-protection gate was not bypassed.
Production/main, owner/MFA, MAPIT data and regional concurrency quota 10 remain
unchanged. Retained dev is closed outside separately reviewed bounded tests.
