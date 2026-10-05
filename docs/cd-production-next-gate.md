# Next delivery gate: private code-only production updates

This is an offline architecture proposal, not a deployable workflow, permission
receipt or authorization to modify the running service. Identity-only GitHub
roles must remain unchanged. Production remains single-owner in eu-west-1,
with quota 10, existing owner/MFA and the USD 1/month gross target (not a billing
hard cap). No paid inference, MAPIT history probe or Telegram activation follows.

## What is still missing

GitHub authentication and CI do not constitute continuous delivery. The existing
production update core is injected, journaled and limited to an exact S3 object
key plus runtime-manifest digest change. It rejects a CloudFormation `RoleARN`
and contains expired authorization windows. It cannot be reused as a fresh
GitHub deployment executor. The old dev rehearsal application was deleted;
a dev identity role is not a deployable dev environment.

Reuse the accepted private ARM builder and conditional exact-key publication
helper. Do not upload a real-bound package, JWKS/manifest, templates, journals,
authorization material or private resource identifiers to GitHub artifacts or
logs. A local private publisher is the initial proposed artifact handoff; its
receipt is not proof of successful production deployment.

## Recommended role separation

Keep the current dev/prod identity roles caller-identity-only. Prepare two new
roles offline, with actual creation a separate reviewed gate:

- A production GitHub executor, bound to the exact observed immutable prod
  environment subject, may update/read only the owned production stack and pass
  only the dedicated CloudFormation role to CloudFormation. It may perform the
  exact existing shutdown and readback controls required by the coordinator.
  It has no direct Lambda code/configuration write, IAM mutation, S3 publication,
  stack creation/deletion or MAPIT-secret access.
- A dedicated CloudFormation service role trusts only CloudFormation and can
  change code/configuration only on the exact existing handler and read runtime
  objects only from its accepted prefix. It cannot manage IAM, the API or S3
  writes/deletion. Whether the provider requires an exact existing-handler
  execution-role `PassRole` must be resolved before approving a policy; do not
  guess or add a wildcard to get past a failure.

This is a proposed capability split, not a complete IAM policy. Enumerate all
required read/control actions and exact resources from accepted operator seams;
independently test the trust, boundary, denied actions and SDK request shapes.
The executor's `PassRole` must bind `iam:PassedToService` to CloudFormation and
the stack operation to the exact approved `cloudformation:RoleArn`.

## Persistent architectural consequence

Attaching a CloudFormation service role is not a temporary GitHub setting.
AWS states that the role cannot subsequently be removed from the stack, is
used for future stack operations, and can be used by other principals permitted
to operate that stack even without their own `PassRole` permission. Review
existing stack operators and least privilege before accepting that permanent
association. [AWS service-role documentation](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html)

The alternative is granting direct Lambda update permissions to the GitHub
caller so CloudFormation can use its temporary credentials. That is simpler,
but permits bypassing the intended update coordinator. It is not silently
selected by this proposal. Neither role design is implemented or activated.

IAM cannot prove the template changed only the two approved properties; retain
an exact template-diff guard, source/artifact binding, journal and readbacks.
Do not combine `Capabilities` and `ResourceTypes`: AWS permits only one, and
the current core supplies `CAPABILITY_NAMED_IAM`. A stack-policy change would
also be a separate reviewed mutation, not implicit protection from that flag.
[AWS UpdateStack contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html)

## Bounded implementation sequence after that decision

1. Independently accept offline roles/boundaries and a fresh injected executor.
   Replace neither old journals nor expired windows. Require immutable source,
   artifact, ownership, regional cost and execution-window bindings.
2. Review the exact role-association change, live policy readbacks and recovery.
   Preserve identity roles and the existing shutdown mechanism. Do not broaden
   another project's IAM or quota.
3. Prepare a private exact candidate and retained prior artifact. CI and the
   protected prod approval bind the exact source and reviewed candidate.
4. Execute close, verify closed, request the exact code-only update once, verify
   exact code/configuration/ownership, then separately approve reopening. On an
   ambiguous write, stop and reconcile by ownership-bound readbacks, never replay.
5. Recovery uses a fresh intent and retained prior ZIP/manifest through the same
   closed checks; it does not blindly replay an old update. Retiring an artifact
   is not rollback and the existing app-deletion retirement helper is unsuitable
   for deleting a prior package during ordinary production upgrades.

A permanent dev deployment needs its own target, lifetime, cost, shutdown and
data-isolation decision. This proposal does not recreate dev resources, enable
automatic deployment on merge, introduce public signup, transfer sessions or
grant broad SAM/CloudFormation deployment permissions.

Independent offline document/core review found no concrete scope mismatch:
the proposal does not claim complete IAM policies, a deployed dev target or
completed CD. The integrated compatibility source passed 2,295 offline tests
with ten environment skips; this validates existing code, not the proposed
roles or an unimplemented delivery executor.
