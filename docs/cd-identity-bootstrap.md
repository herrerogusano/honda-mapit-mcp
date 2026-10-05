# Closed GitHub OIDC identity bootstrap

`build_cd_identity_bootstrap()` is a pure template factory. It returns exactly
four resources: separate `dev` and `prod` IAM roles and permissions-boundary
managed policies. Each role trusts only the already-existing account-wide
GitHub OIDC provider ARN supplied to the factory, the exact audience
`sts.amazonaws.com`, and one exact environment subject derived from the fixed
repository name plus its observed legacy/immutable subject format. The caller
must supply the digest of the separately observed subject; a mismatch fails
closed. No account-wide OIDC provider is created by this template.

Both roles have a 3600-second maximum session duration. Their inline policies
allow only `sts:GetCallerIdentity`; each boundary allows that same action and
explicitly denies every other action with `NotAction`. These are closed
identity/bootstrap roles, not deployment roles. This does not itself provide
the later, separately reviewed IAM permissions needed to update an application.
The factory creates no outputs, deploy permissions, or AWS client. The returned
template necessarily embeds its supplied account ID/provider ARN in the trust
principal and the derived repository subjects in the trust conditions. Treat any
template built with real identifiers as private: do not print, commit, or attach
it to public artifacts. Only synthetic fixtures are used in the checked-in
tests. The role itself receives fixed `Project`, target `Environment`, and
`Purpose=CDIdentityOwnership` tags; the managed policy is intentionally not
tagged because that CloudFormation resource shape does not expose a supported
`Tags` property.

AWS documents permissions boundaries as a maximum permissions limit that does
not grant permissions by itself; effective permission evaluation also depends
on the role's identity policies and other applicable policies. An explicit
deny overrides an allow. See [permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html),
[policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html),
and [the `NotAction` element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html).
CloudFormation resource shapes are documented for [IAM roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html)
and [managed policies](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-managedpolicy.html).

The template is not deployed or accepted as effective account state. Trust
creation, boundary readback, actual `AssumeRoleWithWebIdentity`/caller-identity
verification, and any later permissions expansion remain separate operator
gates. The claim-shape discovery workflow explicitly does not verify JWT
signatures; do not use its output alone as proof for configuring trust.
