# Owner MAPIT enrollment in closed DEV

The post-delivery login verifies and discards a Cognito token. It does not
connect a MAPIT account. `scripts/run_dev_owner_mapit_enrollment.py` is a
separate, explicit operator for that missing step. Its default path uses the
owning historical parsers, current SDK observer, real enrollment registry and
publication adapter. Imports, `--help`, and preparation grant no cloud authority.

## Prerequisites and scope

- A new reviewed source commit, integrated CI and current protections.
- An immutable accepted owner delivery and its original private inputs.
- A fresh ACL-private authority in a new directory, outside Git and OneDrive.
  It binds that exact directory, operation ID, source/CI, account/operator,
  accepted runtime evidence, owner tenant, exclusive period and SDK limit.
- The expected AWS operator, a fresh owner Cognito login and private consent to
  read the existing MAPIT refresh session from Windows Credential Manager.

The new authority is schema 1, kind `owner-mapit-enrollment-dev`, with exactly
`operation_id`, `state_directory`, `account_id`, `operator_arn`, `source_sha`,
`ci_run_id`, `github_owner_id`, `github_repository_id`, `authorized_from_epoch`,
`authorized_until_epoch`, `runtime_evidence_sha256`, `owner_tenant_key` and
`max_sdk_calls`, in addition to `schema` and `kind`. The implementation rejects
an authority longer than 1,200 seconds or above 192 SDK calls. Those maxima
are validation ceilings; preparation still needs an explicit owner decision
for its actual period and scope. Copying an authority into a different
directory is rejected. Accepted or ambiguous attempts are never resumed.

This operator performs at most three conditional document writes and one
create-only Standard SecureString publication. It preserves the existing
owner authorization row, version-one binding keys, historical tenants,
production, MFA, Telegram and Lambda quota. It keeps the API closed and
reservation zero. It neither opens an endpoint nor calls business tools.

## Execution

1. Check source/protections, private provenance and the actual closed runtime
   with the accepted namespace still empty. Admit every SDK request, including
   parser-constructor reads, against one shared counter before dispatch.
2. Obtain a fresh PKCE token using the dedicated DEV owner client. Authenticate
   the owner against the finite invitation list and original authorization
   table. Discard the bearer; retain only the sealed grant and snapshot.
3. Assume and verify the exact namespace enroller role with explicit temporary
   credentials. Read the existing key version into memory with its owning
   loader; never regenerate or republish those keys.
4. Ask for consent in a private native dialog, then read the saved refresh
   session through the captured native backend. `load_readonly()` performs no
   migration, save, delete or global-backend rerouting. No password, MFA code,
   token or session appears in arguments, environment, chat or browser DOM.
5. Recheck source/protections and persist a fresh durable intent. Start the
   exclusive fourteen-second enrollment lease only after consent. Require
   document absence for the first CAS, then exact document revisions 1 and 2
   for the next CAS operations. Verify signed MAPIT identity and publish exactly
   session version one with `Overwrite=False`, followed by decrypted comparison
   in memory. The durable document ends at revision 3 with one active owner.
6. Use the separate post-enrollment observer. It retains full resource,
   template, IAM, table, key metadata and historical-row invariants; verifies
   the actual nonempty document, MAC, proof continuity and session metadata;
   and ends with fresh caller/API/reservation checks. The historical observer
   continues to require an empty namespace and is not weakened.

The CLI requires `--authority-root`, `--delivery-root`, `--source-sha`,
`--ci-run-id` and the same individual private-input path arguments as the
accepted delivery runner. It prints only the query-free local login root and
fixed result categories, phase and bounded counters. SDK calls and the three
possible MAPIT authentication HTTP requests are separate counters. Provider
credential-refresh traffic, public JWKS requests and GitHub gate commands are
not misrepresented as SDK calls.

## Time and private-file checks

Owning provenance validation runs before minting a registered native baseline.
During short leases, the baseline compares file identity/content, every parent
identity, native owner/group/DACL descriptors including control flags, and
registered public/private projections. It runs no PowerShell subprocess.
Mutable fields, copies, re-registration and rebaselining an existing changed
file do not create a new capability. Adding an authority or durable fence must
match the exact fingerprint returned by its owning snapshot validator. SDK
admission resamples both clocks after
the scans and rejects cutoff, rollback or stale source evidence before sending.

## Failure and acceptance

`attempt.json` prevents another process from reusing the directory. Intent
precedes any conditional publication. An uncertain dispatch consumes the
attempt and stops subsequent writes; pending documents or a possibly created
secret are held for separate readonly reconciliation. No cleanup, compensating
deletion, retry, password reset or delivery replay is performed.

`owner_mapit_enrollment_verified` means the account binding and session
publication have passed the closed readback. It does not establish real
vehicle status/distance results, deployed Lambda-role access, endpoint
interoperability or two-account isolation. Those remain separate tests. An
endpoint test needs a new reviewed window and independent closure compatible
with the enrolled handler; the existing synthetic window cannot be reused.

SDK-shaped integration tests traverse the owning parsers/observer, signed MCP
JWT, native baseline, actual registry/publisher and post-readback using
synthetic transports. A representative Windows test scans two public files of
9,317,568 bytes each and keeps the default enrollment lease. This is offline
evidence, not a MAPIT or AWS acceptance receipt.

The pinned SDK CI job runs the platform-independent enrollment/readback tests.
The existing Windows Python 3.13 job installs that same pinned SDK and requires
the native prerequisites, so its full suite also exercises the native complete
operator composition. Native Windows tests are explicitly skipped elsewhere.

Primary API references: [SSM parameter metadata](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ParameterMetadata.html),
[DescribeParameters](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeParameters.html),
[native security descriptors](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow).
