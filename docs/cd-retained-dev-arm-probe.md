# Retained-dev synthetic ARM candidate probe

Status: the fixed synthetic package passed all sixteen checks in the pinned
official ARM container on 2026-10-06. The 28-wheel ZIP contained 951 entries
and was 9,251,174 bytes. Network was disabled, memory was limited to 256 MiB,
and exact owned-container cleanup passed. This is local runtime evidence, not
AWS, CloudFormation, S3, IAM, Cognito, MAPIT, or deployment acceptance.

`scripts/probe_aws_retained_dev_runtime_arm.py` is separate from the
production ARM probe and uses only `build_aws_retained_dev_archive` with the
fixed synthetic Cognito pool/client/owner and bounded execution window. It
reuses pure wheel inventory/ZIP validation and the existing Docker lifecycle
helpers; it does not import or parameterize the production builder.

The local run used the pinned official Lambda Python ARM image,
`--platform linux/arm64`, `--pull=never`, `--network none`, `--memory 256m`,
and a read-only ZIP bind mount. Container cleanup remains label/name/CID
bounded to the exact probe run.

Before tool calls, the container verifies the archive digest, retained manifest
digest and exact synthetic source/API/JWKS/window bindings. It patches only
the in-container clock to the fixed synthetic window, never the host clock.
The matrix exercises initialization, exactly ten tools, all ten synthetic tool
calls, warm repeat, missing/unknown/wrong JWT cases, production-environment
isolation, missing configuration, JWKS digest mismatch, and expired-window
failure. Output is a fixed boolean matrix with no ZIP paths, tokens, payloads,
identifiers, or response bodies.

The source-composition, command-safety tests and fixed-fixture Docker execution
are accepted independently. A later operational candidate still needs a probe
of its exact source/API-bound ZIP, not inference from the fixture result.
