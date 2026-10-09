from __future__ import annotations

import copy
import hashlib
import json

import pytest

from scripts.dev_owner_enrolled_runtime import (
    OwnerEnrolledRuntimeError,
    build_owner_enrolled_dev_runtime_target,
    compare_owner_enrolled_dev_runtime_target,
)
from scripts.build_aws_dev_mapit_binding_bootstrap import OPERATOR_ROLE_NAME
from tests.test_dev_owner_enrolled_runtime import OLD_KEYS, OWNER_KEY, _inputs


def _kwargs(args):
    return {key: value for key, value in args.items() if key != "prior_template"}


def test_bootstrap_key_must_be_exactly_authorized_by_its_single_parameter_statement():
    old, bootstrap, args = _inputs()
    role = bootstrap["Resources"]["IdentityEnrollerRole"]["Properties"]
    assert role["RoleName"] == OPERATOR_ROLE_NAME

    mutations = []
    changed = copy.deepcopy(bootstrap)
    trust = changed["Resources"]["IdentityEnrollerRole"]["Properties"]["AssumeRolePolicyDocument"]
    trust["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::210987654321:user/other"
    mutations.append(changed)

    changed = copy.deepcopy(bootstrap)
    policy = changed["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    create = next(row for row in policy["Statement"] if row.get("Sid") == "ExactCreateOnlyParameters")
    create["Resource"] = [create["Resource"][0], create["Resource"][1].replace(OWNER_KEY, "tenant-" + "c" * 64)]
    mutations.append(changed)

    changed = copy.deepcopy(bootstrap)
    crypto = next(row for row in changed["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]
                  ["PolicyDocument"]["Statement"] if row.get("Sid") == "ExactSecureStringCrypto")
    crypto["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"] = ["*"]
    mutations.append(changed)

    for malformed in mutations:
        with pytest.raises(OwnerEnrolledRuntimeError, match="mapit_bootstrap_invalid"):
            build_owner_enrolled_dev_runtime_target(
                **{**args, "mapit_bootstrap_template": malformed})


def test_owner_subject_and_key_are_single_manifest_entry_and_jwks_are_not_swappable():
    old, bootstrap, args = _inputs()
    manifest = json.loads(args["manifest_raw"])
    manifest["tenants"][0]["key"] = OLD_KEYS[0]
    raw = json.dumps(manifest, separators=(",", ":")).encode()
    with pytest.raises(OwnerEnrolledRuntimeError):
        build_owner_enrolled_dev_runtime_target(**{
            **args, "manifest_raw": raw, "manifest_sha256": hashlib.sha256(raw).hexdigest()})

    # Recompute the public manifest digest while deliberately swapping the
    # supplied JWKS bytes. The parser must still enforce each separately pinned
    # invitation/MAPIT JWKS digest.
    with pytest.raises(OwnerEnrolledRuntimeError, match="owner_manifest_invalid"):
        build_owner_enrolled_dev_runtime_target(**{
            **args, "invitation_jwks": args["mapit_jwks"]})


def test_owner_profile_changes_only_runtime_auth_code_env_and_leading_key_policy():
    old, _bootstrap, args = _inputs()
    original = copy.deepcopy(old)
    target = build_owner_enrolled_dev_runtime_target(**args)
    assert old == original
    assert set(target["Resources"]) == set(old["Resources"])
    changed = {name for name in old["Resources"] if old["Resources"][name] != target["Resources"][name]}
    assert changed == {"McpHandler", "McpJwtAuthorizer", "McpHandlerRole"}
    for name in ("McpUserPool", "McpUserPoolClient", "McpTenantsTable", "McpApi", "McpPostRoute"):
        assert target["Resources"][name] == old["Resources"][name]
    condition = next(row for row in target["Resources"]["McpHandlerRole"]["Properties"]["Policies"]
                     if row["PolicyName"] == "honda-mapit-mcp-dev-retained-tenant-read")
    assert condition["PolicyDocument"]["Statement"][0]["Condition"][
        "ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [*OLD_KEYS, OWNER_KEY]
    assert target["Metadata"]["HistoricalSyntheticRecordsMigrated"] is False
    assert target["Metadata"]["HistoricalSyntheticUsersAuthenticateAfterIssuerSwitch"] is False


def test_exact_target_comparison_rejects_claims_or_policy_drift():
    old, _bootstrap, args = _inputs()
    target = build_owner_enrolled_dev_runtime_target(**args)
    for mutation in (
        lambda value: value["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]
            .update(Issuer="https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_wrong"),
        lambda value: value["Resources"]["McpHandler"]["Properties"].update(
            ReservedConcurrentExecutions=1),
        lambda value: value["Metadata"].update(HistoricalSyntheticUsersAuthenticateAfterIssuerSwitch=True),
    ):
        changed = copy.deepcopy(target)
        mutation(changed)
        with pytest.raises(OwnerEnrolledRuntimeError, match="owner_runtime_delta_invalid"):
            compare_owner_enrolled_dev_runtime_target(
                prior_template=old, target_template=changed, **_kwargs(args))
