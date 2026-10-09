from __future__ import annotations

import copy
import hashlib
import json

import pytest

from scripts.build_aws_dev_mapit_binding_bootstrap import build_dev_mapit_binding_bootstrap
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_template
from scripts.dev_owner_enrolled_runtime import (
    OwnerEnrolledRuntimeError,
    build_owner_enrolled_dev_runtime_target,
    compare_owner_enrolled_dev_runtime_target,
)
from test_dev_enrolled_manifest import _manifest


ACCOUNT = "123456789012"
API_ID = "abc123def4"
BUCKET = "honda-runtime-artifact-test-bucket"
OLD_ZIP = "1" * 64
NEW_ZIP = "9" * 64
OLD_SOURCE = "2" * 40
NEW_SOURCE = "8" * 40
OLD_JWKS = "3" * 64
OLD_MANIFEST = "4" * 64
START = 1_900_000_000
END = START + 300
CALLBACK = "http://localhost:39031/callback"
OLD_KEYS = ("tenant-" + "6" * 64, "tenant-" + "7" * 64)
OLD_SUBJECTS = (
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
)
OWNER_KEY = "tenant-" + "a" * 64
OWNER_SUBJECT = "00000000-0000-4000-8000-0000000000aa"
OWNER_POOL = "eu-west-1_Owner12345"
OWNER_CLIENT = "OwnerClient123456789"


def _inputs():
    old = build_retained_dev_multiuser_template(
        api_id=API_ID, bucket=BUCKET, zip_sha256=OLD_ZIP,
        source_sha256=OLD_SOURCE, jwks_sha256=OLD_JWKS,
        manifest_sha256=OLD_MANIFEST, account_id=ACCOUNT,
        execution_start_epoch=START, execution_end_epoch=END,
        callback_url=CALLBACK, subjects=OLD_SUBJECTS, tenant_keys=OLD_KEYS,
    )
    bootstrap = build_dev_mapit_binding_bootstrap(
        account_id=ACCOUNT,
        operator_user_arn=f"arn:aws:iam::{ACCOUNT}:user/dev-operator",
        tenant_keys=(OWNER_KEY,), excluded_tenant_keys=OLD_KEYS,
        ssm_key_arn=f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
    )
    manifest, invitation, mapit = _manifest()
    manifest["api_id"] = API_ID
    manifest["user_pool_id"] = OWNER_POOL
    manifest["client_id"] = OWNER_CLIENT
    manifest["source_sha"] = NEW_SOURCE
    manifest["tenants"] = [{"key": OWNER_KEY, "subject": OWNER_SUBJECT}]
    raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    args = {
        "prior_template": old,
        "mapit_bootstrap_template": bootstrap,
        "manifest_raw": raw,
        "invitation_jwks": invitation,
        "mapit_jwks": mapit,
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "account_id": ACCOUNT,
        "source_sha": NEW_SOURCE,
        "zip_sha256": NEW_ZIP,
        "execution_start_epoch": START + 20,
        "execution_end_epoch": START + 320,
    }
    return old, bootstrap, args


def _target(**overrides):
    old, _bootstrap, args = _inputs()
    args.update(overrides)
    return build_owner_enrolled_dev_runtime_target(**args)


def test_exact_owner_profile_keeps_app_closed_and_uses_bootstrap_key():
    old, _bootstrap, args = _inputs()
    target = build_owner_enrolled_dev_runtime_target(**args)
    flags = compare_owner_enrolled_dev_runtime_target(
        prior_template=old, target_template=target,
        **{key: value for key, value in args.items() if key != "prior_template"},
    )
    assert all(flags.values())
    assert set(target["Resources"]) == set(old["Resources"])
    assert {name for name in old["Resources"] if old["Resources"][name] != target["Resources"][name]} == {
        "McpHandler", "McpJwtAuthorizer", "McpHandlerRole",
    }
    assert target["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert target["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0

    target_resources = target["Resources"]
    old_resources = old["Resources"]
    assert target_resources["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"] == (
        f"https://cognito-idp.eu-west-1.amazonaws.com/{OWNER_POOL}"
    )
    assert target_resources["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Audience"] == (
        old_resources["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Audience"]
    )
    assert target_resources["McpPostRoute"]["Properties"]["AuthorizationScopes"] == (
        old_resources["McpPostRoute"]["Properties"]["AuthorizationScopes"]
    )
    role_policies = target_resources["McpHandlerRole"]["Properties"]["Policies"]
    tenant_policy = next(policy for policy in role_policies
                         if policy["PolicyName"] == "honda-mapit-mcp-dev-retained-tenant-read")
    condition = tenant_policy["PolicyDocument"]["Statement"][0]["Condition"]
    assert condition == {"ForAllValues:StringEquals": {
        "dynamodb:LeadingKeys": [*OLD_KEYS, OWNER_KEY],
    }}
    assert target_resources["McpTenantsTable"] == old_resources["McpTenantsTable"]
    assert target_resources["McpUserPool"] == old_resources["McpUserPool"]
    assert target_resources["McpUserPoolClient"] == old_resources["McpUserPoolClient"]
    assert target_resources["McpHandler"]["Properties"]["Code"] == {
        "S3Bucket": BUCKET, "S3Key": f"runtime/{NEW_ZIP}.zip",
    }
    assert target_resources["McpHandler"]["Properties"]["Handler"] == (
        "mapit.aws_dev_enrolled_entrypoint.handler"
    )
    env = target_resources["McpHandler"]["Properties"]["Environment"]["Variables"]
    assert env["MAPIT_COGNITO_USER_POOL_ID"] == OWNER_POOL
    assert env["MAPIT_COGNITO_CLIENT_ID"] == OWNER_CLIENT
    assert env["MAPIT_DEV_ENROLLED_MODE"] == "mapit-enrolled"
    assert env["MAPIT_OBSERVED_API_ID"] == {"Ref": "ObservedApiId"}
    assert target["Parameters"]["ObservedApiId"]["Default"] == API_ID
    assert target["Metadata"]["NotDeployReady"] is True
    assert target["Metadata"]["HistoricalSyntheticRecordsMigrated"] is False
    assert target["Metadata"]["HistoricalSyntheticUsersAuthenticateAfterIssuerSwitch"] is False


def test_owner_target_cannot_be_bound_to_a_different_account_than_prior_stack():
    old, _bootstrap, args = _inputs()
    with pytest.raises(OwnerEnrolledRuntimeError, match="owner_account_binding_invalid"):
        build_owner_enrolled_dev_runtime_target(**{**args, "account_id": "210987654321"})


@pytest.mark.parametrize("field,value", [
    ("api_id", "zzzzzzzzzz"),
    ("source_sha", "7" * 40),
    ("client_id", "bad client id"),
    ("user_pool_id", "us-east-1_wrong"),
    ("tenants", [{"key": OWNER_KEY, "subject": OWNER_SUBJECT},
                 {"key": "tenant-" + "b" * 64, "subject": "00000000-0000-4000-8000-0000000000ab"}]),
])
def test_manifest_mismatches_and_multiple_owner_tenants_fail_closed(field, value):
    old, _bootstrap, args = _inputs()
    manifest = json.loads(args["manifest_raw"])
    manifest[field] = value
    args["manifest_raw"] = json.dumps(manifest, separators=(",", ":")).encode()
    args["manifest_sha256"] = hashlib.sha256(args["manifest_raw"]).hexdigest()
    with pytest.raises(OwnerEnrolledRuntimeError):
        build_owner_enrolled_dev_runtime_target(**args)


def test_owner_key_must_be_the_single_exact_bootstrap_key_and_fresh_from_ab():
    old, bootstrap, args = _inputs()
    changed = copy.deepcopy(bootstrap)
    # Keep it structurally plausible but alter the exact authorized SSM path.
    policy = changed["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    paths = next(row for row in policy["Statement"] if row.get("Sid") == "ExactCreateOnlyParameters")["Resource"]
    paths[1] = paths[1].replace(OWNER_KEY, "tenant-" + "c" * 64)
    with pytest.raises(OwnerEnrolledRuntimeError, match="mapit_bootstrap_invalid"):
        build_owner_enrolled_dev_runtime_target(**{**args, "mapit_bootstrap_template": changed})

    manifest = json.loads(args["manifest_raw"])
    manifest["tenants"][0]["key"] = OLD_KEYS[0]
    args["manifest_raw"] = json.dumps(manifest, separators=(",", ":")).encode()
    args["manifest_sha256"] = hashlib.sha256(args["manifest_raw"]).hexdigest()
    with pytest.raises(OwnerEnrolledRuntimeError, match="owner_manifest_invalid|owner_manifest_binding_invalid"):
        build_owner_enrolled_dev_runtime_target(**args)


def test_prior_template_must_be_exact_rebuilt_closed_nineteen_resource_template():
    old, bootstrap, args = _inputs()
    altered = copy.deepcopy(old)
    altered["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = False
    with pytest.raises(OwnerEnrolledRuntimeError, match="prior_template_invalid"):
        build_owner_enrolled_dev_runtime_target(**{**args, "prior_template": altered})

    altered = copy.deepcopy(old)
    altered["Metadata"]["ManifestContract"]["schema"] = True
    with pytest.raises(OwnerEnrolledRuntimeError, match="prior_template_invalid"):
        build_owner_enrolled_dev_runtime_target(**{**args, "prior_template": altered})

    altered = copy.deepcopy(old)
    altered["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] = 1
    with pytest.raises(OwnerEnrolledRuntimeError, match="prior_template_invalid"):
        build_owner_enrolled_dev_runtime_target(**{**args, "prior_template": altered})


def test_target_comparator_rejects_any_unapproved_change():
    old, _bootstrap, args = _inputs()
    target = build_owner_enrolled_dev_runtime_target(**args)
    altered = copy.deepcopy(target)
    altered["Resources"]["McpPostRoute"]["Properties"]["AuthorizationScopes"] = []
    with pytest.raises(OwnerEnrolledRuntimeError, match="owner_runtime_delta_invalid"):
        compare_owner_enrolled_dev_runtime_target(
            prior_template=old, target_template=altered,
            **{key: value for key, value in args.items() if key != "prior_template"},
        )


@pytest.mark.parametrize("start,end", [(0, 300), (START, START), (START, START + 301), (True, START + 300)])
def test_runtime_window_is_bounded_and_exact_integer(start, end):
    old, _bootstrap, args = _inputs()
    args["execution_start_epoch"] = start
    args["execution_end_epoch"] = end
    with pytest.raises(OwnerEnrolledRuntimeError, match="owner_runtime_inputs_invalid"):
        build_owner_enrolled_dev_runtime_target(**args)
