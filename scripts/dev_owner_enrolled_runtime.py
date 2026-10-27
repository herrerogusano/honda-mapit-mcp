"""Pure, opt-in profile for moving the retained DEV runtime to owner OAuth.

This module constructs and compares a closed CloudFormation target. It does
not deploy it, create an invitation, activate a tenant, or prove that a human
login or MAPIT session succeeded. The one owner tenant key must already be the
exact key authorized by the separate MAPIT namespace bootstrap.

The API has one JWT issuer. Switching it to the permanent owner pool therefore
does not preserve authentication for the historical synthetic A/B pool. Their
records, keys, pool, and journals are left untouched; they are not migrated
and must not be represented as still authenticating through this target.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from scripts.build_aws_dev_mapit_binding_bootstrap import (
    CONFIG_PARAMETER,
    OPERATOR_ROLE_NAME,
    build_dev_mapit_binding_bootstrap,
)
from scripts.build_aws_retained_dev_multiuser import (
    EXPECTED_RESOURCES,
    REGION,
    TABLE_NAME as AUTHORIZATION_TABLE_NAME,
    build_retained_dev_multiuser_template,
)

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API_ID = re.compile(r"[a-z0-9]{10}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_POOL_ID = re.compile(r"eu-west-1_[A-Za-z0-9]{9,45}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9]{1,128}\Z")
_SUBJECT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")


class OwnerEnrolledRuntimeError(ValueError):
    """Closed, non-sensitive error categories for this pure profile."""


def _fail(category: str = "owner_enrolled_runtime_invalid") -> None:
    raise OwnerEnrolledRuntimeError(category)


def _required_mapping(value: Any, category: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(category)
    return value


def _rebuild_prior(prior_template: Any) -> tuple[dict[str, Any], tuple[str, str], str, str, str]:
    """Rebuild the exact accepted synthetic base from its public contract fields."""
    try:
        prior = _required_mapping(prior_template, "prior_template_invalid")
        metadata = _required_mapping(prior.get("Metadata"), "prior_template_invalid")
        contract = _required_mapping(metadata.get("ManifestContract"), "prior_template_invalid")
        resources = _required_mapping(prior.get("Resources"), "prior_template_invalid")
        if set(resources) != EXPECTED_RESOURCES:
            _fail("prior_template_invalid")
        tenants = contract.get("tenants")
        if type(tenants) is not list or len(tenants) != 2:
            _fail("prior_template_invalid")
        if any(type(row) is not dict or set(row) != {"key", "subject", "label"} for row in tenants):
            _fail("prior_template_invalid")
        tenant_keys = tuple(row["key"] for row in tenants)
        subjects = tuple(row["subject"] for row in tenants)
        if (any(type(value) is not str or _TENANT_KEY.fullmatch(value) is None for value in tenant_keys)
                or any(type(value) is not str or _SUBJECT.fullmatch(value) is None for value in subjects)
                or len(set(tenant_keys)) != 2 or len(set(subjects)) != 2):
            _fail("prior_template_invalid")

        handler = _required_mapping(resources["McpHandler"].get("Properties"), "prior_template_invalid")
        code = _required_mapping(handler.get("Code"), "prior_template_invalid")
        bucket = code.get("S3Bucket")
        object_key = code.get("S3Key")
        if (type(bucket) is not str or _BUCKET.fullmatch(bucket) is None or ".." in bucket
                or type(object_key) is not str
                or re.fullmatch(r"runtime/([0-9a-f]{64})\.zip", object_key) is None):
            _fail("prior_template_invalid")
        zip_sha = re.fullmatch(r"runtime/([0-9a-f]{64})\.zip", object_key).group(1)

        parameters = _required_mapping(prior.get("Parameters"), "prior_template_invalid")
        api_parameter = _required_mapping(parameters.get("ObservedApiId"), "prior_template_invalid")
        callback_parameter = _required_mapping(parameters.get("OAuthCallbackURL"), "prior_template_invalid")
        api_id = api_parameter.get("Default")
        callback_url = callback_parameter.get("Default")

        if (type(contract.get("schema")) is not int or contract.get("schema") != 1
                or contract.get("builder") != "build_retained_dev_multiuser_archive"
                or contract.get("environment") != "dev"
                or contract.get("synthetic") is not True
                or contract.get("api_id") != api_id
                or type(api_id) is not str or _API_ID.fullmatch(api_id) is None
                or type(callback_url) is not str
                or metadata.get("SourceSha256") != contract.get("source_sha")
                or metadata.get("JwksSha256") != contract.get("jwks_sha256")
                or contract.get("table_arn") != (
                    f"arn:aws:dynamodb:{REGION}:{metadata.get('ExpectedAccountId')}:table/{AUTHORIZATION_TABLE_NAME}"
                )):
            _fail("prior_template_invalid")

        account_id = metadata.get("ExpectedAccountId")
        source_sha = metadata.get("SourceSha256")
        jwks_sha = metadata.get("JwksSha256")
        manifest_sha = metadata.get("ManifestSha256")
        start = metadata.get("ExecutionStartEpoch")
        end = metadata.get("ExecutionEndEpoch")
        if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
                or type(source_sha) is not str or _GIT_SHA.fullmatch(source_sha) is None
                or type(jwks_sha) is not str or _SHA256.fullmatch(jwks_sha) is None
                or type(manifest_sha) is not str or _SHA256.fullmatch(manifest_sha) is None
                or type(start) is not int or type(end) is not int):
            _fail("prior_template_invalid")

        rebuilt = build_retained_dev_multiuser_template(
            api_id=api_id,
            bucket=bucket,
            zip_sha256=zip_sha,
            source_sha256=source_sha,
            jwks_sha256=jwks_sha,
            manifest_sha256=manifest_sha,
            account_id=account_id,
            execution_start_epoch=start,
            execution_end_epoch=end,
            callback_url=callback_url,
            subjects=subjects,
            tenant_keys=tenant_keys,
        )
        if prior != rebuilt:
            _fail("prior_template_invalid")
        return rebuilt, tenant_keys, bucket, api_id, account_id
    except OwnerEnrolledRuntimeError:
        raise
    except Exception:
        _fail("prior_template_invalid")


def _bootstrap_owner_key(bootstrap_template: Any, *, account_id: str,
                         old_tenant_keys: tuple[str, str]) -> str:
    """Validate the fixed MAPIT bootstrap by exact factory reconstruction."""
    try:
        template = _required_mapping(bootstrap_template, "mapit_bootstrap_invalid")
        resources = _required_mapping(template.get("Resources"), "mapit_bootstrap_invalid")
        if set(resources) != {"MapitIdentityBindings", "IdentityEnrollerBoundary",
                              "IdentityEnrollerRole", "RuntimeIdentityBindingPolicy"}:
            _fail("mapit_bootstrap_invalid")
        role = _required_mapping(resources["IdentityEnrollerRole"].get("Properties"), "mapit_bootstrap_invalid")
        if role.get("RoleName") != OPERATOR_ROLE_NAME:
            _fail("mapit_bootstrap_invalid")
        trust = _required_mapping(role.get("AssumeRolePolicyDocument"), "mapit_bootstrap_invalid")
        trust_rows = trust.get("Statement")
        if (type(trust_rows) is not list or len(trust_rows) != 1
                or type(trust_rows[0]) is not dict
                or trust_rows[0].get("Effect") != "Allow"
                or trust_rows[0].get("Action") != "sts:AssumeRole"):
            _fail("mapit_bootstrap_invalid")
        operator_arn = _required_mapping(trust_rows[0].get("Principal"), "mapit_bootstrap_invalid").get("AWS")
        policies = role.get("Policies")
        if type(policies) is not list or len(policies) != 1:
            _fail("mapit_bootstrap_invalid")
        policy = _required_mapping(policies[0], "mapit_bootstrap_invalid")
        statements = _required_mapping(policy.get("PolicyDocument"), "mapit_bootstrap_invalid").get("Statement")
        if type(statements) is not list or len(statements) != 3:
            _fail("mapit_bootstrap_invalid")
        param_statement = next((row for row in statements if type(row) is dict
                                and row.get("Sid") == "ExactCreateOnlyParameters"), None)
        crypto_statement = next((row for row in statements if type(row) is dict
                                and row.get("Sid") == "ExactSecureStringCrypto"), None)
        if param_statement is None or crypto_statement is None:
            _fail("mapit_bootstrap_invalid")
        config_arn = f"arn:aws:ssm:{REGION}:{account_id}:parameter{CONFIG_PARAMETER}"
        parameter_resources = param_statement.get("Resource")
        if type(parameter_resources) is not list or len(parameter_resources) != 2 or config_arn not in parameter_resources:
            _fail("mapit_bootstrap_invalid")
        key_resources = [value for value in parameter_resources if value != config_arn]
        key_pattern = re.compile(
            rf"arn:aws:ssm:{REGION}:{account_id}:parameter/honda-mapit-mcp/dev/tenants/(tenant-[0-9a-f]{{64}})/mapit-refresh-token\Z"
        )
        match = key_pattern.fullmatch(key_resources[0]) if len(key_resources) == 1 and type(key_resources[0]) is str else None
        if match is None:
            _fail("mapit_bootstrap_invalid")
        tenant_key = match.group(1)
        kms_arn = crypto_statement.get("Resource")
        if (type(kms_arn) is not str
                or crypto_statement.get("Condition", {}).get("StringEquals", {}).get(
                    "kms:EncryptionContext:PARAMETER_ARN") != parameter_resources):
            _fail("mapit_bootstrap_invalid")
        rebuilt = build_dev_mapit_binding_bootstrap(
            account_id=account_id,
            operator_user_arn=operator_arn,
            tenant_keys=(tenant_key,),
            excluded_tenant_keys=old_tenant_keys,
            ssm_key_arn=kms_arn,
        )
        if template != rebuilt or tenant_key in old_tenant_keys:
            _fail("mapit_bootstrap_invalid")
        return tenant_key
    except OwnerEnrolledRuntimeError:
        raise
    except Exception:
        _fail("mapit_bootstrap_invalid")


def _parse_manifest(*, manifest_raw: bytes, invitation_jwks: bytes, mapit_jwks: bytes,
                    manifest_sha256: str, account_id: str):
    try:
        return parse_enrolled_dev_manifest(manifest_raw, invitation_jwks, mapit_jwks,
            expected_digest=manifest_sha256, account_id=account_id)
    except Exception:
        _fail("owner_manifest_invalid")


def build_owner_enrolled_dev_runtime_target(
    *,
    prior_template: dict[str, Any],
    mapit_bootstrap_template: dict[str, Any],
    manifest_raw: bytes,
    invitation_jwks: bytes,
    mapit_jwks: bytes,
    manifest_sha256: str,
    account_id: str,
    source_sha: str,
    zip_sha256: str,
    execution_start_epoch: int,
    execution_end_epoch: int,
) -> dict[str, Any]:
    """Rebuild the exact closed owner-enrolled DEV target from pinned inputs.

    The artifact is content-addressed in the existing runtime bucket. The
    authorization-table read is extended by precisely the key already present
    in the real-MAPIT bootstrap; no key, row, or identity is generated here.
    """
    if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
            or type(source_sha) is not str or _GIT_SHA.fullmatch(source_sha) is None
            or type(zip_sha256) is not str or _SHA256.fullmatch(zip_sha256) is None
            or type(execution_start_epoch) is not int or type(execution_end_epoch) is not int
            or execution_start_epoch <= 0 or not 0 < execution_end_epoch - execution_start_epoch <= 300):
        _fail("owner_runtime_inputs_invalid")
    prior, old_keys, bucket, api_id, prior_account_id = _rebuild_prior(prior_template)
    if prior_account_id != account_id:
        _fail("owner_account_binding_invalid")
    owner_key = _bootstrap_owner_key(mapit_bootstrap_template, account_id=account_id,
                                     old_tenant_keys=old_keys)
    manifest = _parse_manifest(manifest_raw=manifest_raw, invitation_jwks=invitation_jwks,
        mapit_jwks=mapit_jwks, manifest_sha256=manifest_sha256, account_id=account_id)
    if len(manifest.policies) != 1:
        _fail("owner_manifest_tenant_count_invalid")
    policy = next(iter(manifest.policies.values()))
    if (set(manifest.policies) != {owner_key}
            or policy.api_id != api_id
            or type(policy.user_pool_id) is not str or _POOL_ID.fullmatch(policy.user_pool_id) is None
            or type(policy.client_id) is not str or _CLIENT_ID.fullmatch(policy.client_id) is None
            or type(manifest.source_sha) is not str or _GIT_SHA.fullmatch(manifest.source_sha) is None
            or manifest.source_sha != source_sha):
        _fail("owner_manifest_binding_invalid")

    target = copy.deepcopy(prior)
    resources = target["Resources"]
    handler = resources["McpHandler"]["Properties"]
    handler["Code"] = {"S3Bucket": bucket, "S3Key": f"runtime/{zip_sha256}.zip"}
    handler["Handler"] = "mapit.aws_dev_enrolled_entrypoint.handler"
    handler["Environment"] = {"Variables": {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_DEV_ENROLLED_MODE": "mapit-enrolled",
        "MAPIT_DEV_ENROLLED_MANIFEST_SHA256": manifest_sha256,
        "MAPIT_DEV_EXPECTED_ACCOUNT_ID": account_id,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(execution_start_epoch),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(execution_end_epoch),
        "MAPIT_SOURCE_SHA256": manifest.source_sha,
        "MAPIT_COGNITO_JWKS_SHA256": hashlib.sha256(invitation_jwks).hexdigest(),
        "MAPIT_IDENTITY_JWKS_SHA256": hashlib.sha256(mapit_jwks).hexdigest(),
        "MAPIT_OBSERVED_API_ID": {"Ref": "ObservedApiId"},
        "MAPIT_COGNITO_USER_POOL_ID": policy.user_pool_id,
        "MAPIT_COGNITO_CLIENT_ID": policy.client_id,
    }}

    authorizer = resources["McpJwtAuthorizer"]["Properties"]
    if authorizer.get("AuthorizerType") != "JWT":
        _fail("prior_template_invalid")
    authorizer["JwtConfiguration"]["Issuer"] = (
        f"https://cognito-idp.{REGION}.amazonaws.com/{policy.user_pool_id}"
    )

    role_policies = resources["McpHandlerRole"]["Properties"].get("Policies")
    if type(role_policies) is not list:
        _fail("prior_template_invalid")
    tenant_policy = next((item for item in role_policies if type(item) is dict
                          and item.get("PolicyName") == "honda-mapit-mcp-dev-retained-tenant-read"), None)
    if tenant_policy is None:
        _fail("prior_template_invalid")
    statement = tenant_policy.get("PolicyDocument", {}).get("Statement")
    if (type(statement) is not list or len(statement) != 1
            or statement[0].get("Condition") != {
                "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(old_keys)}
            }):
        _fail("prior_template_invalid")
    statement[0]["Condition"] = {
        "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": [*old_keys, owner_key]}
    }

    target_metadata = target["Metadata"]
    old_subject_digests = target_metadata.pop("ObservedSubjectDigests", [])
    old_key_digests = target_metadata.pop("ObservedTenantKeyDigests", [])
    target_metadata.update({
        "Readiness": "RETAINED_DEV_OWNER_ENROLLED_NOT_DEPLOY_READY",
        "Purpose": "owner-pool enrolled runtime profile; no guest enrollment or login claim",
        "NotDeployReady": True,
        "SourceSha256": manifest.source_sha,
        "ManifestSha256": manifest_sha256,
        "ExecutionStartEpoch": execution_start_epoch,
        "ExecutionEndEpoch": execution_end_epoch,
        "HistoricalSyntheticSubjectDigests": old_subject_digests,
        "HistoricalSyntheticTenantKeyDigests": old_key_digests,
        "OwnerEnrolledManifestSha256": manifest_sha256,
        "OwnerEnrolledSourceSha256": manifest.source_sha,
        "OwnerEnrolledInvitationJwksSha256": hashlib.sha256(invitation_jwks).hexdigest(),
        "OwnerEnrolledMapitJwksSha256": hashlib.sha256(mapit_jwks).hexdigest(),
        "OwnerEnrolledTenantCount": 1,
        "HistoricalSyntheticRecordsMigrated": False,
        "HistoricalSyntheticUsersAuthenticateAfterIssuerSwitch": False,
        "APIEndpointRemainsDisabled": True,
        "LambdaReservedConcurrencyRemainsZero": True,
    })
    target_metadata.pop("ManifestContract", None)
    target_metadata.pop("JwksSha256", None)
    target_metadata["PendingGates"] = [
        "fresh source and protected-environment checks",
        "exact owner OAuth, MAPIT bootstrap, manifest and runtime readbacks",
        "separately reviewed owner invitation and tenant activation",
        "bounded owner-pool HTTP acceptance and mandatory closed-state verification",
    ]
    return target


def compare_owner_enrolled_dev_runtime_target(
    *, prior_template: dict[str, Any], target_template: dict[str, Any], **target_inputs: Any,
) -> dict[str, bool]:
    """Return pure template-diff flags; reject any unapproved template delta.

    These flags describe generated template content only. They are not AWS
    readbacks and do not establish that any database rows or identities were
    migrated, activated, or preserved in a live account.
    """
    expected = build_owner_enrolled_dev_runtime_target(
        prior_template=prior_template, **target_inputs,
    )
    if type(target_template) is not dict or target_template != expected:
        _fail("owner_runtime_delta_invalid")
    _, old_keys, _, _, _ = _rebuild_prior(prior_template)
    tenant_policy = next(item for item in expected["Resources"]["McpHandlerRole"]["Properties"]["Policies"]
                         if item.get("PolicyName") == "honda-mapit-mcp-dev-retained-tenant-read")
    leading_keys = tenant_policy["PolicyDocument"]["Statement"][0]["Condition"][
        "ForAllValues:StringEquals"]["dynamodb:LeadingKeys"]
    return {
        "prior_template_reconstructed": True,
        "target_matches_exact_owner_profile": True,
        "resource_count_unchanged": len(expected.get("Resources", {})) == len(EXPECTED_RESOURCES),
        "api_endpoint_disabled": expected["Resources"]["McpApi"]["Properties"].get("DisableExecuteApiEndpoint") is True,
        "lambda_reserved_concurrency_zero": expected["Resources"]["McpHandler"]["Properties"].get("ReservedConcurrentExecutions") == 0,
        "historical_synthetic_tenant_keys_preserved": leading_keys[:2] == list(old_keys),
        "historical_synthetic_pool_resources_unchanged": (
            expected["Resources"]["McpUserPool"] == prior_template["Resources"]["McpUserPool"]
            and expected["Resources"]["McpUserPoolClient"] == prior_template["Resources"]["McpUserPoolClient"]
        ),
    }


__all__ = [
    "OwnerEnrolledRuntimeError",
    "build_owner_enrolled_dev_runtime_target",
    "compare_owner_enrolled_dev_runtime_target",
]
