"""Build the closed synthetic runtime candidate for retained dev.

This factory is deliberately separate from the older six-resource dev/OAuth
factories and from all production templates.  It starts with the accepted
five-resource retained-dev scaffold, replaces only the Lambda code reference
and handler, and adds synthetic, non-secret environment fixtures.  The API
endpoint remains disabled and Lambda reserved concurrency remains zero.

The factory performs no AWS SDK, credential, filesystem, network, or runtime
session operation.  The caller must build the ZIP independently and pass its
content digest together with the digest of the bundled public JWKS fixture.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from mapit.aws_dev_runtime import cognito_dev_policy

from scripts.build_aws_retained_dev import (
    CONDITION_NAME,
    EXPECTED_RESOURCES,
    REGION,
    STACK_NAME,
    RetainedDevTemplateError,
    build_retained_dev_template,
)

RUNTIME_HANDLER = "mapit.aws_dev_entrypoint.handler"
SYNTHETIC_USER_POOL_ID = "eu-west-1_SYNTHETICDEV"
SYNTHETIC_CLIENT_ID = "SyntheticRetainedDevClient"
SYNTHETIC_OWNER_SUBJECT = "00000000-0000-4000-8000-000000000001"
SYNTHETIC_EXECUTION_START = 1_893_456_000
SYNTHETIC_EXECUTION_END = 1_893_456_300
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,64}$")
_OWNER_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_BUCKET_PREFIX = "honda-mapit-mcp-dev-retained"


class RetainedDevRuntimeTemplateError(ValueError):
    """Stable local error without echoing supplied identifiers or paths."""


def retained_dev_artifact_bucket(account_id: str) -> str:
    """Return the deterministic private artifact bucket name for one account."""
    if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None:
        raise RetainedDevRuntimeTemplateError("account_invalid")
    return f"{_BUCKET_PREFIX}-{account_id}-{REGION}"


def _validate_inputs(
    account_id: str,
    api_id: str,
    zip_sha256: str,
    jwks_sha256: str,
    execution_start_epoch: int,
    execution_end_epoch: int,
) -> None:
    if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None:
        raise RetainedDevRuntimeTemplateError("account_invalid")
    if type(api_id) is not str or _API_ID.fullmatch(api_id) is None:
        raise RetainedDevRuntimeTemplateError("api_id_invalid")
    if type(zip_sha256) is not str or _SHA256.fullmatch(zip_sha256) is None:
        raise RetainedDevRuntimeTemplateError("runtime_hash_invalid")
    if type(jwks_sha256) is not str or _SHA256.fullmatch(jwks_sha256) is None:
        raise RetainedDevRuntimeTemplateError("jwks_hash_invalid")
    if (
        type(execution_start_epoch) is not int
        or isinstance(execution_start_epoch, bool)
        or type(execution_end_epoch) is not int
        or isinstance(execution_end_epoch, bool)
        or execution_start_epoch <= 0
        or execution_end_epoch <= execution_start_epoch
        or execution_end_epoch - execution_start_epoch > 300
    ):
        raise RetainedDevRuntimeTemplateError("execution_window_invalid")
    if _POOL_ID.fullmatch(SYNTHETIC_USER_POOL_ID) is None or _OWNER_UUID.fullmatch(SYNTHETIC_OWNER_SUBJECT) is None:
        raise RetainedDevRuntimeTemplateError("synthetic_fixture_invalid")
    try:
        cognito_dev_policy(
            user_pool_id=SYNTHETIC_USER_POOL_ID, api_id=api_id,
            client_id=SYNTHETIC_CLIENT_ID, owner_subject=SYNTHETIC_OWNER_SUBJECT,
        )
    except Exception:
        raise RetainedDevRuntimeTemplateError("synthetic_fixture_invalid") from None


def _validate_base(template: dict[str, Any]) -> None:
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != set(EXPECTED_RESOURCES):
        raise RetainedDevRuntimeTemplateError("resource_set_invalid")
    conditions = template.get("Conditions")
    expected_condition = {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        ]
    }
    if conditions != {CONDITION_NAME: expected_condition}:
        raise RetainedDevRuntimeTemplateError("condition_invalid")
    for logical_id in EXPECTED_RESOURCES:
        resource = resources.get(logical_id)
        if not isinstance(resource, dict) or resource.get("Condition") != CONDITION_NAME:
            raise RetainedDevRuntimeTemplateError("resource_condition_invalid")


def _validate_runtime_template(
    template: dict[str, Any], *, bucket: str, zip_sha256: str, jwks_sha256: str,
    api_id: str, start: int, end: int,
) -> None:
    _validate_base(template)
    resources = template["Resources"]
    api = resources["McpApi"]
    api_properties = api.get("Properties")
    if (
        not isinstance(api_properties, dict)
        or api_properties.get("DisableExecuteApiEndpoint") is not True
        or api_properties.get("ProtocolType") != "HTTP"
    ):
        raise RetainedDevRuntimeTemplateError("api_not_closed")
    stage = resources["McpApiStage"].get("Properties")
    if (
        not isinstance(stage, dict)
        or stage.get("ApiId") != {"Ref": "McpApi"}
        or stage.get("StageName") != "$default"
        or stage.get("AutoDeploy") is not True
        or stage.get("DefaultRouteSettings")
        != {"DetailedMetricsEnabled": False, "ThrottlingBurstLimit": 1, "ThrottlingRateLimit": 1}
    ):
        raise RetainedDevRuntimeTemplateError("stage_invalid")
    handler = resources["McpHandler"].get("Properties")
    if not isinstance(handler, dict):
        raise RetainedDevRuntimeTemplateError("handler_invalid")
    expected_environment = {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_COGNITO_USER_POOL_ID": SYNTHETIC_USER_POOL_ID,
        "MAPIT_API_ID": api_id,
        "MAPIT_COGNITO_CLIENT_ID": SYNTHETIC_CLIENT_ID,
        "MAPIT_OWNER_SUBJECT": SYNTHETIC_OWNER_SUBJECT,
        "MAPIT_COGNITO_JWKS_SHA256": jwks_sha256,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(start),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(end),
    }
    environment = handler.get("Environment")
    variables = environment.get("Variables") if isinstance(environment, dict) else None
    if not isinstance(variables, dict):
        raise RetainedDevRuntimeTemplateError("environment_invalid")
    if variables != expected_environment or handler.get("Code") != {
        "S3Bucket": bucket,
        "S3Key": f"runtime/{zip_sha256}.zip",
    }:
        raise RetainedDevRuntimeTemplateError("runtime_binding_invalid")
    if (
        handler.get("Handler") != RUNTIME_HANDLER
        or handler.get("ReservedConcurrentExecutions") != 0
        or handler.get("Architectures") != ["arm64"]
        or handler.get("Runtime") != "python3.13"
        or handler.get("Role") != {"Fn::GetAtt": ["McpHandlerRole", "Arn"]}
        or handler.get("MemorySize") != 256
        or handler.get("Timeout") != 20
    ):
        raise RetainedDevRuntimeTemplateError("handler_not_closed")
    role = resources["McpHandlerRole"].get("Properties")
    if not isinstance(role, dict) or len(role.get("Policies", [])) != 1:
        raise RetainedDevRuntimeTemplateError("role_invalid")
    statements = role["Policies"][0].get("PolicyDocument", {}).get("Statement")
    if statements != [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-dev-retained-handler:*"},
    }]:
        raise RetainedDevRuntimeTemplateError("role_scope_invalid")


def build_retained_dev_runtime_template(
    account_id: str,
    api_id: str,
    zip_sha256: str,
    jwks_sha256: str,
    *,
    execution_start_epoch: int = SYNTHETIC_EXECUTION_START,
    execution_end_epoch: int = SYNTHETIC_EXECUTION_END,
) -> dict[str, Any]:
    """Return a closed five-resource synthetic runtime candidate."""
    _validate_inputs(account_id, api_id, zip_sha256, jwks_sha256, execution_start_epoch, execution_end_epoch)
    bucket = retained_dev_artifact_bucket(account_id)
    try:
        template = copy.deepcopy(build_retained_dev_template())
    except RetainedDevTemplateError:
        raise
    except Exception:
        raise RetainedDevRuntimeTemplateError("base_template_invalid") from None
    resources = template["Resources"]
    handler = resources["McpHandler"]["Properties"]
    handler["Handler"] = RUNTIME_HANDLER
    handler["Code"] = {"S3Bucket": bucket, "S3Key": f"runtime/{zip_sha256}.zip"}
    handler["Environment"] = {"Variables": {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_COGNITO_USER_POOL_ID": SYNTHETIC_USER_POOL_ID,
        "MAPIT_API_ID": api_id,
        "MAPIT_COGNITO_CLIENT_ID": SYNTHETIC_CLIENT_ID,
        "MAPIT_OWNER_SUBJECT": SYNTHETIC_OWNER_SUBJECT,
        "MAPIT_COGNITO_JWKS_SHA256": jwks_sha256,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(execution_start_epoch),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(execution_end_epoch),
    }}
    metadata = template.setdefault("Metadata", {})
    metadata.update({
        "Readiness": "RETAINED_DEV_SYNTHETIC_RUNTIME_NOT_ACTIVE",
        "RuntimeImplementation": True,
        "RuntimeActivation": False,
        "ApiEndpointClosed": True,
        "ReservedConcurrencyZero": True,
        "SyntheticEnvironmentFixtures": True,
        "NoSessionSecretsOAuthOrUsers": True,
        "ArtifactKey": f"runtime/{zip_sha256}.zip",
        "RequiresSeparateActivationAcceptance": True,
    })
    _validate_runtime_template(
        template,
        bucket=bucket,
        zip_sha256=zip_sha256,
        jwks_sha256=jwks_sha256,
        api_id=api_id,
        start=execution_start_epoch,
        end=execution_end_epoch,
    )
    return template


__all__ = [
    "REGION",
    "RUNTIME_HANDLER",
    "RetainedDevRuntimeTemplateError",
    "STACK_NAME",
    "SYNTHETIC_CLIENT_ID",
    "SYNTHETIC_EXECUTION_END",
    "SYNTHETIC_EXECUTION_START",
    "SYNTHETIC_OWNER_SUBJECT",
    "SYNTHETIC_USER_POOL_ID",
    "build_retained_dev_runtime_template",
    "retained_dev_artifact_bucket",
]
