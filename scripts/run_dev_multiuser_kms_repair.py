"""One-shot, injected KMS-key repair for retained DEV role permissions.

The previous runtime update and its consumed journal are read-only evidence.
This module constructs a new recurrent IAM template with the existing AWS
managed Lambda key, then delegates one fresh role-stack update to the accepted
closed CloudFormation updater. It never changes the app stack or opens runtime.
"""
from __future__ import annotations

from collections.abc import Mapping
import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.dev_multiuser_closed_update import ClosedDevUpdate, REGION, _digest as _closed_digest
from scripts.dev_multiuser_readback import verify_role_pair

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_STACK_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_APP_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/honda-mapit-mcp-dev-retained/{_STACK_UUID}\Z")
_ROLE_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/honda-mapit-mcp-dev-retained-cd-delivery/{_STACK_UUID}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"dev-multiuser-[0-9a-f]{32}\Z")
_PROXY_ENV = frozenset({"http_proxy", "https_proxy", "all_proxy", "no_proxy",
                        "aws_ca_bundle", "aws_endpoint_url", "aws_endpoint_url_s3",
                        "aws_endpoint_url_sts"})
_API_ID = re.compile(r"[a-z0-9]{10}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9]{1,128}\Z")
_KMS_ARN = re.compile(r"arn:aws:kms:eu-west-1:([0-9]{12}):key/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\Z")
_KEY_REASON = re.compile(r"arn:aws:kms:eu-west-1:[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_ROLE_BINDINGS = frozenset({
    "account_id", "provider_arn", "owner_id", "repository_id",
    "observed_dev_subject_format", "observed_dev_subject_sha256", "stack_arn",
    "artifact_stack_arn", "handler_arn", "api_arn", "shutdown_state_machine_arn",
    "artifact_bucket_arn", "execution_role_arn",
})
_APP_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role", "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function", "McpUserPool": "AWS::Cognito::UserPool",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    "McpTenantsTable": "AWS::DynamoDB::Table",
}
_METHODS = {
    "sts": {"get_caller_identity"},
    "cloudformation": {"describe_stacks", "describe_stack_resources", "get_template", "describe_stack_events", "update_stack"},
    "lambda": {"get_function_concurrency"},
    "apigatewayv2": {"get_api"},
    "kms": {"describe_key"},
    "iam": {"get_role", "list_role_policies", "get_role_policy", "list_attached_role_policies", "list_role_tags", "get_policy", "get_policy_version"},
}


class KmsRepairError(ValueError):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category if re.fullmatch(r"[a-z][a-z0-9_-]{2,63}", category) else "kms_repair_failed"


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canon(value)).hexdigest()


def _http_ok(value: Any, expected: int = 200) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == expected)


class _CallBudget:
    def __init__(self, clients: Mapping[str, Any], *, guard: Callable[[], None], limit: int = 180):
        self.calls = 0
        self.limit = limit
        self.guard = guard
        self.clients = {name: _MeteredClient(name, client, self) for name, client in clients.items()}


class _MeteredClient:
    def __init__(self, service: str, client: Any, budget: _CallBudget):
        self._service, self._client, self._budget = service, client, budget

    def __getattr__(self, name: str):
        if name not in _METHODS.get(self._service, set()):
            raise AttributeError(name)
        method = getattr(self._client, name, None)
        if not callable(method):
            raise AttributeError(name)

        def invoke(**kwargs):
            self._budget.guard()
            if self._budget.calls >= self._budget.limit:
                raise KmsRepairError("call_budget_exhausted")
            self._budget.calls += 1
            try:
                result = method(**kwargs)
            except Exception:
                self._budget.guard()
                raise
            self._budget.guard()
            return result
        return invoke


def _role_templates(bindings: Mapping[str, Any], *, pool_id: str, key_arn: str | None):
    if type(bindings) is not dict or set(bindings) != _ROLE_BINDINGS:
        raise KmsRepairError("role_bindings_invalid")
    try:
        return build_cd_retained_dev_multiuser_roles(
            **bindings, lambda_environment_key_arn=key_arn, observed_user_pool_id=pool_id,
        )
    except Exception:
        raise KmsRepairError("role_template_invalid") from None


def _extract_event_key(events: Any, *, old_token: str, app_stack_arn: str,
                       account: str) -> str:
    if type(events) is not list or not 1 <= len(events) <= 1000 or any(not isinstance(row, Mapping) for row in events):
        raise KmsRepairError("prior_event_invalid")
    failed = [row for row in events if isinstance(row, Mapping)
              and row.get("ClientRequestToken") == old_token
              and row.get("LogicalResourceId") == "McpHandler"
              and row.get("ResourceType") == "AWS::Lambda::Function"
              and row.get("StackId") == app_stack_arn
              and row.get("ResourceStatus") == "UPDATE_FAILED"]
    rollback = [row for row in events if isinstance(row, Mapping)
                and row.get("ClientRequestToken") == old_token
                and row.get("ResourceType") == "AWS::CloudFormation::Stack"
                and row.get("ResourceStatus") == "UPDATE_ROLLBACK_COMPLETE"
                and row.get("StackId") == app_stack_arn]
    if len(failed) != 1 or len(rollback) != 1:
        raise KmsRepairError("prior_event_invalid")
    reason = failed[0].get("ResourceStatusReason")
    if type(reason) is not str or not reason or len(reason) > 8192:
        raise KmsRepairError("prior_event_invalid")
    matches = _KEY_REASON.findall(reason)
    if len(matches) != 1:
        raise KmsRepairError("prior_event_invalid")
    key_arn = matches[0]
    match = _KMS_ARN.fullmatch(key_arn)
    if match is None or match.group(1) != account:
        raise KmsRepairError("prior_event_invalid")
    return key_arn


def _old_runtime_evidence(value: Any, *, account: str, caller_arn: str,
                          app_stack_arn: str, prior_setup: Mapping[str, Any],
                          new_start: int, new_token: str) -> tuple[str, str]:
    fields = {"binding", "phase"}
    if type(value) is not dict or set(value) != fields or value.get("phase") != "acknowledged":
        raise KmsRepairError("prior_journal_invalid")
    binding = value.get("binding")
    expected = {"schema", "operation", "account", "caller", "stack", "role", "source",
                "start", "end", "token", "prior", "target"}
    if type(binding) is not dict or set(binding) != expected:
        raise KmsRepairError("prior_journal_invalid")
    expected_role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-cfn-update"
    if (type(binding.get("schema")) is not int or binding["schema"] != 1
        or binding.get("operation") != "dev_multiuser_closed_update"
        or binding.get("account") != account or binding.get("caller") != caller_arn
        or binding.get("stack") != app_stack_arn or binding.get("role") != expected_role
        or type(binding.get("source")) is not str or _SHA1.fullmatch(binding["source"]) is None
        or type(binding.get("start")) is not int or isinstance(binding.get("start"), bool)
        or type(binding.get("end")) is not int or isinstance(binding.get("end"), bool)
        or binding["start"] <= 0 or binding["end"] <= binding["start"]
        or binding["end"] - binding["start"] > 7200 or binding["start"] >= new_start
        or type(binding.get("token")) is not str or _TOKEN.fullmatch(binding["token"]) is None
        or binding["token"] == new_token
        or type(binding.get("prior")) is not str or _SHA256.fullmatch(binding["prior"]) is None
        or type(binding.get("target")) is not str or _SHA256.fullmatch(binding["target"]) is None
        or binding["prior"] != _closed_digest(dict(prior_setup))):
        raise KmsRepairError("prior_journal_invalid")
    return binding["token"], binding["source"]


def _app_snapshot(clients: Mapping[str, Any], *, account: str, app_stack_arn: str,
                  app_run_id: int, role_bindings: Mapping[str, Any]) -> tuple[dict[str, Any], str, str]:
    cfn = clients["cloudformation"]
    stack_response = cfn.describe_stacks(StackName=app_stack_arn)
    stacks = stack_response.get("Stacks") if _http_ok(stack_response) else None
    if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
        raise KmsRepairError("app_stack_invalid")
    stack = stacks[0]
    required_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                     "Purpose": "retained-dev", "OperatorRunId": str(app_run_id)}
    tags = stack.get("Tags")
    if (stack.get("StackId") != app_stack_arn or stack.get("StackName") != "honda-mapit-mcp-dev-retained"
        or stack.get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
        or stack.get("EnableTerminationProtection") is not True
        or stack.get("RoleARN") != f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-cfn-update"
        or type(tags) is not list
        or not all(any(isinstance(row, Mapping) and row.get("Key") == k and row.get("Value") == v for row in tags)
                   for k, v in required_tags.items())):
        raise KmsRepairError("app_stack_invalid")
    resources_response = cfn.describe_stack_resources(StackName=app_stack_arn)
    rows = resources_response.get("StackResources") if _http_ok(resources_response) else None
    if (type(rows) is not list or len(rows) != 11
        or resources_response.get("NextToken") not in (None, "")):
        raise KmsRepairError("app_resources_invalid")
    resource_map = {}
    for row in rows:
        if (not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str
            or row["LogicalResourceId"] in resource_map or row.get("ResourceType") != _APP_TYPES.get(row["LogicalResourceId"])
            or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}
            or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
            raise KmsRepairError("app_resources_invalid")
        resource_map[row["LogicalResourceId"]] = row["PhysicalResourceId"]
    if set(resource_map) != set(_APP_TYPES):
        raise KmsRepairError("app_resources_invalid")
    api_id, pool_id = resource_map["McpApi"], resource_map["McpUserPool"]
    if (_API_ID.fullmatch(api_id) is None or _POOL.fullmatch(pool_id) is None
        or resource_map["McpApiStage"] != "$default"
        or resource_map["McpHandler"] != "honda-mapit-mcp-dev-retained-handler"
        or resource_map["McpHandlerRole"] != "honda-mapit-mcp-dev-retained-handler-role"
        or resource_map["McpHandlerLogGroup"] != "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
        or resource_map["McpUserPoolDomain"] != f"honda-mapit-mcp-dev-multiuser-{account}"
        or resource_map["McpTenantsTable"] != "honda-mapit-mcp-dev-tenants"
        or resource_map["McpResourceServer"] not in {
            f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp",
            f"{pool_id}|https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"}):
        raise KmsRepairError("app_resources_invalid")
    if (not _CLIENT.fullmatch(resource_map["McpUserPoolClient"])
        or not re.fullmatch(rf"{re.escape(pool_id)}\|[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}",
                            resource_map["McpManagedLoginBranding"])):
        raise KmsRepairError("app_resources_invalid")
    if role_bindings.get("account_id") != account or role_bindings.get("stack_arn") != app_stack_arn:
        raise KmsRepairError("binding_invalid")
    expected_api_arn = f"arn:aws:apigateway:{REGION}::/apis/{api_id}"
    if role_bindings.get("api_arn") != expected_api_arn:
        raise KmsRepairError("binding_invalid")
    template_response = cfn.get_template(StackName=app_stack_arn, TemplateStage="Original")
    template = template_response.get("TemplateBody") if _http_ok(template_response) else None
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result
    if isinstance(template, str):
        template = json.loads(template, object_pairs_hook=reject_duplicates,
                              parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")))
    elif isinstance(template, Mapping):
        template = json.loads(json.dumps(template, allow_nan=False), object_pairs_hook=reject_duplicates)
    if type(template) is not dict:
        raise KmsRepairError("app_template_invalid")
    expected_template = build_retained_dev_multiuser_setup(
        api_id=api_id, callback_url="http://localhost:39031/callback")
    if _closed_digest(template) != _closed_digest(expected_template):
        raise KmsRepairError("app_template_invalid")
    concurrency = clients["lambda"].get_function_concurrency(
        FunctionName="honda-mapit-mcp-dev-retained-handler")
    if (not _http_ok(concurrency) or type(concurrency.get("ReservedConcurrentExecutions")) is not int
        or isinstance(concurrency.get("ReservedConcurrentExecutions"), bool)
        or concurrency["ReservedConcurrentExecutions"] != 0):
        raise KmsRepairError("runtime_not_closed")
    api = clients["apigatewayv2"].get_api(ApiId=api_id)
    if not _http_ok(api) or api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True:
        raise KmsRepairError("runtime_not_closed")
    return template, api_id, pool_id


def _kms_alias(clients: Mapping[str, Any], *, account: str) -> str:
    response = clients["kms"].describe_key(KeyId="alias/aws/lambda")
    metadata = response.get("KeyMetadata") if _http_ok(response) else None
    arn = metadata.get("Arn") if isinstance(metadata, Mapping) else None
    match = _KMS_ARN.fullmatch(arn) if type(arn) is str else None
    if (match is None or match.group(1) != account
        or metadata.get("KeyManager") != "AWS" or metadata.get("KeyState") != "Enabled"
        or metadata.get("KeySpec") != "SYMMETRIC_DEFAULT" or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"
        or metadata.get("Origin") != "AWS_KMS" or metadata.get("MultiRegion") is not False
        or metadata.get("Enabled") is not True):
        raise KmsRepairError("kms_key_invalid")
    return arn


def _verify_templates(prior: Mapping[str, Any], target: Mapping[str, Any]) -> None:
    prior_resources, target_resources = prior.get("Resources"), target.get("Resources")
    expected = {"RetainedDevCdExecutorRole", "RetainedDevCdExecutorBoundary",
                "RetainedDevCdCloudFormationRole", "RetainedDevCdCloudFormationBoundary"}
    if (not isinstance(prior_resources, Mapping) or set(prior_resources) != expected
        or not isinstance(target_resources, Mapping) or set(target_resources) != expected
        or prior_resources["RetainedDevCdExecutorRole"] != target_resources["RetainedDevCdExecutorRole"]
        or prior_resources["RetainedDevCdExecutorBoundary"] != target_resources["RetainedDevCdExecutorBoundary"]):
        raise KmsRepairError("role_template_scope_invalid")
    prior_other = {key: value for key, value in prior_resources.items()
                   if key not in {"RetainedDevCdCloudFormationRole", "RetainedDevCdCloudFormationBoundary"}}
    target_other = {key: value for key, value in target_resources.items()
                    if key not in {"RetainedDevCdCloudFormationRole", "RetainedDevCdCloudFormationBoundary"}}
    prior_metadata, target_metadata = prior.get("Metadata"), target.get("Metadata")
    if (prior_other != target_other or not isinstance(prior_metadata, Mapping)
        or not isinstance(target_metadata, Mapping)):
        raise KmsRepairError("role_template_scope_invalid")
    for key in set(prior_metadata) | set(target_metadata):
        if key == "CanonicalTemplateSha256":
            continue
        if prior_metadata.get(key) != target_metadata.get(key):
            raise KmsRepairError("role_template_scope_invalid")


def run_kms_repair_step(
    clients: Mapping[str, Any], *, step: str, journal: Any, old_runtime_journal: Any,
    account_id: str, caller_arn: str, app_stack_arn: str, app_creation_run_id: int,
    roles_stack_arn: str, roles_creation_run_id: int, role_bindings: Mapping[str, Any],
    source_sha: str, run_token: str, authorized_from_epoch: int,
    authorized_until_epoch: int, clock: Callable[[], float] = time.time,
    accepted_key_sink: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Run fresh preflight/update/readback for only the four recurrent roles."""
    budget = None
    call_count = 0
    try:
        if step not in {"preflight", "request-update", "check-update"}:
            raise KmsRepairError("step_invalid")
        if (not isinstance(clients, Mapping) or set(clients) != set(_METHODS)
            or any(clients[name] is None for name in _METHODS)
            or type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "0" * 12
            or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
            or type(run_token) is not str or _TOKEN.fullmatch(run_token) is None
            or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
            or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
            or not 0 < authorized_until_epoch - authorized_from_epoch <= 3600
            or not callable(clock)):
            raise KmsRepairError("binding_invalid")
        if (type(caller_arn) is not str
            or re.fullmatch(rf"arn:aws:iam::{account_id}:user/[A-Za-z0-9+=,.@_-]{{1,128}}", caller_arn) is None):
            raise KmsRepairError("binding_invalid")
        app_match = _APP_STACK.fullmatch(app_stack_arn) if type(app_stack_arn) is str else None
        role_match = _ROLE_STACK.fullmatch(roles_stack_arn) if type(roles_stack_arn) is str else None
        if (app_match is None or role_match is None or app_match.group(1) != account_id
            or role_match.group(1) != account_id or type(app_creation_run_id) is not int
            or isinstance(app_creation_run_id, bool) or app_creation_run_id <= 0
            or type(roles_creation_run_id) is not int or isinstance(roles_creation_run_id, bool)
            or roles_creation_run_id <= 0 or role_bindings.get("stack_arn") != app_stack_arn
            or role_bindings.get("account_id") != account_id):
            raise KmsRepairError("binding_invalid")
        if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise KmsRepairError("journal_invalid")
        if type(old_runtime_journal) is not dict:
            raise KmsRepairError("prior_journal_invalid")
        if accepted_key_sink is not None and not callable(accepted_key_sink):
            raise KmsRepairError("binding_invalid")
        last_wall = None

        def guard():
            nonlocal last_wall
            now = clock()
            if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                or now < authorized_from_epoch or now >= authorized_until_epoch
                or last_wall is not None and now < last_wall):
                raise KmsRepairError("window_expired")
            last_wall = float(now)
            return last_wall

        budget = _CallBudget(clients, guard=guard)
        metered = budget.clients
        guard()
        identity = metered["sts"].get_caller_identity()
        if (not _http_ok(identity) or identity.get("Account") != account_id
            or identity.get("Arn") != caller_arn or caller_arn.endswith(":root")
            or not caller_arn.startswith(f"arn:aws:iam::{account_id}:user/")):
            raise KmsRepairError("identity_mismatch")
        prior_app, api_id, pool_id = _app_snapshot(
            metered, account=account_id, app_stack_arn=app_stack_arn,
            app_run_id=app_creation_run_id, role_bindings=role_bindings)
        if role_bindings.get("observed_user_pool_id") not in (None, pool_id):
            raise KmsRepairError("role_bindings_invalid")
        # The consumed historical journal is read without taking its mutable
        # lock-file path; it is immutable evidence, never a write target.
        old_state = old_runtime_journal if type(old_runtime_journal) is dict else None
        old_token, old_source = _old_runtime_evidence(
            old_state, account=account_id, caller_arn=caller_arn,
            app_stack_arn=app_stack_arn, prior_setup=prior_app,
            new_start=authorized_from_epoch, new_token=run_token)
        if old_source == source_sha:
            raise KmsRepairError("source_binding_invalid")
        events_response = metered["cloudformation"].describe_stack_events(StackName=app_stack_arn)
        if (not _http_ok(events_response) or events_response.get("NextToken") not in (None, "")
            or events_response.get("Marker") not in (None, "")):
            raise KmsRepairError("prior_event_invalid")
        event_key = _extract_event_key(events_response.get("StackEvents"), old_token=old_token,
                                       app_stack_arn=app_stack_arn, account=account_id)
        key_arn = _kms_alias(metered, account=account_id)
        if key_arn != event_key:
            raise KmsRepairError("kms_key_mismatch")
        prior_roles = _role_templates(role_bindings, pool_id=pool_id, key_arn=None)
        target_roles = _role_templates(role_bindings, pool_id=pool_id, key_arn=key_arn)
        _verify_templates(prior_roles, target_roles)
        if step != "check-update":
            role_check = verify_role_pair(
                {"iam": metered["iam"]}, prior_roles, account=account_id,
                roles_stack_arn=roles_stack_arn, original_creation_run_id=roles_creation_run_id)
            if role_check.get("success") is not True:
                raise KmsRepairError("role_pair_readback_failed")
        updater = ClosedDevUpdate(
            metered, journal, account=account_id, caller_arn=caller_arn,
            stack_arn=roles_stack_arn, prior_template=prior_roles,
            target_template=target_roles, service_role_arn=None, source_sha=source_sha,
            start=authorized_from_epoch, end=authorized_until_epoch, token=run_token, clock=guard)
        core_step = {"request-update": "update", "check-update": "readback"}.get(step, step)
        raw = updater.run(core_step)
        call_count = budget.calls
        if raw.get("ok") is True and (step == "preflight" or (step == "check-update" and raw.get("phase") == "accepted")):
            expected_template = target_roles if step == "check-update" else prior_roles
            final = verify_role_pair(
                {"iam": metered["iam"]}, expected_template, account=account_id,
                roles_stack_arn=roles_stack_arn, original_creation_run_id=roles_creation_run_id)
            if final.get("success") is not True:
                raise KmsRepairError("role_pair_readback_failed")
            if step == "check-update" and accepted_key_sink is not None:
                try:
                    accepted_key_sink(key_arn)
                except Exception:
                    raise KmsRepairError("accepted_bindings_write_failed") from None
        phase_category = {"ready": "preflight_verified", "acknowledged": "update_acknowledged",
                          "pending": "update_pending", "accepted": "readback_verified"}.get(raw.get("phase"), "update_outcome_unknown")
        return {"success": raw.get("ok") is True and phase_category in {"preflight_verified", "update_acknowledged", "readback_verified"},
                "category": phase_category, "calls": budget.calls}
    except KmsRepairError as exc:
        return {"success": False, "category": exc.category,
                "calls": budget.calls if budget is not None else call_count}
    except Exception:
        return {"success": False, "category": "kms_repair_failed",
                "calls": budget.calls if budget is not None else call_count}


def _build_clients() -> dict[str, Any]:
    """Create fixed one-attempt regional clients after all private/source gates."""
    if any(key.casefold() in _PROXY_ENV or key.casefold().startswith("aws_endpoint_url_")
           for key in os.environ):
        raise KmsRepairError("proxy_or_custom_endpoint_rejected")
    try:
        import logging
        import boto3
        from botocore.config import Config
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        regional = Config(region_name=REGION, connect_timeout=2, read_timeout=3,
                          retries={"mode": "standard", "total_max_attempts": 1},
                          proxies={}, signature_version="v4")
        iam_config = Config(region_name="us-east-1", connect_timeout=2, read_timeout=3,
                             retries={"mode": "standard", "total_max_attempts": 1},
                             proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        specs = {
            "sts": ("sts", REGION, f"https://sts.{REGION}.amazonaws.com", regional),
            "cloudformation": ("cloudformation", REGION, f"https://cloudformation.{REGION}.amazonaws.com", regional),
            "lambda": ("lambda", REGION, f"https://lambda.{REGION}.amazonaws.com", regional),
            "apigatewayv2": ("apigatewayv2", REGION, f"https://apigateway.{REGION}.amazonaws.com", regional),
            "kms": ("kms", REGION, f"https://kms.{REGION}.amazonaws.com", regional),
            "iam": ("iam", "us-east-1", "https://iam.amazonaws.com", iam_config),
        }
        return {key: session.client(service, region_name=region, endpoint_url=url,
                                    config=config, verify=True)
                for key, (service, region, url, config) in specs.items()}
    except KmsRepairError:
        raise
    except Exception:
        raise KmsRepairError("client_construction_failed") from None


def _load_app_binding(path: Path, *, acl_checker=None) -> dict[str, Any]:
    from scripts.run_dev_multiuser_closed_update import _load_app_binding as load
    try:
        return load(path, acl_checker=acl_checker)
    except Exception:
        raise KmsRepairError("app_binding_invalid") from None


def _write_accepted_role_bindings(path: Path, bindings: Mapping[str, Any], key_arn: str,
                                  *, acl_checker=None) -> None:
    """Create, never replace, the private fourteen-field accepted binding."""
    try:
        from scripts.run_aws_retained_dev_bootstrap import validate_private_location
        target = Path(path)
        parent = validate_private_location(target.parent, acl_checker=acl_checker)
        target = parent / target.name
        if (not target.name or target.name in {".", ".."} or target.exists()
            or target.is_symlink() or type(bindings) is not dict
            or set(bindings) != _ROLE_BINDINGS):
            raise ValueError
        match = _KMS_ARN.fullmatch(key_arn) if type(key_arn) is str else None
        if match is None or match.group(1) != bindings.get("account_id"):
            raise ValueError
        value = dict(bindings)
        value["lambda_environment_key_arn"] = key_arn
        payload = _canon(value)
        if len(payload) > 8192:
            raise ValueError
        created = False
        try:
            with target.open("xb") as stream:
                created = True
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            if created:
                try:
                    target.unlink()
                except Exception:
                    pass
            raise
    except Exception:
        raise KmsRepairError("accepted_bindings_write_failed") from None


def run_authorized_step(
    authorization_path: Path, role_bindings_path: Path, app_binding_path: Path,
    roles_binding_path: Path, old_runtime_state_dir: Path, state_dir: Path,
    step: str, *, accepted_bindings_path: Path | None = None,
    acl_checker=None, source_ci_validator=None,
    client_factory=None, journal_factory=None,
) -> dict[str, Any]:
    """Private CLI seam; callers may inject everything for offline tests."""
    try:
        if step not in {"preflight", "request-update", "check-update"}:
            raise KmsRepairError("step_invalid")
        from scripts.run_aws_retained_dev_bootstrap import (
            load_authorization, validate_private_location, validate_source_and_ci,
        )
        from scripts.run_aws_retained_dev_role_bootstrap import _load_bindings
        from scripts.run_dev_multiuser_runtime_update import CasFileJournal, _load_roles_binding
        from scripts.dev_multiuser_journal import PlainFileJournal

        resolved = [validate_private_location(Path(path), acl_checker=acl_checker) for path in (
            authorization_path, role_bindings_path, app_binding_path, roles_binding_path,
            old_runtime_state_dir, state_dir)]
        auth_path, role_path, app_path, roles_path, old_dir, new_dir = resolved
        if old_dir == new_dir:
            raise KmsRepairError("journal_path_reused")
        accepted_path = None
        if step == "check-update":
            if accepted_bindings_path is None:
                raise KmsRepairError("accepted_bindings_path_required")
            candidate = Path(accepted_bindings_path)
            parent = validate_private_location(candidate.parent, acl_checker=acl_checker)
            accepted_path = parent / candidate.name
            if accepted_path.exists() or accepted_path.is_symlink():
                raise KmsRepairError("accepted_bindings_path_exists")
        elif accepted_bindings_path is not None:
            raise KmsRepairError("accepted_bindings_step_invalid")
        auth = load_authorization(auth_path)
        (source_ci_validator or validate_source_and_ci)(auth)
        role_bindings = _load_bindings(role_path)
        roles_binding = _load_roles_binding(roles_path, account_id=auth["account"])
        app_binding = _load_app_binding(app_path, acl_checker=acl_checker)
        if (role_bindings.get("account_id") != auth.get("account")
            or role_bindings.get("stack_arn") != app_binding.get("stack_arn")
            or app_binding.get("stack_arn") == roles_binding.get("stack_arn")):
            raise KmsRepairError("binding_mismatch")
        # Read the consumed old journal without acquiring/creating its lock
        # file. It is immutable evidence, never a write target.
        old_state = PlainFileJournal(old_dir).load()
        if type(old_state) is not dict:
            raise KmsRepairError("prior_journal_invalid")
        journal = (journal_factory or CasFileJournal)(new_dir)
        clients = (client_factory or _build_clients)()
        token = "dev-multiuser-" + hashlib.sha256(
            f"kms-repair:{auth['run_id']}:{auth['source_sha']}".encode("ascii")
        ).hexdigest()[:32]
        return run_kms_repair_step(
            clients, step=step, journal=journal, old_runtime_journal=old_state,
            account_id=auth["account"], caller_arn=auth["expected_caller_arn"],
            app_stack_arn=app_binding["stack_arn"],
            app_creation_run_id=app_binding["original_creation_run_id"],
            roles_stack_arn=roles_binding["stack_arn"],
            roles_creation_run_id=roles_binding["original_creation_run_id"],
            role_bindings=role_bindings, source_sha=auth["source_sha"], run_token=token,
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
            accepted_key_sink=(lambda key: _write_accepted_role_bindings(
                accepted_path, role_bindings, key, acl_checker=acl_checker))
            if step == "check-update" else None,
        )
    except KmsRepairError as exc:
        return {"success": False, "category": exc.category, "calls": 0}
    except Exception:
        return {"success": False, "category": "kms_repair_failed", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--role-bindings", type=Path, required=True)
    parser.add_argument("--app-binding", type=Path, required=True)
    parser.add_argument("--roles-binding", type=Path, required=True)
    parser.add_argument("--old-runtime-state-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--step", choices=("preflight", "request-update", "check-update"), required=True)
    parser.add_argument("--accepted-role-bindings", type=Path)
    args = parser.parse_args(argv)
    result = run_authorized_step(
        args.authorization, args.role_bindings, args.app_binding, args.roles_binding,
        args.old_runtime_state_dir, args.state_dir, args.step,
        accepted_bindings_path=args.accepted_role_bindings,
    )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["KmsRepairError", "run_kms_repair_step", "run_authorized_step", "main"]
