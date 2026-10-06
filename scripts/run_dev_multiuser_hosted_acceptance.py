"""Private, bounded hosted-DEV acceptance runner.

This is the one-shot operator boundary for the isolated synthetic multi-user
DEV candidate.  It intentionally composes already reviewed, closed cores; it
does not discover resources, print provider payloads, persist passwords or
tokens, or touch production.  All private inputs and journals must live
outside the repository and OneDrive.

The default CLI is deliberately difficult to invoke accidentally: it needs an
explicit authorization envelope, private bindings, wheel directory, and all
private artifact inputs.  Tests inject every provider and clock so this module
can be validated without AWS, credentials, or network access.
"""
from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
import uuid

from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError,
    _reject_duplicates,
    load_authorization,
    validate_private_location,
    validate_source_and_ci,
)
from scripts.dev_multiuser_journal import PlainFileJournal as FileJournal
from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.dev_multiuser_managed_login import (
    HttpResponse,
    ManagedLoginClient,
    ManagedLoginError,
    direct_https_transport,
    provision_and_login_pair,
)
from scripts.dev_multiuser_readback import verify_closed_setup, verify_role_pair
from scripts.dev_multiuser_window import DevTestWindow
from scripts.dev_multiuser_test_users import DevMultiuserTestUserOperator, MAX_AUTHORITY_SECONDS
from scripts.run_dev_multiuser_runtime_update import (
    CasFileJournal,
    MultiuserBuildReceipt,
    _verify_caller_identity,
    build_multiuser_candidate_template,
    publish_multiuser_candidate,
    run_multiuser_update_step,
    run_recurrent_iam_step,
)
from scripts.build_aws_dev_multiuser_archive import build_dev_multiuser_archive
from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts import build_aws_dev_multiuser_archive as archive_builder
from mapit.aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantRecord
from mapit.remote_http import FixedRS256TokenVerifier
from scripts.dev_multiuser_e2e import run_http_acceptance
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts
from scripts.aws_retained_dev_delivery_preflight import (
    _alarm_config_matches, _document, _expected_physical, _expected_service_arns,
    _owned_resource_tags, _resource_rows_match, _rule_matches,
    _same, _shutdown_matches, _stack_events_projection, _resolve_internal_template,
    RetainedDevStackCreationTags,
)

REGION = "eu-west-1"
MAX_JWKS_BYTES = 32 * 1024
MAX_HTTP_BODY = 32 * 1024
MAX_CFN_POLLS = 30
CFN_POLL_SECONDS = 10.0
RUNTIME_SECONDS = 300
AUTH_SECONDS = 3600
CALLBACK_URL = "http://localhost:39031/callback"
FUNCTION = "honda-mapit-mcp-dev-retained-handler"
TABLE_NAME = "honda-mapit-mcp-dev-tenants"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:([0-9]{12}):stack/([^/]+)/[0-9a-f-]{36}\Z")

SAFE_CATEGORIES = frozenset({
    "source_verification_failed", "private_acl_invalid", "authorization_invalid",
    "bindings_invalid", "clients_invalid", "identity_mismatch", "roles_readback_failed",
    "setup_readback_failed", "closed_runtime_mismatch", "login_page_failed",
    "delivery_preflight_failed",
    "user_preflight_failed", "user_provision_failed", "user_readback_failed",
    "jwks_fetch_failed", "token_verify_failed", "archive_failed", "publish_failed",
    "iam_update_failed", "runtime_update_failed", "window_failed", "tenant_write_failed",
    "http_acceptance_failed", "closed_readback_failed", "window_expired", "runner_failed",
})


class HostedAcceptanceError(ValueError):
    """Safe category only; never includes identifiers/provider text."""

    def __init__(self, category: str):
        self.category = category if category in SAFE_CATEGORIES else "runner_failed"
        super().__init__(self.category)


def _fail(category: str) -> None:
    raise HostedAcceptanceError(category)


def _ok_response(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _read_private_json(path: Path, *, acl_checker: Callable[[Path], bool] | None = None, max_bytes: int = 32 * 1024) -> dict[str, Any]:
    try:
        resolved = validate_private_location(Path(path), acl_checker=acl_checker)
        size = resolved.stat().st_size
        if type(max_bytes) is not int or max_bytes <= 0 or not 0 < size <= max_bytes:
            raise ValueError
        with resolved.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) != size or len(raw) > max_bytes:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except Exception:
        _fail("bindings_invalid")


def _strict_template_body(value: Any) -> Any:
    """Normalize SDK TemplateBody string/mapping shapes with strict JSON."""
    try:
        if isinstance(value, str):
            raw = value.encode("utf-8", "strict")
        elif isinstance(value, Mapping):
            raw = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        else:
            raise ValueError
        if not 1 <= len(raw) <= 512 * 1024:
            raise ValueError
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")))
        if not isinstance(parsed, Mapping):
            raise ValueError
        return parsed
    except Exception:
        _fail("delivery_preflight_failed")


def _write_private_bytes(path: Path, body: bytes) -> None:
    if type(body) is not bytes or not body or len(body) > MAX_JWKS_BYTES:
        _fail("archive_failed")
    try:
        with path.open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        _fail("archive_failed")


def _binding(path_value: Mapping[str, Any], *, account: str, stack_name: str) -> tuple[str, int]:
    if set(path_value) != {"stack_arn", "original_creation_run_id"}:
        _fail("bindings_invalid")
    stack = path_value.get("stack_arn")
    match = _STACK.fullmatch(stack) if isinstance(stack, str) else None
    if match is None or match.group(1) != account or match.group(2) != stack_name:
        _fail("bindings_invalid")
    run_id = path_value.get("original_creation_run_id")
    if type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0:
        _fail("bindings_invalid")
    return stack, run_id


def _validate_full_role_bindings(value: Mapping[str, Any], *, account: str) -> dict[str, Any]:
    required = {
        "account_id", "provider_arn", "owner_id", "repository_id",
        "observed_dev_subject_format", "observed_dev_subject_sha256", "stack_arn",
        "artifact_stack_arn", "handler_arn", "api_arn", "shutdown_state_machine_arn",
        "artifact_bucket_arn", "execution_role_arn",
    }
    if set(value) not in (required, required | {"lambda_environment_key_arn"}):
        _fail("bindings_invalid")
    if value.get("account_id") != account:
        _fail("bindings_invalid")
    try:
        # Construct both policy variants before a provider client can write.
        build_cd_retained_dev_multiuser_roles(**value, observed_user_pool_id=None)
    except Exception:
        _fail("bindings_invalid")
    return dict(value)


def _verify_sts(sts_client: Any, *, account: str, caller_arn: str) -> None:
    try:
        value = sts_client.get_caller_identity()
        if not _ok_response(value) or value.get("Account") != account or value.get("Arn") != caller_arn:
            _fail("identity_mismatch")
    except HostedAcceptanceError:
        raise
    except Exception:
        _fail("identity_mismatch")


def fetch_public_jwks(*, user_pool_id: str, transport: Callable[..., Any] = direct_https_transport) -> tuple[bytes, str]:
    """Fetch only the exact eu-west-1 Cognito JWKS document, bounded once."""
    if type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None or not callable(transport):
        _fail("jwks_fetch_failed")
    url = f"https://cognito-idp.{REGION}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    try:
        response = transport("GET", url, {"Accept": "application/json", "Cache-Control": "no-store"}, None, 5)
        if (type(response) is not HttpResponse or type(response.status) is not int or response.status != 200
            or response.url != url or type(response.body) is not bytes
            or not 1 <= len(response.body) <= MAX_JWKS_BYTES):
            raise ValueError
        parse_cognito_jwks(response.body)
        return response.body, hashlib.sha256(response.body).hexdigest()
    except Exception:
        _fail("jwks_fetch_failed")


def _user_rows(cognito: Any, *, pool: str, usernames: tuple[str, str]) -> tuple[str, str]:
    subjects: list[str] = []
    try:
        for username in usernames:
            response = cognito.admin_get_user(UserPoolId=pool, Username=username)
            if (not _ok_response(response) or response.get("Username") != username
                or response.get("Enabled") is not True or response.get("UserStatus") != "CONFIRMED"):
                _fail("user_readback_failed")
            attrs = response.get("UserAttributes")
            if not isinstance(attrs, list):
                _fail("user_readback_failed")
            found = [row.get("Value") for row in attrs if isinstance(row, Mapping) and row.get("Name") == "sub"]
            if len(found) != 1 or type(found[0]) is not str or _UUID.fullmatch(found[0]) is None:
                _fail("user_readback_failed")
            subjects.append(found[0])
    except HostedAcceptanceError:
        raise
    except Exception:
        _fail("user_readback_failed")
    if len(set(subjects)) != 2:
        _fail("user_readback_failed")
    return subjects[0], subjects[1]


def _verify_token(token: str, *, subject: str, pool: str, api_id: str, client_id: str, jwks: bytes) -> None:
    try:
        policy = CognitoDevPolicy(pool, api_id, client_id, subject)
        verifier = FixedRS256TokenVerifier(policy, parse_cognito_jwks(jwks))
        verified = asyncio.run(verifier.verify_token(token))
        if (verified is None or verified.subject != subject or verified.client_id != client_id
            or verified.resource != policy.audience or verified.scopes != [policy.required_scope]):
            _fail("token_verify_failed")
    except HostedAcceptanceError:
        raise
    except Exception:
        _fail("token_verify_failed")


def _create_dir(path: Path, *, acl_checker: Callable[[Path], bool] | None) -> Path:
    try:
        _create_private_directory(path, acl_checker=acl_checker)
        return validate_private_location(path, acl_checker=acl_checker)
    except Exception:
        _fail("private_acl_invalid")


def _derive_user_window(now: int, authorized_from: int, authorized_until: int) -> tuple[int, int]:
    """Return the separate, at-most-five-minute user-provisioning window."""
    if (type(now) is not int or type(authorized_from) is not int
        or type(authorized_until) is not int or authorized_until <= authorized_from
        or now < authorized_from or now >= authorized_until):
        _fail("window_expired")
    end = min(now + MAX_AUTHORITY_SECONDS, authorized_until)
    if end <= now:
        _fail("window_expired")
    return now, end


def _tenant_write(store: DynamoDBTenantStore, journal: FileJournal, key: str, *, revoked: bool = False) -> bool:
    """Perform one journaled CAS and strong readback; no implicit retries."""
    operation = "revoke" if revoked else "activate"
    with journal.locked():
        prior = journal.load()
        if prior is not None:
            if prior.get("operation") != operation or prior.get("key") != key or prior.get("phase") not in {"intent", "committed"}:
                return False
            if prior.get("phase") == "committed":
                expected = 2 if revoked else 1
                record = store.get(key)
                return record is not None and record.status == ("revoked" if revoked else "active") and record.revision == expected
            # An existing intent is ambiguous: reconcile by a fresh strong
            # read only.  Never replay the business CAS after an uncertain
            # write or a process restart.
            record = store.get(key)
            target_revision = 2 if revoked else 1
            if record is not None and record.status == ("revoked" if revoked else "active") and record.revision == target_revision:
                journal.save({"schema": 1, "operation": operation, "key": key, "phase": "committed", "expected_revision": 1 if revoked else None, "target_revision": target_revision})
                return True
            return False
        expected_revision = 1 if revoked else None
        target_revision = 2 if revoked else 1
        journal.save({"schema": 1, "operation": operation, "key": key, "phase": "intent", "expected_revision": expected_revision, "target_revision": target_revision})
        try:
            if store.cas(key, expected_revision, DurableTenantRecord(key, "revoked" if revoked else "active", target_revision)) is not True:
                return False
        except Exception:
            return False
        record = store.get(key)
        if record is None or record.status != ("revoked" if revoked else "active") or record.revision != target_revision:
            return False
        journal.save({"schema": 1, "operation": operation, "key": key, "phase": "committed", "expected_revision": expected_revision, "target_revision": target_revision})
        return True


def _poll_update(call: Callable[[str], Mapping[str, Any]], *, sleep: Callable[[float], None], clock: Callable[[], float], deadline: int) -> bool:
    if clock() >= deadline:
        return False
    result = call("request-update")
    if result.get("success") is not True:
        return False
    for index in range(MAX_CFN_POLLS):
        if clock() >= deadline:
            return False
        result = call("check-update")
        if result.get("success") is not True:
            return False
        if result.get("category") == "readback_verified":
            return True
        if index + 1 < MAX_CFN_POLLS:
            if clock() >= deadline:
                return False
            sleep(CFN_POLL_SECONDS)
    return False


def _v2_readback_call(clients: Mapping[str, Any], service: str, method: str, *, calls: list[int], max_calls: int, **kwargs: Any) -> Mapping[str, Any]:
    if calls[0] >= max_calls:
        raise ValueError("readback budget")
    calls[0] += 1
    value = getattr(clients[service], method)(**kwargs)
    if not _ok_response(value) or not isinstance(value, Mapping):
        raise ValueError("invalid readback")
    if value.get("IsTruncated") is True or "NextToken" in value or "Marker" in value:
        raise ValueError("unbounded readback")
    return value


def _run_v2_infrastructure_preflight(
    clients: Mapping[str, Any], *, account: str, app_stack: str, app_run: int,
    controls_stack: str, controls_run: int, artifact_stack: str,
    artifact_run: int, artifact_bucket: str, api_id: str, callback_url: str,
) -> None:
    """Verify the current 11-resource/V2 retained-dev closure.

    This intentionally does not call the historical five-resource delivery
    preflight.  Its factories are parameterized here by the exact setup,
    timed-controls and artifact templates currently being hosted.
    """
    calls = [0]
    max_calls = 64
    controls_name = "honda-mapit-mcp-dev-retained-controls"
    artifacts_name = "honda-mapit-mcp-dev-retained-runtime-artifacts"
    try:
        # CloudFormation ownership, exact resource sets and exact source
        # templates are checked before any service-level readback.
        control_stack = _v2_readback_call(clients, "cloudformation", "describe_stacks", calls=calls, max_calls=max_calls, StackName=controls_stack).get("Stacks")
        artifact_stack_value = _v2_readback_call(clients, "cloudformation", "describe_stacks", calls=calls, max_calls=max_calls, StackName=artifact_stack).get("Stacks")
        artifact_stack_row = artifact_stack_value[0] if isinstance(artifact_stack_value, list) and len(artifact_stack_value) == 1 else None
        for value, arn, name in ((control_stack, controls_stack, controls_name), (artifact_stack_value, artifact_stack, artifacts_name)):
            if (not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping)
                or value[0].get("StackId") != arn or value[0].get("StackName") != name
                or value[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or value[0].get("EnableTerminationProtection") is not True):
                raise ValueError("stack ownership")
        artifact_tags = artifact_stack_row.get("Tags") if isinstance(artifact_stack_row, Mapping) else None
        artifact_tag_values = {row.get("Key"): row.get("Value") for row in artifact_tags} if isinstance(artifact_tags, list) and all(isinstance(row, Mapping) and set(row) == {"Key", "Value"} for row in artifact_tags) else {}
        if (artifact_tag_values.get("Project") != "honda-mapit-mcp" or artifact_tag_values.get("Environment") != "dev"
            or artifact_tag_values.get("Purpose") != "retained-dev-artifacts"
            or not isinstance(artifact_tag_values.get("OperatorRunId"), str)
            or re.fullmatch(r"[1-9][0-9]*", artifact_tag_values["OperatorRunId"]) is None):
            raise ValueError("artifact ownership tags")
        if str(artifact_run) != artifact_tag_values["OperatorRunId"]:
            raise ValueError("artifact ownership tags")
        control_rows = _v2_readback_call(clients, "cloudformation", "describe_stack_resources", calls=calls, max_calls=max_calls, StackName=controls_stack).get("StackResources")
        artifact_rows = _v2_readback_call(clients, "cloudformation", "describe_stack_resources", calls=calls, max_calls=max_calls, StackName=artifact_stack).get("StackResources")
        control_template = build_dev_multiuser_timed_controls(api_id)
        artifact_template = build_retained_dev_artifacts()
        control_types = {key: value.get("Type") for key, value in control_template["Resources"].items()}
        artifact_types = {key: value.get("Type") for key, value in artifact_template["Resources"].items()}
        if not _resource_rows_match(control_rows, stack_arn=controls_stack, stack_name=controls_name, expected_types=control_types, physical_ids=_expected_physical(account)):
            raise ValueError("control resources")
        if not _resource_rows_match(artifact_rows, stack_arn=artifact_stack, stack_name=artifacts_name, expected_types=artifact_types, physical_ids={"RuntimeArtifactBucket": artifact_bucket, "RuntimeArtifactBucketPolicy": artifact_bucket}):
            raise ValueError("artifact resources")
        control_actual_template = _strict_template_body(_v2_readback_call(clients, "cloudformation", "get_template", calls=calls, max_calls=max_calls, StackName=controls_stack, TemplateStage="Original").get("TemplateBody"))
        artifact_actual_template = _strict_template_body(_v2_readback_call(clients, "cloudformation", "get_template", calls=calls, max_calls=max_calls, StackName=artifact_stack, TemplateStage="Original").get("TemplateBody"))
        if not _same(control_actual_template, control_template) or not _same(artifact_actual_template, artifact_template):
            raise ValueError("template mismatch")
        if not _stack_events_projection(_v2_readback_call(clients, "cloudformation", "describe_stack_events", calls=calls, max_calls=max_calls, StackName=controls_stack).get("StackEvents"), stack_arn=controls_stack, stack_name=controls_name):
            raise ValueError("control events")
        if not _stack_events_projection(_v2_readback_call(clients, "cloudformation", "describe_stack_events", calls=calls, max_calls=max_calls, StackName=artifact_stack).get("StackEvents"), stack_arn=artifact_stack, stack_name=artifacts_name):
            raise ValueError("artifact events")

        expected_arns = _expected_service_arns(account)
        control_creation = RetainedDevStackCreationTags.from_receipt(
            stack_kind="controls", stack_arn=controls_stack, account_id=account,
            tags=[{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-controls"}, {"Key": "OperatorRunId", "Value": str(controls_run)}],
        )
        artifact_creation = RetainedDevStackCreationTags.from_receipt(
            stack_kind="artifact", stack_arn=artifact_stack, account_id=account,
            tags=[{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": str(artifact_run)}],
        )
        control_stack_tags = control_stack[0].get("Tags") if isinstance(control_stack[0], Mapping) else None
        if not _owned_resource_tags(control_stack_tags, [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-controls"}], stack=control_creation, logical_id=""):
            raise ValueError("control stack tags")
        if not _owned_resource_tags(artifact_stack_row.get("Tags"), [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-artifacts"}], stack=artifact_creation, logical_id=""):
            raise ValueError("artifact stack tags")
        control_props = control_template["Resources"]
        shutdown_props = _resolve_internal_template(control_props["ShutdownStateMachine"]["Properties"], account)
        shutdown = _v2_readback_call(clients, "stepfunctions", "describe_state_machine", calls=calls, max_calls=max_calls, stateMachineArn=expected_arns["ShutdownStateMachine"])
        if not _shutdown_matches(shutdown, shutdown_props, account_id=account):
            raise ValueError("shutdown")
        shutdown_tags = _v2_readback_call(clients, "stepfunctions", "list_tags_for_resource", calls=calls, max_calls=max_calls, resourceArn=expected_arns["ShutdownStateMachine"])
        if not _owned_resource_tags(shutdown_tags.get("tags"), shutdown_props.get("Tags"), stack=control_creation, logical_id="ShutdownStateMachine"):
            raise ValueError("shutdown tags")
        expected_rule = _resolve_internal_template(control_props["RequestTripwireAlarmRule"]["Properties"], account)
        rule = _v2_readback_call(clients, "events", "describe_rule", calls=calls, max_calls=max_calls, Name="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule")
        if not _rule_matches(rule, expected_rule, account_id=account):
            raise ValueError("rule")
        targets = _v2_readback_call(clients, "events", "list_targets_by_rule", calls=calls, max_calls=max_calls, Rule=rule["Name"])
        expected_targets = expected_rule.get("Targets")
        if targets.get("Targets") != expected_targets:
            raise ValueError("targets")
        rule_tags = _v2_readback_call(clients, "events", "list_tags_for_resource", calls=calls, max_calls=max_calls, ResourceARN=expected_arns["RequestTripwireAlarmRule"])
        if not _owned_resource_tags(rule_tags.get("Tags"), expected_rule.get("Tags"), stack=control_creation, logical_id="RequestTripwireAlarmRule"):
            raise ValueError("rule tags")
        expected_alarm = control_props["RequestTripwireAlarm"]["Properties"]
        alarms = _v2_readback_call(clients, "cloudwatch", "describe_alarms", calls=calls, max_calls=max_calls, AlarmNames=["honda-mapit-mcp-dev-retained-request-tripwire"]).get("MetricAlarms")
        if not isinstance(alarms, list) or len(alarms) != 1 or not _alarm_config_matches(alarms[0], expected_alarm):
            raise ValueError("alarm")
        alarm_tags = _v2_readback_call(clients, "cloudwatch", "list_tags_for_resource", calls=calls, max_calls=max_calls, ResourceARN=expected_arns["RequestTripwireAlarm"])
        if not _owned_resource_tags(alarm_tags.get("Tags"), expected_alarm.get("Tags"), stack=control_creation, logical_id="RequestTripwireAlarm"):
            raise ValueError("alarm tags")
        for logical_id in ("ShutdownWorkflowRole", "RequestTripwireEventRole"):
            props = control_props[logical_id]["Properties"]
            resolved = _resolve_internal_template(props, account)
            role_name = resolved.get("RoleName")
            role = _v2_readback_call(clients, "iam", "get_role", calls=calls, max_calls=max_calls, RoleName=role_name).get("Role")
            tags = _v2_readback_call(clients, "iam", "list_role_tags", calls=calls, max_calls=max_calls, RoleName=role_name).get("Tags")
            policies = _v2_readback_call(clients, "iam", "list_role_policies", calls=calls, max_calls=max_calls, RoleName=role_name)
            attached = _v2_readback_call(clients, "iam", "list_attached_role_policies", calls=calls, max_calls=max_calls, RoleName=role_name)
            expected_policies = resolved.get("Policies")
            if (not isinstance(role, Mapping) or role.get("RoleName") != role_name
                or role.get("Arn") != expected_arns[logical_id]
                or role.get("Path") not in {None, "/"}
                or not _same(_document(role.get("AssumeRolePolicyDocument")), resolved.get("AssumeRolePolicyDocument"))
                or not _owned_resource_tags(tags, resolved.get("Tags"), stack=control_creation, logical_id=logical_id)
                or not isinstance(expected_policies, list)
                or sorted(policies.get("PolicyNames", [])) != sorted(item.get("PolicyName") for item in expected_policies)
                or attached.get("AttachedPolicies") != []):
                raise ValueError("control IAM role")
            for policy in expected_policies:
                name = policy.get("PolicyName")
                actual = _v2_readback_call(clients, "iam", "get_role_policy", calls=calls, max_calls=max_calls, RoleName=role_name, PolicyName=name)
                if (actual.get("RoleName") != role_name or actual.get("PolicyName") != name
                    or not _same(_document(actual.get("PolicyDocument")), policy.get("PolicyDocument"))):
                    raise ValueError("control inline policy")

        bucket_props = artifact_template["Resources"]["RuntimeArtifactBucket"]["Properties"]
        bucket_reads = {
            "get_bucket_location": "LocationConstraint", "get_public_access_block": "PublicAccessBlockConfiguration",
            "get_bucket_encryption": "ServerSideEncryptionConfiguration", "get_bucket_ownership_controls": "OwnershipControls",
            "get_bucket_versioning": "Status", "get_bucket_lifecycle_configuration": "Rules", "get_bucket_policy_status": "PolicyStatus",
            "get_bucket_tagging": "TagSet", "get_bucket_policy": "Policy",
        }
        expected_lifecycle = [{"ID": "DevTerminalJournalRetention", "Status": "Enabled", "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}, "Expiration": {"Days": 30}}]
        expected_tags = [
            {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": str(artifact_run)},
            {"Key": "aws:cloudformation:stack-id", "Value": artifact_stack}, {"Key": "aws:cloudformation:stack-name", "Value": artifacts_name},
            {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"},
        ]
        expected_policy = {"Version": "2012-10-17", "Statement": [{"Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{artifact_bucket}", f"arn:aws:s3:::{artifact_bucket}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        for method, response_key in bucket_reads.items():
            reply = _v2_readback_call(clients, "s3", method, calls=calls, max_calls=max_calls, Bucket=artifact_bucket, ExpectedBucketOwner=account)
            value = _document(reply.get(response_key)) if method == "get_bucket_policy" else reply.get(response_key)
            if method == "get_bucket_location" and value != "eu-west-1":
                raise ValueError("bucket location")
            if method == "get_bucket_encryption" and value != {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}:
                raise ValueError("bucket encryption")
            if method == "get_bucket_ownership_controls" and value != bucket_props.get("OwnershipControls"):
                raise ValueError("bucket ownership")
            if method == "get_bucket_versioning" and value not in (None, ""):
                raise ValueError("bucket versioning")
            if method == "get_bucket_lifecycle_configuration" and value != expected_lifecycle:
                raise ValueError("bucket lifecycle")
            if method == "get_bucket_policy_status" and value != {"IsPublic": False}:
                raise ValueError("bucket policy status")
            if method == "get_public_access_block" and value != bucket_props.get("PublicAccessBlockConfiguration"):
                raise ValueError("bucket public access")
            if method == "get_bucket_tagging" and not _same(value, expected_tags):
                raise ValueError("bucket tags")
            if method == "get_bucket_policy" and not _same(value, expected_policy):
                raise ValueError("bucket policy")
        return
    except Exception:
        _fail("delivery_preflight_failed")


def _run_arm_candidate_probe(
    archive_path: Path, *, manifest: Mapping[str, Any], manifest_sha: str,
    jwks_sha: str, tokens: Mapping[str, str], runtime_start: int,
    runtime_end: int, account: str, api_id: str, pool_id: str,
    client_id: str,
) -> None:
    """Execute the pinned offline ARM candidate check before S3 publication."""
    try:
        from scripts import probe_aws_dev_multiuser_arm as probe
        context = probe.docker_helpers._docker_context()
        tenants = manifest.get("tenants")
        if (not isinstance(tenants, list) or len(tenants) != 2
            or any(not isinstance(row, Mapping) for row in tenants)
            or set(tokens) != {"a", "b"}):
            _fail("archive_failed")
        payload = {
            "checks": list(probe.CHECKS), "manifest_sha256": manifest_sha,
            "jwks_sha256": jwks_sha, "source_sha": manifest.get("source_sha"),
            "user_pool_id": pool_id, "client_id": client_id, "account_id": account,
            "api_id": api_id, "start": runtime_start, "end": runtime_end,
            "now": runtime_start + 60, "keys": {"a": tenants[0].get("key"), "b": tenants[1].get("key")},
            "tokens": {"a": tokens["a"], "b": tokens["b"]},
        }
        result = probe.probe_candidate_archive(archive_path, context=context, payload=payload)
        if result.get("success") is not True or result.get("category") != "multiuser_arm_probe_passed":
            _fail("archive_failed")
    except HostedAcceptanceError:
        raise
    except Exception:
        _fail("archive_failed")


def _build_aws_clients() -> dict[str, Any]:
    """Construct fixed direct-TLS clients only after local gates pass."""
    blocked = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url"}
    if any(name.casefold() in blocked for name in os.environ):
        _fail("clients_invalid")
    try:
        import boto3
        from botocore.config import Config
        config = Config(
            region_name=REGION, connect_timeout=2, read_timeout=3,
            retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4",
        )
        session = boto3.Session(region_name=REGION)
        clients = {
            "sts": session.client("sts", region_name=REGION, endpoint_url="https://sts.eu-west-1.amazonaws.com", config=config, verify=True),
            "iam": session.client("iam", region_name="us-east-1", endpoint_url="https://iam.amazonaws.com", config=Config(region_name="us-east-1", connect_timeout=2, read_timeout=3, retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4"), verify=True),
            "cloudformation": session.client("cloudformation", region_name=REGION, endpoint_url="https://cloudformation.eu-west-1.amazonaws.com", config=config, verify=True),
            "cognito": session.client("cognito-idp", region_name=REGION, endpoint_url="https://cognito-idp.eu-west-1.amazonaws.com", config=config, verify=True),
            "apigateway": session.client("apigatewayv2", region_name=REGION, endpoint_url="https://apigateway.eu-west-1.amazonaws.com", config=config, verify=True),
            "apigatewayv2": session.client("apigatewayv2", region_name=REGION, endpoint_url="https://apigateway.eu-west-1.amazonaws.com", config=config, verify=True),
            "dynamodb": session.client("dynamodb", region_name=REGION, endpoint_url="https://dynamodb.eu-west-1.amazonaws.com", config=config, verify=True),
            "lambda": session.client("lambda", region_name=REGION, endpoint_url="https://lambda.eu-west-1.amazonaws.com", config=config, verify=True),
            "stepfunctions": session.client("stepfunctions", region_name=REGION, endpoint_url="https://states.eu-west-1.amazonaws.com", config=config, verify=True),
            "events": session.client("events", region_name=REGION, endpoint_url="https://events.eu-west-1.amazonaws.com", config=config, verify=True),
            "cloudwatch": session.client("cloudwatch", region_name=REGION, endpoint_url="https://monitoring.eu-west-1.amazonaws.com", config=config, verify=True),
            "s3": session.client("s3", region_name=REGION, endpoint_url="https://s3.eu-west-1.amazonaws.com", config=config, verify=True),
        }
        return clients
    except HostedAcceptanceError:
        raise
    except Exception:
        _fail("clients_invalid")


@dataclass(frozen=True)
class HostedAcceptanceInputs:
    authorization_path: Path
    private_root: Path
    app_binding_path: Path
    roles_binding_path: Path
    controls_binding_path: Path
    role_bindings_path: Path
    wheel_dir: Path
    artifact_binding_path: Path | None = None


def run_hosted_acceptance(
    inputs: HostedAcceptanceInputs,
    *,
    clients: Mapping[str, Any] | None = None,
    clients_factory: Callable[[], Mapping[str, Any]] | None = None,
    source_verifier: Callable[[Mapping[str, Any]], Any] = validate_source_and_ci,
    acl_checker: Callable[[Path], bool] | None = None,
    login_client_factory: Callable[..., ManagedLoginClient] | None = None,
    jwks_fetcher: Callable[..., tuple[bytes, str]] = fetch_public_jwks,
    archive_factory: Callable[..., Any] = build_dev_multiuser_archive,
    http_acceptance: Callable[..., Mapping[str, Any]] | None = None,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Run the exact ordered hosted-DEV path and return only safe booleans."""
    opened = False
    window: DevTestWindow | None = None
    tenant_store: DynamoDBTenantStore | None = None
    tenant_a_journal: FileJournal | None = None
    tenant_a_key: str | None = None
    revocation_journal: FileJournal | None = None
    token_map: dict[str, str] = {}
    try:
        auth = load_authorization(validate_private_location(inputs.authorization_path, acl_checker=acl_checker))
        source_verifier(auth)
        root = validate_private_location(inputs.private_root, acl_checker=acl_checker)
        app_binding = _read_private_json(inputs.app_binding_path, acl_checker=acl_checker)
        roles_binding = _read_private_json(inputs.roles_binding_path, acl_checker=acl_checker)
        controls_binding = _read_private_json(inputs.controls_binding_path, acl_checker=acl_checker)
        artifact_binding = (_read_private_json(inputs.artifact_binding_path, acl_checker=acl_checker)
                            if inputs.artifact_binding_path is not None else None)
        role_values = _validate_full_role_bindings(_read_private_json(inputs.role_bindings_path, acl_checker=acl_checker), account=auth["account"])
        app_stack, app_run = _binding(app_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained")
        roles_stack, roles_run = _binding(roles_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-cd-delivery")
        controls_stack, controls_run = _binding(controls_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-controls")
        # The role factory binds the application stack (the stack whose
        # Lambda/API it serves); the separate CD-delivery stack is only the
        # CloudFormation role-pair readback namespace.
        if role_values.get("stack_arn") != app_stack:
            _fail("bindings_invalid")
        if artifact_binding is None:
            _fail("bindings_invalid")
        artifact_stack, artifact_run = _binding(artifact_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-runtime-artifacts")
        if role_values.get("artifact_stack_arn") != artifact_stack:
            _fail("bindings_invalid")
        role_template = build_cd_retained_dev_multiuser_roles(**role_values, observed_user_pool_id=None)
        if clients is None:
            if not callable(clients_factory):
                _fail("clients_invalid")
            clients = clients_factory()
        required = {"sts", "iam", "cloudformation", "cognito", "apigateway", "apigatewayv2", "dynamodb", "lambda", "stepfunctions", "events", "cloudwatch", "s3"}
        if set(clients) != required or any(clients[name] is None for name in required):
            _fail("clients_invalid")
        _verify_sts(clients["sts"], account=auth["account"], caller_arn=auth["expected_caller_arn"])
        roles_result = verify_role_pair({"iam": clients["iam"]}, role_template, account=auth["account"], roles_stack_arn=roles_stack, original_creation_run_id=roles_run)
        if roles_result.get("success") is not True:
            _fail("roles_readback_failed")
        # The setup verifier is intentionally before all user writes.  It
        # checks the actual API, pool, client, domain, branding, table, route
        # closure, stack ownership and exact 11-resource shape.
        rows = clients["cloudformation"].describe_stack_resources(StackName=app_stack).get("StackResources")
        if not isinstance(rows, list) or len(rows) != 11:
            _fail("setup_readback_failed")
        by_logical = {row.get("LogicalResourceId"): row for row in rows if isinstance(row, Mapping)}
        api_id = by_logical.get("McpApi", {}).get("PhysicalResourceId")
        pool_id = by_logical.get("McpUserPool", {}).get("PhysicalResourceId")
        client_id = by_logical.get("McpUserPoolClient", {}).get("PhysicalResourceId")
        if type(api_id) is not str or _API.fullmatch(api_id) is None or type(pool_id) is not str or _POOL.fullmatch(pool_id) is None or type(client_id) is not str or _CLIENT.fullmatch(client_id) is None:
            _fail("setup_readback_failed")
        setup_result = verify_closed_setup(
            {"cloudformation": clients["cloudformation"], "cognito": clients["cognito"], "apigateway": clients["apigateway"], "dynamodb": clients["dynamodb"]},
            account=auth["account"], stack_arn=app_stack, api_id=api_id, user_pool_id=pool_id,
            client_id=client_id, callback_url=CALLBACK_URL, original_creation_run_id=app_run,
        )
        if setup_result.get("success") is not True:
            _fail("setup_readback_failed")
        app_template = _strict_template_body(clients["cloudformation"].get_template(StackName=app_stack, TemplateStage="Original").get("TemplateBody"))
        if not _same(app_template, build_retained_dev_multiuser_setup(api_id=api_id, callback_url=CALLBACK_URL)):
            _fail("setup_readback_failed")
        # Fresh, complete app/artifact/control/role/bucket readback must pass
        # before the login smoke or either Cognito user can be provisioned.
        run_dir = _create_dir(root / ("hosted-dev-" + secrets.token_hex(16)), acl_checker=acl_checker)
        _run_v2_infrastructure_preflight(
            clients, account=auth["account"], app_stack=app_stack, app_run=app_run,
            controls_stack=controls_stack, controls_run=controls_run,
            artifact_stack=artifact_stack, artifact_run=artifact_run,
            artifact_bucket=role_values["artifact_bucket_arn"].split(":::", 1)[-1],
            api_id=api_id, callback_url=CALLBACK_URL,
        )
        resource = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
        scope = resource + "/use"
        domain = f"honda-mapit-mcp-dev-multiuser-{auth['account']}.auth.eu-west-1.amazoncognito.com"
        def make_client() -> ManagedLoginClient:
            if login_client_factory is not None:
                return login_client_factory(domain=domain, account_id=auth["account"], client_id=client_id, callback_url=CALLBACK_URL, resource=resource, required_scope=scope)
            return ManagedLoginClient(account_id=auth["account"], domain=domain, client_id=client_id, callback_url=CALLBACK_URL, resource=resource, required_scope=scope)
        dry = make_client().dry_login_page()
        if dry.get("success") is not True:
            _fail("login_page_failed")
        for name in ("users", "artifact", "iam", "runtime", "window", "tenant-a", "tenant-b", "revocation"):
            _create_dir(run_dir / name, acl_checker=acl_checker)
        revocation_journal = FileJournal(run_dir / "revocation")
        user_journal = FileJournal(run_dir / "users")
        user_start, user_end = _derive_user_window(int(clock()), auth["start"], auth["end"])
        operator = DevMultiuserTestUserOperator(
            {"cognito": clients["cognito"]}, user_journal, account_id=auth["account"], user_pool_id=pool_id,
            run_id=str(auth["run_id"]), authorized_from_epoch=user_start, authorized_until_epoch=user_end, wall_clock=clock,
        )
        if operator.preflight().get("category") != "preflight_verified":
            _fail("user_preflight_failed")
        def receive_token(username: str, token: Any) -> None:
            if type(username) is not str or not hasattr(token, "access_token"):
                _fail("user_provision_failed")
            token_map[username] = token.access_token
        login_result = provision_and_login_pair(operator, make_client, on_tokens=receive_token)
        if login_result.get("category") != "users_authenticated":
            _fail("user_provision_failed")
        state = user_journal.load()
        usernames = tuple(row.get("username") for row in state.get("slots", [])) if isinstance(state, Mapping) else ()
        if len(usernames) != 2 or any(type(name) is not str for name in usernames):
            _fail("user_readback_failed")
        subjects = _user_rows(clients["cognito"], pool=pool_id, usernames=(usernames[0], usernames[1]))
        if set(token_map) != set(usernames):
            _fail("token_verify_failed")
        jwks, jwks_sha = jwks_fetcher(user_pool_id=pool_id)
        for username, subject in zip(usernames, subjects):
            _verify_token(token_map[username], subject=subject, pool=pool_id, api_id=api_id, client_id=client_id, jwks=jwks)
        keys = ("tenant-" + secrets.token_hex(32), "tenant-" + secrets.token_hex(32))
        tenant_a_key = keys[0]
        manifest = {
            "schema": 1, "builder": "build_retained_dev_multiuser_archive", "environment": "dev", "synthetic": True,
            "source_sha": auth["source_sha"], "api_id": api_id, "user_pool_id": pool_id, "client_id": client_id,
            "jwks_sha256": jwks_sha, "table_arn": f"arn:aws:dynamodb:{REGION}:{auth['account']}:{'table/' + TABLE_NAME}",
            "tenants": [{"key": keys[0], "subject": subjects[0], "label": "synthetic-A"}, {"key": keys[1], "subject": subjects[1], "label": "synthetic-B"}],
        }
        manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        manifest_path, jwks_path, archive_path = run_dir / "artifact" / "manifest.json", run_dir / "artifact" / "jwks.json", run_dir / "artifact" / "runtime.zip"
        _write_private_bytes(manifest_path, manifest_raw); _write_private_bytes(jwks_path, jwks)
        summary = archive_factory(inputs.wheel_dir, manifest_path, jwks_path, archive_path, account_id=auth["account"])
        if (not archive_path.is_file() or getattr(summary, "dependencies_valid", False) is not True
            or getattr(summary, "source_allowlist_valid", False) is not True
            or getattr(summary, "lock_valid", False) is not True
            or getattr(summary, "manifest_valid", False) is not True):
            _fail("archive_failed")
        # The ARM probe uses its own short synthetic clock.  The Lambda
        # execution window is deliberately derived later, after recurrent IAM
        # readback, so publication/update cannot consume a stale window.
        probe_start = int(clock())
        probe_end = probe_start + RUNTIME_SECONDS
        _run_arm_candidate_probe(
            archive_path, manifest=manifest,
            manifest_sha=hashlib.sha256(manifest_raw).hexdigest(), jwks_sha=jwks_sha,
            tokens={"a": token_map[usernames[0]], "b": token_map[usernames[1]]},
            runtime_start=probe_start, runtime_end=probe_end,
            account=auth["account"], api_id=api_id, pool_id=pool_id, client_id=client_id,
        )
        role_journal = CasFileJournal(run_dir / "iam")
        recurrent_args = dict(clients={key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")}, journal=role_journal, account_id=auth["account"], stack_arn=roles_stack, caller_arn=auth["expected_caller_arn"], source_sha=auth["source_sha"], run_token="dev-multiuser-" + secrets.token_hex(16), role_bindings=role_values, observed_user_pool_id=pool_id, authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"])
        if run_recurrent_iam_step(step="preflight", **recurrent_args).get("success") is not True or not _poll_update(lambda step: run_recurrent_iam_step(step=step, **recurrent_args), sleep=sleep, clock=clock, deadline=auth["end"]):
            _fail("iam_update_failed")
        recurrent_roles = build_cd_retained_dev_multiuser_roles(**role_values, observed_user_pool_id=pool_id)
        recurrent_readback = verify_role_pair(
            {"iam": clients["iam"]}, recurrent_roles, account=auth["account"],
            roles_stack_arn=roles_stack, original_creation_run_id=roles_run,
        )
        if recurrent_readback.get("success") is not True:
            _fail("iam_update_failed")
        runtime_start = int(clock()) + 30
        runtime_end = runtime_start + RUNTIME_SECONDS
        if runtime_end >= auth["end"]:
            _fail("window_expired")
        receipt = MultiuserBuildReceipt(
            source_sha=auth["source_sha"], api_id=api_id, user_pool_id=pool_id, client_id=client_id,
            jwks_sha256=jwks_sha, manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            zip_sha256=summary.sha256, archive_path=archive_path,
            execution_start_epoch=runtime_start, execution_end_epoch=runtime_end,
        )
        artifact_journal = CasFileJournal(run_dir / "artifact")
        pub = publish_multiuser_candidate(clients["s3"], artifact_journal, receipt, account_id=auth["account"], bucket=f"honda-mapit-mcp-dev-retained-{auth['account']}-eu-west-1", run_id=str(uuid.uuid4()), authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"], wall_clock=clock, monotonic=monotonic)
        if pub.get("success") is not True:
            _fail("publish_failed")
        runtime_journal = CasFileJournal(run_dir / "runtime")
        update_args = dict(clients={key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")}, journal=runtime_journal, account_id=auth["account"], stack_arn=app_stack, caller_arn=auth["expected_caller_arn"], cfn_role_arn=f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update", source_sha=auth["source_sha"], run_token="dev-multiuser-" + secrets.token_hex(16), receipt=receipt, callback_url=CALLBACK_URL, subjects=subjects, tenant_keys=keys, bucket=f"honda-mapit-mcp-dev-retained-{auth['account']}-eu-west-1", authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"])
        if run_multiuser_update_step(step="preflight", **update_args).get("success") is not True or not _poll_update(lambda step: run_multiuser_update_step(step=step, **update_args), sleep=sleep, clock=clock, deadline=auth["end"]):
            _fail("runtime_update_failed")
        config = clients["lambda"].get_function_configuration(FunctionName=FUNCTION)
        concurrency = clients["lambda"].get_function_concurrency(FunctionName=FUNCTION)
        function = clients["lambda"].get_function(FunctionName=FUNCTION)
        code_sha = function.get("Configuration", {}).get("CodeSha256") if isinstance(function, Mapping) and isinstance(function.get("Configuration"), Mapping) else None
        expected_environment = {
            "MAPIT_MCP_ENV": "dev", "MAPIT_DEV_MULTIUSER_MODE": "synthetic",
            "MAPIT_SOURCE_SHA256": auth["source_sha"], "MAPIT_COGNITO_JWKS_SHA256": jwks_sha,
            "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": hashlib.sha256(manifest_raw).hexdigest(),
            "MAPIT_DEV_EXPECTED_ACCOUNT_ID": auth["account"],
            "MAPIT_DEV_EXECUTION_START_EPOCH": str(runtime_start),
            "MAPIT_DEV_EXECUTION_END_EPOCH": str(runtime_end),
            "MAPIT_COGNITO_USER_POOL_ID": pool_id, "MAPIT_COGNITO_CLIENT_ID": client_id,
            "MAPIT_OBSERVED_API_ID": api_id,
        }
        if (not _ok_response(config) or config.get("State") != "Active" or config.get("Runtime") != "python3.13"
            or config.get("Handler") != "mapit.aws_dev_multiuser_entrypoint.handler"
            or config.get("Architectures") != ["arm64"] or config.get("MemorySize") != 256
            or config.get("Timeout") != 20 or not _ok_response(concurrency)
            or concurrency.get("ReservedConcurrentExecutions") != 0
            or not _ok_response(function) or type(code_sha) is not str or not code_sha
            or config.get("Environment", {}).get("Variables") != expected_environment):
            _fail("runtime_update_failed")
        lambda_tags = clients["lambda"].list_tags(Resource=FUNCTION)
        expected_lambda_tags = [
            {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev"}, {"Key": "OperatorRunId", "Value": str(app_run)},
            {"Key": "aws:cloudformation:stack-id", "Value": app_stack},
            {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained"},
            {"Key": "aws:cloudformation:logical-id", "Value": "McpHandler"},
        ]
        if not _owned_resource_tags(lambda_tags.get("Tags"), expected_lambda_tags[:3], stack=RetainedDevStackCreationTags.from_receipt(stack_kind="app", stack_arn=app_stack, account_id=auth["account"], tags=expected_lambda_tags[:4]), logical_id="McpHandler"):
            _fail("runtime_update_failed")
        try:
            if archive_path.stat().st_size > 16 * 1024 * 1024:
                _fail("runtime_update_failed")
            expected_code_sha = base64.b64encode(hashlib.sha256(archive_path.read_bytes()).digest()).decode("ascii")
        except HostedAcceptanceError:
            raise
        except Exception:
            _fail("runtime_update_failed")
        if code_sha != expected_code_sha:
            _fail("runtime_update_failed")
        runtime_bucket = f"honda-mapit-mcp-dev-retained-{auth['account']}-eu-west-1"
        head = clients["s3"].head_object(Bucket=runtime_bucket, Key=f"runtime/{receipt.zip_sha256}.zip", ExpectedBucketOwner=auth["account"])
        if (not _ok_response(head) or head.get("ServerSideEncryption") != "AES256"
            or type(head.get("ContentLength")) is not int or head["ContentLength"] <= 0):
            _fail("runtime_update_failed")
        while clock() < runtime_start:
            sleep(min(1.0, runtime_start - clock()))
        machine_arn = f"arn:aws:states:{REGION}:{auth['account']}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
        window = DevTestWindow({key: clients[key] for key in ("lambda", "apigatewayv2", "stepfunctions")}, FileJournal(run_dir / "window"), account=auth["account"], api_id=api_id, machine_arn=machine_arn, source_sha=auth["source_sha"], run_id=uuid.uuid4().hex, execution_start=runtime_start, execution_end=runtime_end, clock=clock)
        if window.preflight().get("success") is not True:
            _fail("window_failed")
        # Mark the close obligation before the opening call: a partial/unknown
        # opening must still enter the finally cleanup path.
        opened = True
        if window.open().get("success") is not True:
            _fail("window_failed")
        store = DynamoDBTenantStore(clients["dynamodb"], table_arn=manifest["table_arn"], allowed_keys=keys, writer=clients["dynamodb"])
        tenant_store = store
        tenant_a_journal = FileJournal(run_dir / "tenant-a")
        if not _tenant_write(store, tenant_a_journal, keys[0]) or not _tenant_write(store, FileJournal(run_dir / "tenant-b"), keys[1]):
            _fail("tenant_write_failed")
        accept = (http_acceptance or run_http_acceptance)(api_id=api_id, token_a=token_map[usernames[0]], token_b=token_map[usernames[1]], revoke_a=lambda: _tenant_write(store, revocation_journal, keys[0], revoked=True))
        if accept.get("success") is not True:
            _fail("http_acceptance_failed")
        closed = window.close()
        if closed.get("success") is not True:
            _fail("closed_readback_failed")
        # Keep the cleanup obligation set until a successful close/readback.
        opened = False
        return {"success": True, "category": "hosted_multiuser_acceptance_verified", "checks": {"source_ci": True, "identity": True, "roles": True, "setup": True, "login_page": True, "users": True, "tokens": True, "archive": True, "artifact": True, "iam": True, "runtime": True, "timer": True, "http": True, "tenants": True}}
    except HostedAcceptanceError as exc:
        return {"success": False, "category": exc.category}
    except Exception:
        return {"success": False, "category": "runner_failed"}
    finally:
        if tenant_store is not None and tenant_a_key is not None and revocation_journal is not None:
            try:
                _tenant_write(tenant_store, revocation_journal, tenant_a_key, revoked=True)
            except Exception:
                pass
        if opened and window is not None:
            try:
                window.close()
            except Exception:
                pass
        token_map.clear()


__all__ = ["HostedAcceptanceError", "HostedAcceptanceInputs", "fetch_public_jwks", "run_hosted_acceptance", "main"]


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authorization", "private-root", "app-binding", "roles-binding", "controls-binding", "role-bindings", "artifact-binding", "wheel-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    values = vars(args)
    inputs = HostedAcceptanceInputs(
        authorization_path=values["authorization"], private_root=values["private_root"],
        app_binding_path=values["app_binding"], roles_binding_path=values["roles_binding"],
        controls_binding_path=values["controls_binding"], role_bindings_path=values["role_bindings"],
        wheel_dir=values["wheel_dir"], artifact_binding_path=values["artifact_binding"],
    )
    result = run_hosted_acceptance(inputs, clients_factory=_build_aws_clients)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
