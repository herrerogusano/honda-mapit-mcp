"""Fresh, one-shot operator for MAPIT namespace key publication.

Import is inert. This runner does not perform MAPIT authentication or read a
MAPIT session. Historical bootstrap state is parsed read-only; the only write
is the separate create-only SecureString publication delegated to the reviewed
publisher core.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Callable

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from mapit.cloud_transport import validate_cloud_config
from mapit.config import MapitConfig
from scripts.build_aws_dev_mapit_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_BOUNDARY_NAME, OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME, STACK_NAME,
)
from scripts.dev_mapit_binding_key_setup import publish_mapit_keys
from scripts.dev_mapit_bootstrap_contract import (
    build_plan,
)
from scripts.dev_mapit_runtime_evidence import make_mapit_runtime_evidence_verifier
from scripts.dev_mapit_key_clients import create_mapit_key_clients
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _build_clients, _reject_constant, _reject_duplicates,
    validate_github_protections,
)
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization, validate_private_location, validate_source_and_ci,
)
from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator, _valid_runtime_evidence
from scripts.run_dev_mapit_bootstrap import ci_evidence_digest, load_runner_authority

REGION = "eu-west-1"
MAX_AUTH_BYTES = 16 * 1024
MAX_CONFIG_BYTES = 8 * 1024
MAX_TOTAL_CALLS = 160
MAX_TOTAL_SECONDS = 90.0
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_STACK_ARN = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}\Z")
_TABLE_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_AUTH_FIELDS = {"account", "expected_caller_arn", "source_sha", "ci_run_id", "run_id", "start", "end"}
_CONFIG_FIELDS = {
    "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
    "core_api_url", "geo_api_url", "frontend_url", "discovery_enabled", "http_timeout",
}
_EXPECTED_TYPES = {
    "MapitIdentityBindings": "AWS::DynamoDB::Table",
    "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
    "IdentityEnrollerRole": "AWS::IAM::Role",
    "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy",
}
_ENDPOINTS = {
    "sts": ("sts", REGION, f"https://sts.{REGION}.amazonaws.com"),
    "cloudformation": ("cloudformation", REGION, f"https://cloudformation.{REGION}.amazonaws.com"),
    "iam": ("iam", "us-east-1", "https://iam.amazonaws.com"),
    "dynamodb": ("dynamodb", REGION, f"https://dynamodb.{REGION}.amazonaws.com"),
    "ssm": ("ssm", REGION, f"https://ssm.{REGION}.amazonaws.com"),
    "cognito": ("cognito-idp", REGION, f"https://cognito-idp.{REGION}.amazonaws.com"),
    "apigatewayv2": ("apigatewayv2", REGION, f"https://apigateway.{REGION}.amazonaws.com"),
    "lambda": ("lambda", REGION, f"https://lambda.{REGION}.amazonaws.com"),
    "kms": ("kms", REGION, f"https://kms.{REGION}.amazonaws.com"),
}
_SAFE_CATEGORIES = {
    "authorization_invalid", "private_input_invalid", "source_unverified",
    "protections_unverified", "clients_invalid", "journal_consumed",
    "bootstrap_unverified", "caller_unverified", "runtime_unverified",
    "assume_role_unverified", "key_publication_invalid", "key_publication_unauthorized",
    "key_publication_consumed", "key_publication_preflight_failed", "key_publication_exists",
    "key_publication_intent_failed", "key_publication_outcome_unknown", "key_publication_unverified",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=True).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_result(ok: bool, category: str, calls: int, command_calls: int) -> dict[str, Any]:
    return {"step": "publish", "ok": bool(ok),
            "category": category if category in _SAFE_CATEGORIES | {"key_publication_verified"} else "key_publication_unverified",
            "calls": max(0, calls), "command_calls": max(0, command_calls)}


def _load_config(path: Path, *, acl_checker=None) -> MapitConfig:
    path = validate_private_location(path, acl_checker=acl_checker)
    size = path.stat().st_size
    if type(size) is not int or not 0 < size <= MAX_CONFIG_BYTES:
        raise ValueError
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                       parse_constant=_reject_constant)
    if type(value) is not dict or set(value) != _CONFIG_FIELDS:
        raise ValueError
    if (any(type(value[k]) is not str for k in ("region", "user_pool_id", "user_pool_client_id",
                                                  "identity_pool_id", "core_api_url", "geo_api_url",
                                                  "frontend_url"))
            or type(value["discovery_enabled"]) is not bool
            or type(value["http_timeout"]) not in (int, float)
            or isinstance(value["http_timeout"], bool)):
        raise ValueError
    config = MapitConfig(**value)
    validate_cloud_config(config)
    if config.frontend_url != "https://app.mapit.me/":
        raise ValueError
    return config


def _load_accepted_bootstrap(authority_path: Path, state_dir: Path, clients, *, acl_checker=None,
                             clock=time.time, monotonic=time.monotonic):
    """Parse immutable accepted state without locking/saving or checking old window freshness."""
    authority_path = validate_private_location(authority_path, acl_checker=acl_checker)
    state_dir = validate_private_location(state_dir, acl_checker=acl_checker)
    authority, source, github = load_runner_authority(authority_path, acl_checker=acl_checker)
    journal = FileJournal(state_dir)
    state_path = validate_private_location(journal.path, acl_checker=acl_checker)
    if not state_path.is_file() or state_path.stat().st_size > 128 * 1024:
        raise ValueError
    from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator
    coordinator = MapitBootstrapCoordinator(
        clients, journal, authority=authority, fresh_source=lambda _authority: {},
        fresh_protections=lambda _authority: {}, closed_runtime_verifier=lambda *_a, **_k: {},
        # Parser-only use: never run a step with this expired historical authority.
        wall_clock=lambda: authority.authorized_from_epoch, monotonic=lambda: 0.0,
    )
    state = coordinator._load()
    if (type(state) is not dict or state.get("preflight") is not True
            or state.get("acknowledged") is not True or state.get("readback") is not True):
        raise ValueError
    plan = coordinator.plan
    stack_id = state["acknowledged_stack_id"]
    receipt = state["readback_receipt"]
    created = datetime.fromisoformat(receipt["table_created_at_utc"])
    if not authority.authorized_from_epoch <= created.timestamp() < authority.authorized_until_epoch:
        raise ValueError
    receipt_binding = {
        "authority_sha256": authority._binding_sha256,
        "intent": state["intent"], "readback_receipt": receipt,
        "template_sha256": plan.template_sha256,
    }
    return authority, source, github, state, plan, _digest(receipt_binding)


class _ReadClient:
    def __init__(self, client, counter, started, deadline, monotonic, clock, auth_start, auth_end,
                 wall_state, *, allow_methods=()):
        self._client, self._counter = client, counter
        self._started, self._deadline, self._monotonic = started, deadline, monotonic
        self._clock, self._auth_start, self._auth_end = clock, auth_start, auth_end
        self._wall_state = wall_state
        self._allow_methods = frozenset(allow_methods)

    def __getattr__(self, name):
        if name in {"meta", "_endpoint"}:
            return getattr(self._client, name)
        target = getattr(self._client, name, None)
        if not callable(target) or not (name.startswith(("get_", "describe_", "list_"))
                                         or name == "assume_role" or name in self._allow_methods):
            raise ValueError
        def call(**kwargs):
            now = self._monotonic()
            epoch = self._clock()
            if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                    or now < self._counter[1] or now >= self._deadline or self._counter[0] >= MAX_TOTAL_CALLS
                    or type(epoch) not in (int, float) or isinstance(epoch, bool) or not math.isfinite(epoch)
                    or epoch < self._wall_state[0] or not self._auth_start <= epoch < self._auth_end):
                raise ValueError
            self._wall_state[0] = float(epoch)
            self._counter[0] += 1
            result = target(**kwargs)
            after = self._monotonic()
            after_epoch = self._clock()
            if (type(after) not in (int, float) or isinstance(after, bool) or not math.isfinite(after)
                    or after < now or after >= self._deadline
                    or type(after_epoch) not in (int, float) or isinstance(after_epoch, bool)
                    or not math.isfinite(after_epoch) or after_epoch < self._wall_state[0]
                    or not self._auth_start <= after_epoch < self._auth_end):
                raise ValueError
            self._wall_state[0] = float(after_epoch)
            self._counter[1] = float(after)
            if not isinstance(result, Mapping):
                raise ValueError
            metadata = result.get("ResponseMetadata")
            if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata["HTTPStatusCode"] != 200):
                raise ValueError
            for key in ("NextMarker", "Marker"):
                if result.get(key) not in (None, ""):
                    raise ValueError
            if result.get("NextToken") not in (None, ""):
                # Stack events are the only allowed bounded first page; callers
                # separately prove the exact matching completion event.
                if not (name == "describe_stack_events" and type(result["NextToken"]) is str
                        and len(result["NextToken"]) <= 4096):
                    raise ValueError
            if "IsTruncated" in result and result["IsTruncated"] is not False:
                raise ValueError
            return result
        return call


def _validate_clients(clients):
    if not isinstance(clients, Mapping) or set(clients) != set(_ENDPOINTS):
        raise ValueError
    for name, client in clients.items():
        service, region, endpoint = _ENDPOINTS[name]
        meta, cfg = client.meta, client.meta.config
        if (meta.service_model.service_name != service or meta.region_name != region or meta.endpoint_url != endpoint
                or type(cfg.retries.get("total_max_attempts")) is not int or cfg.retries["total_max_attempts"] != 1
                or cfg.signature_version != "v4" or type(cfg.proxies) is not dict or cfg.proxies != {}
                or client._endpoint.http_session._verify is not True
                or any(type(x) not in (int, float) or isinstance(x, bool) or not math.isfinite(x) or not 0 < x <= 3
                       for x in (cfg.connect_timeout, cfg.read_timeout))):
            raise ValueError


def _validate_key_clients(clients):
    if not isinstance(clients, Mapping) or set(clients) != {"sts", "ssm"}:
        raise ValueError
    for name, client in clients.items():
        service = "ssm" if name == "ssm" else "sts"
        meta, cfg = client.meta, client.meta.config
        if (meta.service_model.service_name != service or meta.region_name != REGION
                or meta.endpoint_url != f"https://{service}.{REGION}.amazonaws.com"
                or type(cfg.retries.get("total_max_attempts")) is not int or cfg.retries["total_max_attempts"] != 1
                or cfg.signature_version != "v4" or type(cfg.proxies) is not dict or cfg.proxies != {}
                or client._endpoint.http_session._verify is not True
                or any(type(x) not in (int, float) or isinstance(x, bool) or not math.isfinite(x) or not 0 < x <= 3
                       for x in (cfg.connect_timeout, cfg.read_timeout))):
            raise ValueError


def _verify_current_bootstrap(clients, authority, state, plan, receipt_digest, counter, started, deadline, monotonic):
    """Exact read-only current readback of the retained bootstrap resources."""
    def call(service, method, **kwargs):
        return getattr(clients[service], method)(**kwargs)
    stack_reply = call("cloudformation", "describe_stacks", StackName=STACK_NAME)
    rows = stack_reply.get("Stacks")
    stack_id = state["acknowledged_stack_id"]
    if type(rows) is not list or len(rows) != 1:
        raise ValueError
    stack = rows[0]
    expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                     "Purpose": "mapit-enrolled-identity-bindings", "OperatorRunId": str(authority.run_id)}
    tags = stack.get("Tags")
    if (stack.get("StackId") != stack_id or stack.get("StackName") != STACK_NAME
            or stack.get("StackStatus") != "CREATE_COMPLETE" or stack.get("EnableTerminationProtection") is not True
            or stack.get("RoleARN") not in (None, "") or type(tags) is not list
            or {row.get("Key"): row.get("Value") for row in tags if isinstance(row, Mapping)} != expected_tags
            or len(tags) != len(expected_tags)):
        raise ValueError
    template_reply = call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
    body = template_reply.get("TemplateBody")
    if type(body) is str:
        body = json.loads(body, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    if not isinstance(body, Mapping) or _canonical(body) != plan.template_json.encode("ascii"):
        raise ValueError
    events = call("cloudformation", "describe_stack_events", StackName=STACK_NAME).get("StackEvents")
    token = state["intent"]["client_request_token"]
    matches = []
    for event in events if type(events) is list and len(events) <= 100 else ():
        stamp = event.get("Timestamp") if isinstance(event, Mapping) else None
        if (isinstance(event, Mapping) and event.get("ClientRequestToken") == token
                and event.get("StackId") == stack_id and event.get("StackName") == STACK_NAME
                and event.get("LogicalResourceId") == STACK_NAME and event.get("PhysicalResourceId") == stack_id
                and event.get("ResourceType") == "AWS::CloudFormation::Stack"
                and event.get("ResourceStatus") == "CREATE_COMPLETE"
                and isinstance(stamp, datetime) and stamp.tzinfo is not None
                and authority.authorized_from_epoch <= stamp.timestamp() < authority.authorized_until_epoch):
            matches.append(event)
    if len(matches) != 1:
        raise ValueError
    resource_reply = call("cloudformation", "describe_stack_resources", StackName=STACK_NAME)
    resources = resource_reply.get("StackResources")
    if type(resources) is not list or len(resources) != 4:
        raise ValueError
    by_name = {}
    for row in resources:
        if (not isinstance(row, Mapping) or row.get("StackId") != stack_id or row.get("StackName") != STACK_NAME
                or row.get("ResourceStatus") != "CREATE_COMPLETE"
                or row.get("LogicalResourceId") in by_name
                or _EXPECTED_TYPES.get(row.get("LogicalResourceId")) != row.get("ResourceType")
                or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
            raise ValueError
        by_name[row["LogicalResourceId"]] = row
    if set(by_name) != set(_EXPECTED_TYPES):
        raise ValueError
    account = authority.account_id
    boundary_arn = f"arn:aws:iam::{account}:policy/{OPERATOR_BOUNDARY_NAME}"
    if (by_name["MapitIdentityBindings"]["PhysicalResourceId"] != STACK_NAME
            or by_name["IdentityEnrollerBoundary"]["PhysicalResourceId"] != boundary_arn
            or by_name["IdentityEnrollerRole"]["PhysicalResourceId"] != OPERATOR_ROLE_NAME):
        raise ValueError
    table = call("dynamodb", "describe_table", TableName=STACK_NAME).get("Table")
    props = plan.template["Resources"]["MapitIdentityBindings"]["Properties"]
    table_arn = f"arn:aws:dynamodb:{REGION}:{account}:table/{STACK_NAME}"
    if (not isinstance(table, Mapping) or table.get("TableName") != STACK_NAME or table.get("TableArn") != table_arn
            or table.get("TableStatus") != "ACTIVE" or table.get("TableId") != state["readback_receipt"]["table_id"]
            or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("OnDemandThroughput") != props.get("OnDemandThroughput")
            or table.get("KeySchema") != props.get("KeySchema")
            or table.get("AttributeDefinitions") != props.get("AttributeDefinitions")
            or table.get("DeletionProtectionEnabled") is not True or table.get("SSEDescription") is not None
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("LocalSecondaryIndexes") not in (None, [])):
        raise ValueError
    created = table.get("CreationDateTime")
    if (not isinstance(created, datetime) or created.tzinfo is None
            or created.astimezone(timezone.utc).isoformat(timespec="microseconds")
            != state["readback_receipt"]["table_created_at_utc"]):
        raise ValueError
    tag_reply = call("dynamodb", "list_tags_of_resource", ResourceArn=table_arn)
    expected_table_tags = {**expected_tags,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:stack-name": STACK_NAME,
        "aws:cloudformation:logical-id": "MapitIdentityBindings"}
    observed = {}
    for row in tag_reply.get("Tags", []) if type(tag_reply.get("Tags")) is list else ():
        if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or row.get("Key") in observed:
            raise ValueError
        observed[row["Key"]] = row["Value"]
    cloudformation_tags = {key: expected_table_tags[key] for key in (
        "aws:cloudformation:stack-id", "aws:cloudformation:stack-name",
        "aws:cloudformation:logical-id")}
    if (tag_reply.get("NextToken") not in (None, "")
            or any(observed.get(key) != value for key, value in expected_tags.items())
            or any(key not in expected_table_tags or expected_table_tags[key] != value
                   for key, value in observed.items())
            or set(observed) - set(expected_tags) - set(cloudformation_tags)):
        raise ValueError
    item = call("dynamodb", "get_item", TableName=table_arn,
                Key={"key": {"S": "identity-bindings-v1"}}, ConsistentRead=True,
                ReturnConsumedCapacity="NONE")
    if set(item) != {"ResponseMetadata"}:
        raise ValueError
    # Exact operator trust, permissions boundary and runtime read policy.
    role = call("iam", "get_role", RoleName=OPERATOR_ROLE_NAME).get("Role")
    role_props = plan.template["Resources"]["IdentityEnrollerRole"]["Properties"]
    from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator
    decode = MapitBootstrapCoordinator._decode_document
    if (not isinstance(role, Mapping) or role.get("RoleName") != OPERATOR_ROLE_NAME
            or role.get("Arn") != f"arn:aws:iam::{account}:role/{OPERATOR_ROLE_NAME}"
            or role.get("Path") != "/" or role.get("MaxSessionDuration") != 3600
            or not isinstance(role.get("PermissionsBoundary"), Mapping)
            or role["PermissionsBoundary"].get("PermissionsBoundaryArn") != boundary_arn
            or role["PermissionsBoundary"].get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}
            or decode(role.get("AssumeRolePolicyDocument")) != role_props["AssumeRolePolicyDocument"]):
        raise ValueError
    enroller_policy = role_props["Policies"][0]
    actual_inline = call("iam", "get_role_policy", RoleName=OPERATOR_ROLE_NAME,
                         PolicyName=enroller_policy["PolicyName"])
    if (actual_inline.get("RoleName") != OPERATOR_ROLE_NAME
            or actual_inline.get("PolicyName") != enroller_policy["PolicyName"]
            or decode(actual_inline.get("PolicyDocument")) != enroller_policy["PolicyDocument"]):
        raise ValueError
    inline_names = call("iam", "list_role_policies", RoleName=OPERATOR_ROLE_NAME)
    if (inline_names.get("PolicyNames") != [enroller_policy["PolicyName"]]
            or inline_names.get("IsTruncated", False) is not False or inline_names.get("Marker") not in (None, "")):
        raise ValueError
    attached = call("iam", "list_attached_role_policies", RoleName=OPERATOR_ROLE_NAME)
    if (attached.get("AttachedPolicies") != [] or attached.get("IsTruncated", False) is not False
            or attached.get("Marker") not in (None, "")):
        raise ValueError
    boundary = call("iam", "get_policy", PolicyArn=boundary_arn).get("Policy")
    if (not isinstance(boundary, Mapping) or boundary.get("Arn") != boundary_arn
            or boundary.get("PolicyName") != OPERATOR_BOUNDARY_NAME or boundary.get("Path") != "/"
            or boundary.get("DefaultVersionId") != "v1"):
        raise ValueError
    policy_version = call("iam", "get_policy_version", PolicyArn=boundary_arn, VersionId="v1").get("PolicyVersion")
    boundary_doc = plan.template["Resources"]["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
    if (not isinstance(policy_version, Mapping) or policy_version.get("IsDefaultVersion") is not True
            or decode(policy_version.get("Document")) != boundary_doc):
        raise ValueError
    runtime_props = plan.template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    runtime_doc = call("iam", "get_role_policy", RoleName=RUNTIME_ROLE_NAME,
                       PolicyName=runtime_props["PolicyName"])
    if (runtime_doc.get("RoleName") != RUNTIME_ROLE_NAME or runtime_doc.get("PolicyName") != runtime_props["PolicyName"]
            or decode(runtime_doc.get("PolicyDocument")) != runtime_props["PolicyDocument"]):
        raise ValueError
    key = call("kms", "describe_key", KeyId="alias/aws/ssm").get("KeyMetadata")
    if (not isinstance(key, Mapping) or key.get("Arn") != authority.ssm_key_arn
            or key.get("AWSAccountId") != account or key.get("KeyManager") != "AWS"
            or key.get("Enabled") is not True or key.get("KeyState") != "Enabled"
            or key.get("KeyUsage") != "ENCRYPT_DECRYPT"):
        raise ValueError
    for parameter in (CONFIG_PARAMETER,) + tuple(
            f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in authority._tenant_keys):
        try:
            call("ssm", "get_parameter", Name=parameter, WithDecryption=False)
        except Exception as exc:
            response = getattr(exc, "response", {})
            error = response.get("Error", {}) if isinstance(response, Mapping) else {}
            metadata = response.get("ResponseMetadata", {}) if isinstance(response, Mapping) else {}
            if (not isinstance(error, Mapping) or error.get("Code") != "ParameterNotFound"
                    or not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata["HTTPStatusCode"] != 400):
                raise
        else:
            raise ValueError
    current = {"authority_sha256": authority._binding_sha256,
               "intent": state["intent"], "readback_receipt": state["readback_receipt"],
               "template_sha256": plan.template_sha256}
    if _digest(current) != receipt_digest:
        raise ValueError


def _read_journal(journal):
    if journal.load() is not None:
        raise RuntimeError("journal_consumed")


def run_authorized_step(
    authorization_path: Path,
    bootstrap_authority_path: Path,
    bootstrap_state_dir: Path,
    runtime_evidence_path: Path,
    synthetic_binding_path: Path,
    synthetic_authorization_path: Path,
    synthetic_state_dir: Path,
    config_path: Path,
    publication_state_dir: Path,
    step: str = "publish",
    *, acl_checker=None, source_validator=validate_source_and_ci,
    protection_validator=validate_github_protections, client_factory=_build_clients,
    assume_role_client_factory=create_mapit_key_clients,
    journal_factory=FileJournal,
    runtime_verifier_factory=make_mapit_runtime_evidence_verifier,
    command_runner=subprocess.run, clock=time.time, monotonic=time.monotonic,
):
    """Validate fresh gates/readbacks, assume once, then publish one key bundle."""
    count = [0, 0]
    commands = [0]
    stage = "authorization_invalid"
    try:
        if step != "publish":
            raise ValueError
        mono0, wall0 = monotonic(), clock()
        if (type(mono0) not in (int, float) or isinstance(mono0, bool) or not math.isfinite(mono0)
                or type(wall0) not in (int, float) or isinstance(wall0, bool) or not math.isfinite(wall0)):
            raise ValueError
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        if not auth_path.is_file() or not 0 < auth_path.stat().st_size <= MAX_AUTH_BYTES:
            raise ValueError
        auth = load_authorization(auth_path)
        if (set(auth) != _AUTH_FIELDS or type(auth["account"]) is not str
                or type(auth["source_sha"]) is not str or re.fullmatch(r"[0-9a-f]{40}", auth["source_sha"]) is None
                or type(auth["run_id"]) is not int or type(auth["ci_run_id"]) is not int
                or type(auth["start"]) is not int or type(auth["end"]) is not int
                or not 0 < auth["end"] - auth["start"] <= 600 or not auth["start"] <= wall0 < auth["end"]):
            raise ValueError
        bootstrap_authority, _bootstrap_source, github = load_runner_authority(
            validate_private_location(Path(bootstrap_authority_path), acl_checker=acl_checker),
            acl_checker=acl_checker)
        bootstrap_plan = build_plan(bootstrap_authority)
        if (auth["account"] != bootstrap_authority.account_id
                or auth["expected_caller_arn"] != bootstrap_authority.expected_caller_arn
                or auth["run_id"] == bootstrap_authority.run_id):
            raise ValueError
        config = _load_config(Path(config_path), acl_checker=acl_checker)
        pub_state = validate_private_location(Path(publication_state_dir), acl_checker=acl_checker)
        bootstrap_state = validate_private_location(Path(bootstrap_state_dir), acl_checker=acl_checker)
        historical_state = validate_private_location(Path(synthetic_state_dir), acl_checker=acl_checker)
        protected_paths = [auth_path, Path(bootstrap_authority_path), bootstrap_state,
                           Path(runtime_evidence_path), Path(synthetic_binding_path),
                           Path(synthetic_authorization_path), historical_state, Path(config_path)]
        protected_paths = [Path(path).resolve() for path in protected_paths]
        if any(pub_state == path or pub_state in path.parents or path in pub_state.parents
               for path in protected_paths):
            raise ValueError
        journal = journal_factory(pub_state)
        _read_journal(journal)

        def counted_command(*args, **kwargs):
            commands[0] += 1
            return command_runner(*args, **kwargs)

        stage = "source_unverified"
        source_validator(auth, command_runner=counted_command)
        stage = "protections_unverified"
        protection_validator(github, command_runner=counted_command)
        now = clock()
        mono = monotonic()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                or now < auth["start"] or now >= auth["end"] or type(mono) not in (int, float)
                or isinstance(mono, bool) or not math.isfinite(mono) or mono < mono0
                or mono - mono0 >= MAX_TOTAL_SECONDS):
            raise ValueError
        stage = "clients_invalid"
        raw_clients = client_factory()
        _validate_clients(raw_clients)
        deadline = float(mono0) + MAX_TOTAL_SECONDS
        wall_state = [float(wall0)]
        clients = {name: _ReadClient(client, count, float(mono), deadline, monotonic,
                                     clock, auth["start"], auth["end"], wall_state)
                   for name, client in raw_clients.items()}
        # Validate the immutable historical journal with its owning coordinator
        # parser. It is read-only here; the fresh publication authority below
        # is the only authority that can authorize a new write.
        bootstrap_authority, _bootstrap_source, github, bootstrap_state, bootstrap_plan, receipt_digest = _load_accepted_bootstrap(
            Path(bootstrap_authority_path), Path(bootstrap_state_dir), raw_clients,
            acl_checker=acl_checker, clock=clock, monotonic=monotonic)
        def fresh():
            current = monotonic()
            epoch = clock()
            if (type(current) not in (int, float) or isinstance(current, bool) or not math.isfinite(current)
                    or current < count[1] or current >= deadline or count[0] > MAX_TOTAL_CALLS
                    or type(epoch) not in (int, float) or isinstance(epoch, bool) or not math.isfinite(epoch)
                    or epoch < wall_state[0] or epoch < auth["start"] or epoch >= auth["end"]):
                raise ValueError
            count[1] = float(current)
            wall_state[0] = float(epoch)
            return current

        stage = "caller_unverified"
        fresh()
        caller = clients["sts"].get_caller_identity()
        if caller.get("Account") != auth["account"] or caller.get("Arn") != auth["expected_caller_arn"]:
            raise ValueError

        # Source/protection are rerun near the cloud evidence reads, still before
        # role assumption or any publication intent.
        stage = "source_unverified"
        source_validator(auth, command_runner=counted_command)
        stage = "protections_unverified"
        protection_validator(github, command_runner=counted_command)
        fresh()
        stage = "bootstrap_unverified"
        _verify_current_bootstrap(clients, bootstrap_authority, bootstrap_state, bootstrap_plan,
                                  receipt_digest, count, mono0, deadline, monotonic)

        stage = "runtime_unverified"
        runtime_verifier = runtime_verifier_factory(
            evidence_path=Path(runtime_evidence_path), synthetic_binding_path=Path(synthetic_binding_path),
            synthetic_authorization_path=Path(synthetic_authorization_path),
            synthetic_state_dir=Path(synthetic_state_dir), acl_checker=acl_checker,
            monotonic=monotonic,
        )
        proof = runtime_verifier(clients, bootstrap_authority, bootstrap_plan.template, phase="readback")
        if not _valid_runtime_evidence(proof, bootstrap_authority, "readback"):
            raise ValueError
        stage = "source_unverified"
        source_validator(auth, command_runner=counted_command)
        stage = "protections_unverified"
        protection_validator(github, command_runner=counted_command)
        fresh()

        stage = "assume_role_unverified"
        fresh()
        role_arn = f"arn:aws:iam::{auth['account']}:role/{OPERATOR_ROLE_NAME}"
        assumed = clients["sts"].assume_role(RoleArn=role_arn,
            RoleSessionName=f"mapit-key-{auth['run_id']}", DurationSeconds=900)
        credentials = assumed.get("Credentials") if isinstance(assumed, Mapping) else None
        user = assumed.get("AssumedRoleUser") if isinstance(assumed, Mapping) else None
        expiration = credentials.get("Expiration") if isinstance(credentials, Mapping) else None
        if (not isinstance(credentials, Mapping) or set(credentials) != {
                "AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
                or not isinstance(user, Mapping)
                or user.get("Arn") != f"arn:aws:sts::{auth['account']}:assumed-role/{OPERATOR_ROLE_NAME}/mapit-key-{auth['run_id']}"
                or not isinstance(expiration, datetime) or expiration.tzinfo is None
                or not 20 <= expiration.timestamp() - clock() <= 900):
            raise ValueError
        explicit_clients = assume_role_client_factory(credentials, wall_clock=clock)
        _validate_key_clients(explicit_clients)
        explicit_clients = {name: _ReadClient(client, count, float(fresh()), deadline, monotonic,
                                              clock, auth["start"], auth["end"], wall_state,
                                              allow_methods=("put_parameter",) if name == "ssm" else ())
                            for name, client in explicit_clients.items()}
        stage = "key_publication_unverified"
        result = publish_mapit_keys(
            explicit_clients, journal, account_id=auth["account"], config=config,
            source_sha=auth["source_sha"], run_id=auth["run_id"],
            bootstrap_sha256=receipt_digest, start=auth["start"], end=auth["end"],
            clock=clock, monotonic=monotonic,
        )
        if result.get("ok") is not True or result.get("category") != "key_publication_verified":
            return _safe_result(False, result.get("category", stage), count[0], commands[0])
        return _safe_result(True, "key_publication_verified", count[0], commands[0])
    except Exception:
        return _safe_result(False, stage, count[0], commands[0])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Publish one fresh DEV MAPIT binding-key secret version.")
    for name in ("authorization", "bootstrap-authority", "bootstrap-state-dir", "runtime-evidence",
                 "synthetic-binding", "synthetic-authorization", "synthetic-state-dir", "config", "state-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    result = run_authorized_step(
        args.authorization, args.bootstrap_authority, args.bootstrap_state_dir,
        args.runtime_evidence, args.synthetic_binding, args.synthetic_authorization,
        args.synthetic_state_dir, args.config, args.state_dir,
    )
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
