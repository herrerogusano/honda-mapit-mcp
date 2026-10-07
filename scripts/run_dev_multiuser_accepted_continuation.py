"""One fresh, closed update and bounded acceptance of an already accepted DEV runtime.

This is deliberately separate from the ordinary setup/recovery runner.  It
requires the exact accepted-runtime and reset lineage as private inputs, creates
new journals, and never resumes a historical write.  All passwords and access
tokens remain process-local; all provider calls are injected in tests.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
import uuid

from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization,
    validate_private_location,
    validate_source_and_ci,
)
from scripts.dev_multiuser_journal import PlainFileJournal as FileJournal
from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.dev_multiuser_confirmed_pair_recovery import (
    _digest as _pair_digest,
    _latest_pair,
    _reset_state,
    validate_recurring_pair_history,
    prepare_confirmed_pair_reset,
    reset_confirmed_pair_once,
)
from scripts.dev_multiuser_user_recovery import _validate_original
from scripts.dev_multiuser_managed_login import (
    ManagedLoginClient,
    provision_and_login_pair,
)
from scripts.dev_multiuser_readback import verify_role_pair, verify_closed_setup
from scripts.dev_multiuser_window import DevTestWindow
from scripts.run_dev_multiuser_runtime_update import (
    CasFileJournal,
    MultiuserBuildReceipt,
    _read_multiuser_archive,
    build_multiuser_candidate_template,
    publish_multiuser_candidate,
)
from scripts.dev_multiuser_closed_update import ClosedDevUpdate
from scripts.build_aws_dev_multiuser_archive import build_dev_multiuser_archive
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts import run_dev_multiuser_hosted_acceptance as hosted
from mapit.aws_dev_multiuser_entrypoint import MAX_MANIFEST_BYTES, parse_manifest
from mapit.aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantRecord
from scripts.dev_multiuser_e2e import run_http_acceptance

REGION = "eu-west-1"
FUNCTION = hosted.FUNCTION
RUNTIME_SECONDS = hosted.RUNTIME_SECONDS
AUTH_SECONDS = hosted.AUTH_SECONDS


@dataclass(frozen=True)
class AcceptedContinuationInputs:
    """Explicit private paths; filenames are not treated as provenance."""

    authorization_path: Path
    private_root: Path
    app_binding_path: Path
    roles_binding_path: Path
    controls_binding_path: Path
    artifact_binding_path: Path
    role_bindings_path: Path
    wheel_dir: Path
    original_creation_users_path: Path
    first_pair_users_path: Path
    first_reset_users_path: Path
    first_reset_path: Path
    prior_reset_users_path: Path
    prior_reset_path: Path
    accepted_users_path: Path
    accepted_reset_path: Path
    accepted_runtime_path: Path
    accepted_artifact_dir: Path


class AcceptedContinuationError(ValueError):
    _CATEGORIES = frozenset({
        "bindings_invalid", "source_invalid", "clients_invalid", "identity_invalid",
        "history_invalid", "accepted_runtime_invalid", "setup_readback_failed",
        "private_acl_invalid", "window_expired", "login_page_failed", "user_preflight_failed",
        "archive_failed", "publish_failed", "runtime_update_failed", "runtime_readback_failed",
        "login_failed", "token_invalid", "window_failed", "tenant_write_failed",
        "http_acceptance_failed", "closure_unverified", "runner_failed",
    })

    def __init__(self, category: str):
        super().__init__(category if category in self._CATEGORIES else "runner_failed")
        self.category = category if category in self._CATEGORIES else "runner_failed"


def _fail(category: str) -> None:
    raise AcceptedContinuationError(category)


def validate_accepted_pair_lineage(
    *, original_creation_users: Any,
    first_pair_users: Any,
    first_reset_users: Any,
    first_reset: Any,
    prior_reset_users: Any,
    prior_reset: Any,
    accepted_users: Any,
    accepted_reset: Any,
    accepted_runtime: Any,
    account: str,
    pool: str,
    accepted_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate 828c -> 8ed -> f247 -> 54ad without relaxing old history rules."""
    try:
        h8ed = validate_recurring_pair_history(
            original_creation_journal=original_creation_users,
            first_confirmed_pair_journal=first_pair_users,
            latest_pair_journal=first_reset_users,
            previous_reset_journal=first_reset,
            account=account, user_pool_id=pool,
        )
        hf247 = validate_recurring_pair_history(
            original_creation_journal=original_creation_users,
            first_confirmed_pair_journal=first_pair_users,
            latest_pair_journal=prior_reset_users,
            previous_reset_journal=prior_reset,
            earlier_reset_journal=first_reset,
            account=account, user_pool_id=pool,
        )
        original = _validate_original(original_creation_users.load(), account=account, pool=pool)
        current_pair = _latest_pair(accepted_users.load(), account=account, pool=pool, original=original)
        reset = _reset_state(accepted_reset.load(), allow_complete=True)
        runtime = accepted_runtime.load()
        if (type(runtime) is not dict or set(runtime) != {"binding", "phase"}
            or runtime.get("phase") != "accepted" or type(runtime.get("binding")) is not dict):
            raise ValueError
        binding = runtime["binding"]
        expected_binding_fields = {"schema", "operation", "account", "caller", "end", "prior", "role",
                                   "source", "stack", "start", "target", "token"}
        expected_tenants = accepted_manifest.get("tenants")
        if (set(binding) != expected_binding_fields or type(binding.get("schema")) is not int or binding.get("schema") != 1
            or binding.get("operation") != "dev_multiuser_closed_update"
            or binding.get("account") != account
            or binding.get("source") != accepted_manifest.get("source_sha")
            or type(binding.get("stack")) is not str
            or re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{re.escape(account)}:stack/honda-mapit-mcp-dev-retained/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}", binding["stack"]) is None
            or type(binding.get("caller")) is not str or binding.get("caller") == ""
            or type(binding.get("role")) is not str
            or binding.get("role") != f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-cfn-update"
            or type(binding.get("source")) is not str or re.fullmatch(r"[0-9a-f]{40}", binding["source"]) is None
            or type(binding.get("token")) is not str or re.fullmatch(r"dev-multiuser-[0-9a-f]{32}", binding["token"]) is None
            or type(binding.get("prior")) is not str or re.fullmatch(r"[0-9a-f]{64}", binding["prior"]) is None
            or type(binding.get("target")) is not str or re.fullmatch(r"[0-9a-f]{64}", binding["target"]) is None
            or type(binding.get("start")) is not int or isinstance(binding.get("start"), bool)
            or type(binding.get("end")) is not int or isinstance(binding.get("end"), bool)
            or not 0 < binding["end"] - binding["start"] <= AUTH_SECONDS
            or type(expected_tenants) is not list or len(expected_tenants) != 2):
            raise ValueError
        if (reset["phase"] != "complete" or reset["revision"] != 6
            or reset["account_id"] != account or reset["user_pool_id"] != pool
            or reset["run_id"] != original["run_id"]
            or reset["original_creation_sha256"] != hf247["original_sha256"]
            or reset["first_confirmed_pair_sha256"] != hf247["first_pair_sha256"]
            or reset["previous_reset_sha256"] != hf247["previous_reset_sha256"]
            or reset["consumed_pair_sha256"] != hf247["latest_pair_sha256"]
            or reset["latest_pair_sha256"] != hf247["first_pair_sha256"]
            or reset["source_sha256"] != binding["source"]
            or not binding["start"] <= reset["authorized_from_epoch"] < reset["authorized_until_epoch"] <= binding["end"]):
            raise ValueError
        for index, row in enumerate(current_pair["slots"]):
            manifest_row = expected_tenants[index]
            reset_row = reset["slots"][index]
            if (manifest_row.get("label") != f"synthetic-{chr(65 + index)}"
                or manifest_row.get("subject") is None
                or hashlib.sha256(manifest_row["subject"].encode("ascii")).hexdigest() != row["user_sub_sha256"]
                or row["user_sub_sha256"] != reset_row["subject_sha256"]
                or manifest_row.get("key") is None):
                raise ValueError
        # The latest reset journal is a consumed second-recurring attempt.  It
        # is validated by exact chain hashes above, never passed to the older
        # validator which intentionally rejects its consumed-pair marker.
        return {"first_pair_sha256": hf247["first_pair_sha256"],
                "previous_reset_sha256": hf247["previous_reset_sha256"],
                "consumed_pair_sha256": hf247["latest_pair_sha256"],
                "accepted_pair_sha256": _pair_digest(accepted_users.load()),
                "accepted_reset_sha256": _pair_digest(reset),
                "accepted_runtime_binding": dict(binding)}
    except Exception:
        _fail("history_invalid")


def run_accepted_runtime_continuation(
    inputs: AcceptedContinuationInputs,
    *,
    clients: Mapping[str, Any] | None = None,
    clients_factory: Callable[[], Mapping[str, Any]] | None = None,
    source_verifier: Callable[[Mapping[str, Any]], Any] = validate_source_and_ci,
    acl_checker: Callable[[Path], bool] | None = None,
    login_client_factory: Callable[..., ManagedLoginClient] | None = None,
    jwks_fetcher: Callable[..., tuple[bytes, str]] = hosted.fetch_public_jwks,
    archive_factory: Callable[..., Any] = build_dev_multiuser_archive,
    http_acceptance: Callable[..., Mapping[str, Any]] | None = None,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    """Continue one accepted 19-resource runtime into one bounded A/B test."""
    window: DevTestWindow | None = None
    opened = False
    tenant_store = None
    tenant_a_key = None
    token_map: dict[str, str] = {}
    revocation_journal = None
    stage = "preflight"
    safe_http_result: dict[str, Any] | None = None
    try:
        auth = load_authorization(validate_private_location(inputs.authorization_path, acl_checker=acl_checker))
        source_verifier(auth)
        root = validate_private_location(inputs.private_root, acl_checker=acl_checker)
        checked_paths = {
            name: validate_private_location(getattr(inputs, name), acl_checker=acl_checker)
            for name in (
                "authorization_path", "app_binding_path", "roles_binding_path",
                "controls_binding_path", "artifact_binding_path", "role_bindings_path",
                "original_creation_users_path", "first_pair_users_path", "first_reset_users_path",
                "first_reset_path", "prior_reset_users_path", "prior_reset_path",
                "accepted_users_path", "accepted_reset_path", "accepted_runtime_path",
            )
        }
        try:
            from scripts.build_aws_dev_runtime import _validate_external_wheel_dir
            checked_paths["wheel_dir"] = _validate_external_wheel_dir(
                Path(inputs.wheel_dir), Path(__file__).resolve().parents[1])
        except Exception:
            _fail("bindings_invalid")
        checked_paths["accepted_artifact_dir"] = validate_private_location(inputs.accepted_artifact_dir, acl_checker=acl_checker)
        if any(_path_contains(root, candidate) or _path_contains(candidate, root)
               for name, candidate in checked_paths.items() if name not in {"wheel_dir"}):
            _fail("bindings_invalid")
        try:
            if next(root.iterdir(), None) is not None:
                _fail("accepted_runtime_invalid")
        except AcceptedContinuationError:
            raise
        except Exception:
            _fail("private_acl_invalid")
        if clients is None:
            if not callable(clients_factory):
                _fail("clients_invalid")
            clients = clients_factory()
        required = {"sts", "iam", "cloudformation", "cognito", "apigateway", "apigatewayv2", "dynamodb",
                    "lambda", "stepfunctions", "events", "cloudwatch", "s3", "kms"}
        if set(clients) != required or any(clients.get(name) is None for name in required):
            _fail("clients_invalid")
        # Bind immutable lineage before any service write or user reset.
        state_paths = {
            "original_creation_users": ("original_creation_users_path", False),
            "first_pair_users": ("first_pair_users_path", False),
            "first_reset_users": ("first_reset_users_path", False),
            "first_reset": ("first_reset_path", False),
            "prior_reset_users": ("prior_reset_users_path", False),
            "prior_reset": ("prior_reset_path", False),
            "accepted_users": ("accepted_users_path", False),
            "accepted_reset": ("accepted_reset_path", False),
            "accepted_runtime": ("accepted_runtime_path", True),
        }
        journals = {key: (CasFileJournal(checked_paths[path_field]) if cas else FileJournal(checked_paths[path_field]))
                    for key, (path_field, cas) in state_paths.items()}
        # Read-only basic binding/ownership gates. Detailed service checks are
        # delegated to the same accepted DEV infrastructure verifier.
        app_binding = hosted._read_private_json(inputs.app_binding_path, acl_checker=acl_checker)
        roles_binding = hosted._read_private_json(inputs.roles_binding_path, acl_checker=acl_checker)
        controls_binding = hosted._read_private_json(inputs.controls_binding_path, acl_checker=acl_checker)
        artifact_binding = hosted._read_private_json(inputs.artifact_binding_path, acl_checker=acl_checker)
        role_values = hosted._validate_full_role_bindings(
            hosted._read_private_json(inputs.role_bindings_path, acl_checker=acl_checker), account=auth["account"])
        app_stack, app_run = hosted._binding(app_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained")
        roles_stack, roles_run = hosted._binding(roles_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-cd-delivery")
        controls_stack, controls_run = hosted._binding(controls_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-controls")
        artifact_stack, artifact_run = hosted._binding(artifact_binding, account=auth["account"], stack_name="honda-mapit-mcp-dev-retained-runtime-artifacts")
        if role_values.get("stack_arn") != app_stack or role_values.get("artifact_stack_arn") != artifact_stack:
            _fail("bindings_invalid")
        accepted_runtime_state = journals["accepted_runtime"].load()
        accepted_runtime_binding = accepted_runtime_state.get("binding") if isinstance(accepted_runtime_state, Mapping) else None
        expected_update_role = f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update"
        if (not isinstance(accepted_runtime_binding, Mapping)
            or set(accepted_runtime_binding) != {"schema", "operation", "account", "caller", "end", "prior", "role", "source", "stack", "start", "target", "token"}
            or type(accepted_runtime_binding.get("schema")) is not int
            or accepted_runtime_binding.get("schema") != 1
            or accepted_runtime_binding.get("operation") != "dev_multiuser_closed_update"
            or accepted_runtime_binding.get("account") != auth["account"]
            or accepted_runtime_binding.get("caller") != auth["expected_caller_arn"]
            or accepted_runtime_binding.get("role") != expected_update_role
            or accepted_runtime_binding.get("stack") != app_stack
            or type(accepted_runtime_binding.get("source")) is not str
            or re.fullmatch(r"[0-9a-f]{40}", accepted_runtime_binding["source"]) is None
            or type(accepted_runtime_binding.get("token")) is not str
            or re.fullmatch(r"dev-multiuser-[0-9a-f]{32}", accepted_runtime_binding["token"]) is None
            or type(accepted_runtime_binding.get("prior")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", accepted_runtime_binding["prior"]) is None
            or type(accepted_runtime_binding.get("target")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", accepted_runtime_binding["target"]) is None
            or type(accepted_runtime_binding.get("start")) is not int
            or isinstance(accepted_runtime_binding.get("start"), bool)
            or type(accepted_runtime_binding.get("end")) is not int
            or isinstance(accepted_runtime_binding.get("end"), bool)):
            _fail("accepted_runtime_invalid")
        hosted._verify_sts(clients["sts"], account=auth["account"], caller_arn=auth["expected_caller_arn"])
        app_stack_reply = clients["cloudformation"].describe_stacks(StackName=app_stack)
        stack_rows = app_stack_reply.get("Stacks") if isinstance(app_stack_reply, Mapping) else None
        if (not hosted._ok_response(app_stack_reply) or type(stack_rows) is not list or len(stack_rows) != 1
            or not isinstance(stack_rows[0], Mapping)
            or stack_rows[0].get("StackId") != app_stack
            or stack_rows[0].get("StackName") != "honda-mapit-mcp-dev-retained"
            or stack_rows[0].get("StackStatus") != "UPDATE_COMPLETE"
            or stack_rows[0].get("EnableTerminationProtection") is not True
            or stack_rows[0].get("RoleARN") != expected_update_role):
            _fail("accepted_runtime_invalid")
        stack_creation_tags = hosted.RetainedDevStackCreationTags.from_receipt(
            stack_kind="app", stack_arn=app_stack, account_id=auth["account"],
            tags=stack_rows[0].get("Tags"),
        )
        if stack_creation_tags.operator_run_id != app_run:
            _fail("accepted_runtime_invalid")
        resource_reply = clients["cloudformation"].describe_stack_resources(StackName=app_stack)
        rows = resource_reply.get("StackResources") if hosted._ok_response(resource_reply) else None
        if not isinstance(rows, list) or len(rows) != 19:
            _fail("accepted_runtime_invalid")
        by_name = {row.get("LogicalResourceId"): row for row in rows if isinstance(row, Mapping)}
        if (len(by_name) != 19 or any(
            row.get("StackId") != app_stack or row.get("StackName") != "honda-mapit-mcp-dev-retained"
            or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            for row in by_name.values()
        )):
            _fail("accepted_runtime_invalid")
        accepted_events_reply = clients["cloudformation"].describe_stack_events(StackName=app_stack)
        if not hosted._ok_response(accepted_events_reply):
            _fail("accepted_runtime_invalid")
        if not _has_exact_accepted_completion_event(
            accepted_events_reply, stack_arn=app_stack,
            token=accepted_runtime_binding["token"],
            start=accepted_runtime_binding["start"], end=accepted_runtime_binding["end"],
        ):
            _fail("accepted_runtime_invalid")
        api_id, pool_id, client_id = (by_name.get(name, {}).get("PhysicalResourceId")
                                      for name in ("McpApi", "McpUserPool", "McpUserPoolClient"))
        if (type(api_id) is not str or hosted._API.fullmatch(api_id) is None
            or type(pool_id) is not str or hosted._POOL.fullmatch(pool_id) is None
            or type(client_id) is not str or hosted._CLIENT.fullmatch(client_id) is None):
            _fail("accepted_runtime_invalid")
        role_template = build_cd_retained_dev_multiuser_roles(**role_values, observed_user_pool_id=pool_id)
        if verify_role_pair({"iam": clients["iam"]}, role_template, account=auth["account"],
                            roles_stack_arn=roles_stack, original_creation_run_id=roles_run).get("success") is not True:
            _fail("setup_readback_failed")
        current_template_reply = clients["cloudformation"].get_template(StackName=app_stack, TemplateStage="Original")
        if not hosted._ok_response(current_template_reply):
            _fail("accepted_runtime_invalid")
        current_body = hosted._strict_template_body(current_template_reply.get("TemplateBody"))
        if not isinstance(current_body, dict) or current_body.get("Resources", {}).get("McpApi", {}).get("Properties", {}).get("DisableExecuteApiEndpoint") is not True:
            _fail("accepted_runtime_invalid")
        env = clients["lambda"].get_function_configuration(FunctionName=FUNCTION)
        variables = env.get("Environment", {}).get("Variables", {}) if isinstance(env, Mapping) else {}
        start_text, end_text = variables.get("MAPIT_DEV_EXECUTION_START_EPOCH"), variables.get("MAPIT_DEV_EXECUTION_END_EPOCH")
        if (type(start_text) is not str or not start_text.isdecimal()
            or type(end_text) is not str or not end_text.isdecimal()):
            _fail("accepted_runtime_invalid")
        prior_start, prior_end = int(start_text), int(end_text)
        accepted_manifest_path = checked_paths["accepted_artifact_dir"] / "manifest.json"
        accepted_jwks_path = checked_paths["accepted_artifact_dir"] / "jwks.json"
        accepted_zip = checked_paths["accepted_artifact_dir"] / "runtime.zip"
        manifest_raw = _read_bounded_private_file(accepted_manifest_path, MAX_MANIFEST_BYTES, acl_checker=acl_checker)
        accepted_manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
        manifest = parse_manifest(manifest_raw, expected_digest=accepted_manifest_sha, account_id=auth["account"])
        lineage = validate_accepted_pair_lineage(
            **journals, account=auth["account"], pool=pool_id, accepted_manifest=manifest)
        accepted_binding = lineage["accepted_runtime_binding"]
        if (accepted_binding.get("stack") != app_stack or accepted_binding.get("source") != manifest.get("source_sha")
            or not accepted_binding.get("start") <= prior_start < prior_end <= accepted_binding.get("end")
            or accepted_binding.get("target") != hashlib.sha256(json.dumps(current_body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()):
            _fail("accepted_runtime_invalid")
        # Reconstruct the exact prior target from the accepted artifact and the
        # currently read-back execution window; no filename-derived trust.
        accepted_jwks = _read_bounded_private_file(accepted_jwks_path, 32 * 1024, acl_checker=acl_checker)
        accepted_zip_raw = _read_bounded_private_file(accepted_zip, 16 * 1024 * 1024, acl_checker=acl_checker)
        accepted_receipt = MultiuserBuildReceipt(
            source_sha=manifest.get("source_sha"), api_id=api_id, user_pool_id=pool_id,
            client_id=client_id, jwks_sha256=hashlib.sha256(accepted_jwks).hexdigest(),
            manifest_sha256=accepted_manifest_sha, zip_sha256=hashlib.sha256(accepted_zip_raw).hexdigest(),
            archive_path=accepted_zip, execution_start_epoch=prior_start, execution_end_epoch=prior_end,
        )
        _body, parsed_manifest = _read_multiuser_archive(accepted_receipt, account_id=auth["account"], acl_checker=acl_checker)
        prior_template = build_multiuser_candidate_template(
            accepted_receipt, account_id=auth["account"], bucket=role_values["artifact_bucket_arn"].split(":::", 1)[-1],
            callback_url=hosted.CALLBACK_URL,
            subjects=(parsed_manifest["tenants"][0]["subject"], parsed_manifest["tenants"][1]["subject"]),
            tenant_keys=(parsed_manifest["tenants"][0]["key"], parsed_manifest["tenants"][1]["key"]),
        )
        if not hosted._same(current_body, prior_template):
            _fail("accepted_runtime_invalid")
        original_setup_template = build_retained_dev_multiuser_setup(
            api_id=api_id, callback_url=hosted.CALLBACK_URL)
        prior_binding_digest = hashlib.sha256(json.dumps(
            original_setup_template, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        if accepted_binding.get("prior") != prior_binding_digest:
            _fail("accepted_runtime_invalid")
        expected_resource_types = {name: value.get("Type") for name, value in prior_template["Resources"].items()}
        if (set(by_name) != set(expected_resource_types)
            or any(by_name[name].get("ResourceType") != expected_resource_types[name] for name in expected_resource_types)):
            _fail("accepted_runtime_invalid")
        setup_result = verify_closed_setup(
            {key: clients[key] for key in ("cloudformation", "cognito", "apigateway", "dynamodb")},
            account=auth["account"], stack_arn=app_stack, api_id=api_id,
            user_pool_id=pool_id, client_id=client_id, callback_url=hosted.CALLBACK_URL,
            original_creation_run_id=app_run,
            table_arn=f"arn:aws:dynamodb:{REGION}:{auth['account']}:table/honda-mapit-mcp-dev-tenants",
            expected_runtime_template=prior_template,
            expected_route_keys=(
                "POST /mcp", "GET /.well-known/oauth-protected-resource/mcp",
                "GET /.well-known/oauth-authorization-server",
            ),
        )
        if setup_result.get("success") is not True:
            _fail("accepted_runtime_invalid")
        _verify_multiuser_runtime_children(
            clients, prior_template, by_name, account=auth["account"], api_id=api_id,
        )
        # Exact accepted function and closed state, plus no pre-existing item
        # at either fresh key, are mandatory before creating a new artifact.
        quota = clients["lambda"].get_account_settings()
        concurrency = clients["lambda"].get_function_concurrency(FunctionName=FUNCTION)
        api = clients["apigatewayv2"].get_api(ApiId=api_id)
        function = clients["lambda"].get_function_configuration(FunctionName=FUNCTION)
        limits = quota.get("AccountLimit", {}) if isinstance(quota, Mapping) else {}
        if (not hosted._ok_response(quota) or limits.get("ConcurrentExecutions") != 10
            or limits.get("UnreservedConcurrentExecutions") != 10
            or not hosted._ok_response(concurrency) or concurrency.get("ReservedConcurrentExecutions") != 0
            or not hosted._ok_response(api) or api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
            or function.get("FunctionName") != FUNCTION or function.get("Handler") != "mapit.aws_dev_multiuser_entrypoint.handler"):
            _fail("accepted_runtime_invalid")
        # Verify the currently deployed archive/environment/tags, not merely
        # the historical template, before the first new S3 or CFN write.
        _verify_new_runtime(clients, accepted_receipt, parsed_manifest, role_values,
                            app_stack, app_run, api_id, auth["account"], acl_checker=acl_checker)
        _run_private_infrastructure_preflight(clients, auth["account"], app_stack, app_run,
                                              controls_stack, controls_run, artifact_stack,
                                              artifact_run, role_values, api_id)
        # Read the same users/subjects from Cognito and bind them to the
        # accepted reset journal before package creation.
        accepted_user_state = journals["accepted_users"].load()
        run_id = accepted_user_state["run_id"]
        usernames = tuple(row["username"] for row in accepted_user_state["slots"])
        if len(usernames) != 2:
            _fail("history_invalid")
        subjects = hosted._user_rows(clients["cognito"], pool=pool_id, usernames=(usernames[0], usernames[1]))
        if any(hashlib.sha256(subject.encode("ascii")).hexdigest() != accepted_user_state["slots"][i]["user_sub_sha256"] for i, subject in enumerate(subjects)):
            _fail("history_invalid")
        # Fresh private workspace and fresh keys/journals; never reopen any
        # historical path and never reuse an old publication/update token.
        run_dir = _create_private_child(root / "accepted-runtime-continuation", acl_checker)
        for name in ("continuation", "artifact", "runtime", "window", "users", "reset", "recovery", "tenant-a", "tenant-b", "revocation"):
            _create_private_child(run_dir / name, acl_checker)
        # The exact 19-resource role grants LeadingKeys to the accepted keys.
        # Reuse those exact keys only after a strong read proves neither row
        # exists; changing them would require an IAM/template update.
        keys = tuple(row["key"] for row in parsed_manifest["tenants"])
        existing_store = DynamoDBTenantStore(
            clients["dynamodb"], table_arn=parsed_manifest["table_arn"],
            allowed_keys=keys, writer=clients["dynamodb"],
        )
        if any(existing_store.get(key) is not None for key in keys):
            _fail("accepted_runtime_invalid")
        stage = "package"
        jwks, jwks_sha = jwks_fetcher(user_pool_id=pool_id)
        if hashlib.sha256(jwks).hexdigest() != parsed_manifest.get("jwks_sha256"):
            _fail("archive_failed")
        manifest = {
            "schema": 1, "builder": "build_retained_dev_multiuser_archive", "environment": "dev", "synthetic": True,
            "source_sha": auth["source_sha"], "api_id": api_id, "user_pool_id": pool_id, "client_id": client_id,
            "jwks_sha256": jwks_sha,
            "table_arn": f"arn:aws:dynamodb:{REGION}:{auth['account']}:table/honda-mapit-mcp-dev-tenants",
            "tenants": [{"key": keys[i], "subject": subjects[i], "label": f"synthetic-{chr(65+i)}"} for i in range(2)],
        }
        manifest_raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        manifest_path, jwks_path, archive_path = (run_dir / "artifact" / name for name in ("manifest.json", "jwks.json", "runtime.zip"))
        _write_private(manifest_path, manifest_raw); _write_private(jwks_path, jwks)
        summary = archive_factory(checked_paths["wheel_dir"], manifest_path, jwks_path, archive_path, account_id=auth["account"])
        if (not archive_path.is_file() or getattr(summary, "manifest_valid", False) is not True
            or getattr(summary, "source_allowlist_valid", False) is not True
            or getattr(summary, "dependencies_valid", False) is not True
            or getattr(summary, "lock_valid", False) is not True):
            _fail("archive_failed")
        # Leave a bounded reset/login interval after the closed update while
        # keeping the deployed test window fixed at five minutes.
        now = _safe_now(clock)
        # Allow up to the existing five-minute CFN readback budget, then a
        # separate five-minute A/B reset/login window, plus a one-minute
        # handoff margin before the fixed five-minute HTTP test window.
        runtime_start = now + 660
        runtime_end = runtime_start + RUNTIME_SECONDS
        if runtime_end >= auth["end"]:
            _fail("window_expired")
        receipt = MultiuserBuildReceipt(
            source_sha=auth["source_sha"], api_id=api_id, user_pool_id=pool_id, client_id=client_id,
            jwks_sha256=jwks_sha, manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            zip_sha256=summary.sha256, archive_path=archive_path,
            execution_start_epoch=runtime_start, execution_end_epoch=runtime_end,
        )
        _read_multiuser_archive(receipt, account_id=auth["account"], acl_checker=acl_checker)
        target_template = build_multiuser_candidate_template(
            receipt, account_id=auth["account"], bucket=role_values["artifact_bucket_arn"].split(":::", 1)[-1],
            callback_url=hosted.CALLBACK_URL, subjects=subjects, tenant_keys=keys,
        )
        if not _only_artifact_source_window_delta(prior_template, target_template):
            _fail("archive_failed")
        artifact_journal = CasFileJournal(run_dir / "artifact")
        continuation_journal = FileJournal(run_dir / "continuation")
        if continuation_journal.load() is not None:
            _fail("accepted_runtime_invalid")
        continuation_journal.save({
            "schema": 1, "phase": "publish_intent", "source_sha": auth["source_sha"],
            "accepted_runtime_sha256": hashlib.sha256(json.dumps(accepted_runtime_binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "artifact_sha256": receipt.zip_sha256, "authorization_run_id": auth["run_id"],
            "run_id": str(uuid.uuid4()),
        })
        stage = "publish"
        published = publish_multiuser_candidate(
            clients["s3"], artifact_journal, receipt, account_id=auth["account"],
            bucket=role_values["artifact_bucket_arn"].split(":::", 1)[-1],
            run_id=str(uuid.uuid4()), authorized_from_epoch=auth["start"],
            authorized_until_epoch=auth["end"], wall_clock=clock, monotonic=monotonic,
            archive_acl_checker=acl_checker,
        )
        if (published.get("success") is not True
            or published.get("category") != "artifact_uploaded_verified"
            or published.get("head_verified") is not True):
            _fail("publish_failed")
        continuation_state = continuation_journal.load()
        if not isinstance(continuation_state, Mapping) or continuation_state.get("phase") != "publish_intent":
            _fail("publish_failed")
        continuation_state = dict(continuation_state)
        continuation_state["phase"] = "published"
        continuation_journal.save(continuation_state)
        # The direct core accepts an explicit exact prior 19-resource template;
        # the normal 11->19 runner remains untouched.
        update_journal = CasFileJournal(run_dir / "runtime")
        updater = ClosedDevUpdate(
            {key: clients[key] for key in ("sts", "cloudformation", "lambda", "apigatewayv2")},
            update_journal, account=auth["account"], caller_arn=auth["expected_caller_arn"],
            stack_arn=app_stack, prior_template=prior_template, target_template=target_template,
            service_role_arn=f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update",
            source_sha=auth["source_sha"], start=auth["start"], end=auth["end"],
            token="dev-multiuser-" + secrets.token_hex(16), clock=clock,
        )
        stage = "runtime_update"
        if not updater.run("preflight").get("ok") or not updater.run("update").get("ok"):
            _fail("runtime_update_failed")
        accepted = False
        for _ in range(hosted.MAX_CFN_POLLS):
            result = updater.run("readback")
            if result.get("phase") == "accepted":
                accepted = True
                break
            if result.get("phase") != "pending" or _safe_now(clock) >= auth["end"]:
                break
            sleep(hosted.CFN_POLL_SECONDS)
        if not accepted:
            _fail("runtime_update_failed")
        continuation_state = continuation_journal.load()
        if not isinstance(continuation_state, Mapping) or continuation_state.get("phase") != "published":
            _fail("runtime_update_failed")
        continuation_state = dict(continuation_state)
        continuation_state["phase"] = "runtime_accepted"
        continuation_journal.save(continuation_state)
        _verify_new_runtime(clients, receipt, manifest, role_values, app_stack, app_run, api_id, auth["account"], acl_checker=acl_checker)
        # Now consume exactly one newly authorized reset/login per existing A/B.
        reset_start = _safe_now(clock)
        if runtime_start - reset_start < 330:
            _fail("window_expired")
        reset_end = min(auth["end"], reset_start + 300)
        fresh_users = FileJournal(run_dir / "users")
        reset_journal = FileJournal(run_dir / "reset")
        provenance = FileJournal(run_dir / "recovery")
        stage = "reset"
        reset_prepared = prepare_confirmed_pair_reset(
            clients={"cognito": clients["cognito"]},
            original_creation_journal=FileJournal(checked_paths["original_creation_users_path"]),
            latest_pair_journal=FileJournal(checked_paths["first_pair_users_path"]),
            fresh_user_journal=fresh_users, reset_journal=reset_journal, provenance_journal=provenance,
            account=auth["account"], user_pool_id=pool_id, source_sha256=auth["source_sha"],
            authorized_from_epoch=reset_start, authorized_until_epoch=reset_end,
            allow_two_confirmed_user_resets=True,
            first_confirmed_pair_sha256=lineage["first_pair_sha256"],
            previous_reset_sha256=lineage["accepted_reset_sha256"],
            consumed_pair_sha256=lineage["accepted_pair_sha256"], wall_clock=clock,
        )
        if reset_prepared.get("success") is not True:
            _fail("user_preflight_failed")
        # A reset operator invokes the reviewed one-shot A-then-B password and
        # Managed Login flow. Credentials/tokens are intentionally ephemeral.
        domain = f"honda-mapit-mcp-dev-multiuser-{auth['account']}.auth.eu-west-1.amazoncognito.com"
        resource = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
        def make_client():
            factory = login_client_factory or ManagedLoginClient
            return factory(account_id=auth["account"], domain=domain, client_id=client_id,
                           callback_url=hosted.CALLBACK_URL, resource=resource, required_scope=resource + "/use")
        stage = "login"
        dry = make_client().dry_login_page()
        if dry.get("success") is not True:
            _fail("login_page_failed")
        def receive_token(username: str, token: Any) -> None:
            if type(username) is not str or not hasattr(token, "access_token"):
                _fail("login_failed")
            token_map[username] = token.access_token
        class ResetLoginOperator:
            def provision(self, *, on_confirmed_user):
                return reset_confirmed_pair_once(
                    clients={"cognito": clients["cognito"]}, fresh_user_journal=fresh_users,
                    reset_journal=reset_journal, account=auth["account"], user_pool_id=pool_id,
                    run_id=fresh_users.load()["run_id"], source_sha256=auth["source_sha"],
                    authorized_from_epoch=reset_start, authorized_until_epoch=reset_end,
                    allow_two_confirmed_user_resets=True, on_confirmed_user=on_confirmed_user,
                    wall_clock=clock,
                )
        logins = provision_and_login_pair(ResetLoginOperator(), make_client, on_tokens=receive_token)
        if logins.get("category") != "users_authenticated" or set(token_map) != set(usernames):
            _fail("login_failed")
        new_state = fresh_users.load()
        new_subjects = hosted._user_rows(clients["cognito"], pool=pool_id, usernames=(usernames[0], usernames[1]))
        for i, username in enumerate(usernames):
            _verify_token = hosted._verify_token
            _verify_token(token_map[username], subject=new_subjects[i], pool=pool_id, api_id=api_id,
                          client_id=client_id, jwks=jwks)
            if hashlib.sha256(new_subjects[i].encode("ascii")).hexdigest() != new_state["slots"][i]["user_sub_sha256"]:
                _fail("token_invalid")
        # The built package's subjects must still match; a Cognito subject
        # change cannot be silently rebound to this deployment.
        if tuple(new_subjects) != tuple(subjects):
            _fail("token_invalid")
        stage = "arm_probe"
        if _run_arm_probe(archive_path, manifest, receipt, token_map, new_state, clock=clock):
            _fail("archive_failed")
        machine = f"arn:aws:states:{REGION}:{auth['account']}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
        stage = "window"
        while _safe_now(clock) < runtime_start:
            sleep(min(1.0, runtime_start - _safe_now(clock)))
        if _safe_now(clock) + 150 >= runtime_end:
            _fail("window_expired")
        window = DevTestWindow(
            {key: clients[key] for key in ("lambda", "apigatewayv2", "stepfunctions")},
            FileJournal(run_dir / "window"), account=auth["account"], api_id=api_id,
            machine_arn=machine, source_sha=auth["source_sha"], run_id=uuid.uuid4().hex,
            execution_start=runtime_start, execution_end=runtime_end, clock=clock,
        )
        if window.preflight().get("success") is not True:
            _fail("window_failed")
        opened = True
        if window.open().get("success") is not True:
            _fail("window_failed")
        store = DynamoDBTenantStore(clients["dynamodb"], table_arn=manifest["table_arn"], allowed_keys=keys, writer=clients["dynamodb"])
        tenant_store, tenant_a_key = store, keys[0]
        revocation_journal = FileJournal(run_dir / "revocation")
        stage = "tenant_write"
        if not hosted._tenant_write(store, FileJournal(run_dir / "tenant-a"), keys[0]):
            _fail("tenant_write_failed")
        # The retained table is explicitly capped at one write request unit.
        # Pace the two one-shot activations instead of relying on burst
        # capacity, then recheck the fixed window before the second write.
        sleep(1.1)
        try:
            window._guard()
        except Exception:
            _fail("window_expired")
        if _safe_now(clock) + 150 >= runtime_end:
            _fail("window_expired")
        if not hosted._tenant_write(store, FileJournal(run_dir / "tenant-b"), keys[1]):
            _fail("tenant_write_failed")
        stage = "http_acceptance"
        accept = (http_acceptance or run_http_acceptance)(api_id=api_id, token_a=token_map[usernames[0]],
                   token_b=token_map[usernames[1]], revoke_a=lambda: hosted._tenant_write(store, revocation_journal, keys[0], revoked=True))
        safe_http_result = _safe_http_receipt(accept)
        if (accept.get("success") is not True
            or safe_http_result.get("success") is not True
            or safe_http_result.get("category") != "http_acceptance_verified"):
            _fail("http_acceptance_failed")
        stage = "close"
        if window.close().get("success") is not True:
            _fail("closure_unverified")
        final_update = updater.run("readback")
        if final_update.get("phase") != "accepted":
            _fail("closure_unverified")
        final_resource_reply = clients["cloudformation"].describe_stack_resources(StackName=app_stack)
        final_rows = final_resource_reply.get("StackResources") if hosted._ok_response(final_resource_reply) else None
        if not _same_resource_inventory(final_rows, by_name, app_stack):
            _fail("closure_unverified")
        _verify_new_runtime(clients, receipt, manifest, role_values, app_stack,
                            app_run, api_id, auth["account"], acl_checker=acl_checker)
        opened = False
        return {"success": True, "category": "accepted_runtime_multiuser_verified", "stage": "complete",
                "checks": {"history": True, "accepted_runtime": True, "fresh_update": True,
                           "pair_reset_login": True, "arm_candidate": True, "window": True,
                           "tenants": True, "http": True, "closure": True}}
    except AcceptedContinuationError as exc:
        result = {"success": False, "category": exc.category, "stage": stage}
        if safe_http_result is not None:
            result["http"] = safe_http_result
        return result
    except Exception:
        result = {"success": False, "category": "runner_failed", "stage": stage}
        if safe_http_result is not None:
            result["http"] = safe_http_result
        return result
    finally:
        try:
            if tenant_store is not None and tenant_a_key is not None and revocation_journal is not None:
                hosted._tenant_write(tenant_store, revocation_journal, tenant_a_key, revoked=True)
        except Exception:
            pass
        if opened and window is not None:
            try:
                window.close()
            except Exception:
                pass
        token_map.clear()


def _run_private_infrastructure_preflight(clients, account, app_stack, app_run, controls_stack, controls_run, artifact_stack, artifact_run, role_values, api_id):
    hosted._run_v2_infrastructure_preflight(
        clients, account=account,
        app_stack=app_stack, app_run=app_run,
        controls_stack=controls_stack, controls_run=controls_run,
        artifact_stack=artifact_stack, artifact_run=artifact_run,
        artifact_bucket=role_values["artifact_bucket_arn"].split(":::", 1)[-1],
        api_id=api_id, callback_url=hosted.CALLBACK_URL,
    )


def _create_private_child(path: Path, acl_checker) -> Path:
    try:
        _create_private_directory(path, acl_checker=acl_checker)
        return validate_private_location(path, acl_checker=acl_checker)
    except Exception:
        _fail("private_acl_invalid")


def _path_contains(parent: Path, child: Path) -> bool:
    try:
        return child.resolve(strict=True).is_relative_to(parent.resolve(strict=True))
    except Exception:
        return True


def _read_bounded_private_file(path: Path, limit: int, *, acl_checker=None) -> bytes:
    try:
        safe = validate_private_location(path, acl_checker=acl_checker)
        if safe.is_symlink() or not safe.is_file() or type(limit) is not int or limit <= 0:
            raise ValueError
        size = safe.stat().st_size
        if not 0 < size <= limit:
            raise ValueError
        with safe.open("rb") as stream:
            value = stream.read(limit + 1)
        if len(value) != size or len(value) > limit:
            raise ValueError
        return value
    except Exception:
        _fail("accepted_runtime_invalid")


def _write_private(path: Path, body: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(body)
    except Exception:
        _fail("private_acl_invalid")


def _safe_now(clock) -> int:
    try:
        value = clock()
        if type(value) not in (int, float) or isinstance(value, bool) or value <= 0:
            raise ValueError
        import math
        if not math.isfinite(value):
            raise ValueError
        return int(value)
    except Exception:
        _fail("window_expired")


def _template_diff_paths(before: Any, after: Any, prefix: tuple[str, ...] = ()) -> set[tuple[str, ...]]:
    if type(before) is dict and type(after) is dict:
        if set(before) != set(after):
            return {prefix + ("<keys>",)}
        changed: set[tuple[str, ...]] = set()
        for key in before:
            changed.update(_template_diff_paths(before[key], after[key], prefix + (str(key),)))
        return changed
    if type(before) is list and type(after) is list:
        if len(before) != len(after):
            return {prefix + ("<length>",)}
        changed: set[tuple[str, ...]] = set()
        for index, (left, right) in enumerate(zip(before, after)):
            changed.update(_template_diff_paths(left, right, prefix + (str(index),)))
        return changed
    return set() if before == after and type(before) is type(after) else {prefix}


def _same_resource_inventory(rows: Any, initial: Mapping[str, Mapping[str, Any]], stack_arn: str) -> bool:
    if type(rows) is not list or len(rows) != 19 or len(initial) != 19:
        return False
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            return False
        logical = row.get("LogicalResourceId")
        prior = initial.get(logical) if type(logical) is str else None
        if (prior is None or logical in seen or row.get("StackId") != stack_arn
            or row.get("StackName") != "honda-mapit-mcp-dev-retained"
            or row.get("ResourceType") != prior.get("ResourceType")
            or row.get("PhysicalResourceId") != prior.get("PhysicalResourceId")
            or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}):
            return False
        seen.add(logical)
    return seen == set(initial)


def _has_exact_accepted_completion_event(events: Any, *, stack_arn: str, token: str,
                                        start: int, end: int) -> bool:
    """Match the accepted update in one bounded event page only.

    A continuation token is deliberately ignored; this path neither paginates
    historical events nor persists/echoes provider pagination state.
    """
    if not isinstance(events, Mapping):
        return False
    # NextToken may legitimately be present on the first bounded page. It is
    # intentionally not inspected or followed.
    rows = events.get("StackEvents")
    if type(rows) is not list or not 1 <= len(rows) <= 100:
        return False
    matches = 0
    for event in rows:
        if not isinstance(event, Mapping):
            continue
        timestamp = event.get("Timestamp")
        if (event.get("StackId") == stack_arn
            and event.get("StackName") == "honda-mapit-mcp-dev-retained"
            and event.get("PhysicalResourceId") == stack_arn
            and event.get("ResourceType") == "AWS::CloudFormation::Stack"
            and event.get("ResourceStatus") == "UPDATE_COMPLETE"
            and event.get("ClientRequestToken") == token
            and isinstance(timestamp, datetime) and timestamp.tzinfo is not None
            and timestamp.utcoffset() is not None):
            try:
                if start <= timestamp.timestamp() < end:
                    matches += 1
            except (OverflowError, OSError, ValueError):
                return False
    return matches == 1


def _only_artifact_source_window_delta(prior: Any, target: Any) -> bool:
    """Allow only the immutable package pointer, source digest and runtime window."""
    allowed = {
        ("Resources", "McpHandler", "Properties", "Code", "S3Key"),
        ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_SOURCE_SHA256"),
        ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256"),
        ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_EXECUTION_START_EPOCH"),
        ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_EXECUTION_END_EPOCH"),
        ("Metadata", "SourceSha256"),
        ("Metadata", "ManifestSha256"),
        ("Metadata", "ExecutionStartEpoch"),
        ("Metadata", "ExecutionEndEpoch"),
        ("Metadata", "ManifestContract", "source_sha"),
    }
    try:
        changed = _template_diff_paths(prior, target)
        required = {
            ("Resources", "McpHandler", "Properties", "Code", "S3Key"),
            ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_SOURCE_SHA256"),
            ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256"),
            ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_EXECUTION_START_EPOCH"),
            ("Resources", "McpHandler", "Properties", "Environment", "Variables", "MAPIT_DEV_EXECUTION_END_EPOCH"),
        }
        return bool(changed) and changed <= allowed and required <= changed
    except Exception:
        return False


def _safe_http_receipt(value: Any) -> dict[str, Any]:
    """Project the E2E receipt onto bounded, known-safe fields only."""
    if not isinstance(value, Mapping) or type(value.get("success")) is not bool:
        return {"success": False, "category": "http_receipt_invalid"}
    categories = {
        "http_acceptance_verified", "http_acceptance_failed", "binding_invalid",
        "clock_invalid", "budget_exhausted", "pacing_failed", "transport_failed",
        "endpoint_mismatch", "protocol_invalid",
    }
    stages = {
        "before_start", "before_rpc", "after_settling", "after_pacing", "after_transport",
        "initialize", "tools_list", "tenant_a_status", "tenant_a_distance", "tenant_b_status",
        "tenant_b_distance", "foreign_route", "anonymous_access", "revocation",
        "after_revocation", "revoked_a_access", "tenant_b_after_revocation", "unexpected",
    }
    checks_allowed = {
        "initialize", "tools_exact", "tenant_a_status", "tenant_a_distance",
        "tenant_b_status", "tenant_b_distance", "foreign_route_denied",
        "anonymous_denied", "revocation_committed", "revoked_a_denied", "b_after_a_revocation",
    }
    if value["success"] is True:
        checks = value.get("checks")
        if (value.get("category") != "http_acceptance_verified"
            or "failure_stage" in value
            or type(value.get("calls")) is not int or value.get("calls") != 10
            or not isinstance(checks, Mapping)
            or set(checks) != checks_allowed
            or any(type(checks[key]) is not bool or checks[key] is not True for key in checks_allowed)):
            return {"success": False, "category": "http_receipt_invalid"}
    result: dict[str, Any] = {
        "success": value["success"],
        "category": value.get("category") if type(value.get("category")) is str and value["category"] in categories else "http_receipt_invalid",
    }
    stage = value.get("failure_stage")
    if stage is not None:
        result["failure_stage"] = stage if type(stage) is str and stage in stages else "unexpected"
    calls = value.get("calls")
    if type(calls) is int and 0 <= calls <= 12:
        result["calls"] = calls
    else:
        result["calls"] = 0
    status = value.get("http_status")
    if type(status) is int and 100 <= status <= 599:
        result["http_status"] = status
    checks = value.get("checks")
    if isinstance(checks, Mapping):
        result["checks"] = {key: item for key, item in checks.items()
                             if type(key) is str and key in checks_allowed and type(item) is bool}
    else:
        result["checks"] = {}
    return result


def _verify_new_runtime(clients, receipt, manifest, role_values, app_stack, app_run, api_id, account, *, acl_checker=None):
    if (not isinstance(manifest, Mapping) or manifest.get("source_sha") != receipt.source_sha
        or manifest.get("api_id") != api_id or manifest.get("jwks_sha256") != receipt.jwks_sha256
        or manifest.get("user_pool_id") != receipt.user_pool_id
        or manifest.get("client_id") != receipt.client_id):
        _fail("runtime_readback_failed")
    config = clients["lambda"].get_function_configuration(FunctionName=FUNCTION)
    function = clients["lambda"].get_function(FunctionName=FUNCTION)
    concurrency = clients["lambda"].get_function_concurrency(FunctionName=FUNCTION)
    api = clients["apigatewayv2"].get_api(ApiId=api_id)
    expected = {
        "MAPIT_MCP_ENV": "dev", "MAPIT_DEV_MULTIUSER_MODE": "synthetic",
        "MAPIT_SOURCE_SHA256": receipt.source_sha,
        "MAPIT_COGNITO_JWKS_SHA256": receipt.jwks_sha256,
        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": receipt.manifest_sha256,
        "MAPIT_DEV_EXPECTED_ACCOUNT_ID": account,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(receipt.execution_start_epoch),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(receipt.execution_end_epoch),
        "MAPIT_COGNITO_USER_POOL_ID": receipt.user_pool_id,
        "MAPIT_COGNITO_CLIENT_ID": receipt.client_id,
        "MAPIT_OBSERVED_API_ID": api_id,
    }
    cfg = function.get("Configuration", {}) if isinstance(function, Mapping) else {}
    code_sha = cfg.get("CodeSha256")
    expected_function_arn = f"arn:aws:lambda:{REGION}:{account}:function:{FUNCTION}"
    if (not hosted._ok_response(config) or config.get("FunctionName") != FUNCTION
        or config.get("State") != "Active"
        or config.get("Runtime") != "python3.13" or config.get("Handler") != "mapit.aws_dev_multiuser_entrypoint.handler"
        or config.get("Architectures") != ["arm64"] or config.get("MemorySize") != 256
        or config.get("Timeout") != 20 or config.get("Environment", {}).get("Variables") != expected
        or not hosted._ok_response(concurrency) or concurrency.get("ReservedConcurrentExecutions") != 0
        or not hosted._ok_response(api) or api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
        or not hosted._ok_response(function) or type(code_sha) is not str
        or cfg.get("FunctionArn") != expected_function_arn
        or cfg.get("FunctionName") != FUNCTION
        or cfg.get("Role") != f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-handler-role"):
        _fail("runtime_readback_failed")
    lambda_tags = hosted._read_lambda_tags(
        clients["lambda"], function_arn=expected_function_arn, account=account,
    )
    creation_tags = hosted.RetainedDevStackCreationTags.from_receipt(
        stack_kind="app", stack_arn=app_stack, account_id=account,
        tags=[
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev"},
            {"Key": "OperatorRunId", "Value": str(app_run)},
        ],
    )
    expected_tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"},
    ]
    if not hosted._owned_resource_tags(lambda_tags, expected_tags, stack=creation_tags, logical_id="McpHandler"):
        _fail("runtime_readback_failed")
    body = _read_bounded_private_file(receipt.archive_path, 16 * 1024 * 1024, acl_checker=acl_checker)
    if base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") != code_sha:
        _fail("runtime_readback_failed")
    bucket = role_values["artifact_bucket_arn"].split(":::", 1)[-1]
    head = clients["s3"].head_object(
        Bucket=bucket, Key=f"runtime/{receipt.zip_sha256}.zip",
        ExpectedBucketOwner=account, ChecksumMode="ENABLED",
    )
    expected_checksum = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    if (not hosted._ok_response(head) or head.get("ServerSideEncryption") != "AES256"
        or type(head.get("ContentLength")) is not int or head["ContentLength"] != len(body)
        or head.get("ChecksumSHA256") != expected_checksum):
        _fail("runtime_readback_failed")


def _verify_multiuser_runtime_children(clients, template, resource_rows, *, account, api_id):
    """Bind the closed 19-resource app's API children and Lambda role.

    This is a small continuation-specific layer atop the retained-dev setup
    verifier: that verifier checks the Cognito and table configuration, while
    this function binds the three routes, JWT authorizer, integration, invoke
    policy, and exact function execution role to the same 19-resource factory.
    """
    try:
        resources = template["Resources"]
        rows = resource_rows
        function_arn = f"arn:aws:lambda:{REGION}:{account}:function:{FUNCTION}"
        resource_uri = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"

        def read(service, method, **kwargs):
            response = getattr(clients[service], method)(**kwargs)
            if not hosted._ok_response(response):
                _fail("accepted_runtime_invalid")
            return response

        def exact_single_items(reply):
            items = reply.get("Items")
            if type(items) is not list or len(items) != 1 or reply.get("NextToken") not in (None, "") or not isinstance(items[0], Mapping):
                _fail("accepted_runtime_invalid")
            return items[0]

        authorizer = exact_single_items(read("apigatewayv2", "get_authorizers", ApiId=api_id, MaxResults="100"))
        authorizer_id = rows["McpJwtAuthorizer"].get("PhysicalResourceId")
        expected_issuer = f"https://cognito-idp.{REGION}.amazonaws.com/{rows['McpUserPool'].get('PhysicalResourceId')}"
        if (authorizer.get("AuthorizerId") != authorizer_id
            or authorizer.get("AuthorizerType") != "JWT"
            or authorizer.get("IdentitySource") != ["$request.header.Authorization"]
            or authorizer.get("JwtConfiguration") != {"Issuer": expected_issuer, "Audience": [resource_uri]}):
            _fail("accepted_runtime_invalid")

        integration = exact_single_items(read("apigatewayv2", "get_integrations", ApiId=api_id, MaxResults="100"))
        integration_id = rows["McpLambdaIntegration"].get("PhysicalResourceId")
        expected_integration_uri = f"arn:aws:apigateway:{REGION}:lambda:path/2015-03-31/functions/{function_arn}/invocations"
        if (integration.get("IntegrationId") != integration_id
            or integration.get("IntegrationType") != "AWS_PROXY"
            or integration.get("IntegrationMethod") != "POST"
            or integration.get("PayloadFormatVersion") != "2.0"
            or integration.get("TimeoutInMillis") != 20000
            or integration.get("IntegrationUri") not in {
                expected_integration_uri, function_arn,
            }):
            _fail("accepted_runtime_invalid")

        routes_reply = read("apigatewayv2", "get_routes", ApiId=api_id, MaxResults="100")
        route_rows = routes_reply.get("Items")
        route_expectations = {
            "POST /mcp": ("McpPostRoute", "JWT", authorizer_id, [resource_uri + "/use"]),
            "GET /.well-known/oauth-protected-resource/mcp": ("McpProtectedResourceMetadataRoute", "NONE", None, None),
            "GET /.well-known/oauth-authorization-server": ("McpAuthorizationServerMetadataRoute", "NONE", None, None),
        }
        if (type(route_rows) is not list or len(route_rows) != 3
            or routes_reply.get("NextToken") not in (None, "")
            or any(not isinstance(item, Mapping) for item in route_rows)):
            _fail("accepted_runtime_invalid")
        by_route = {item.get("RouteKey"): item for item in route_rows}
        if set(by_route) != set(route_expectations):
            _fail("accepted_runtime_invalid")
        for route_key, (logical_id, auth_type, expected_authorizer, scopes) in route_expectations.items():
            route = by_route[route_key]
            actual_scopes = route.get("AuthorizationScopes")
            scopes_match = (
                actual_scopes == scopes if scopes is not None
                else actual_scopes is None or type(actual_scopes) is list and actual_scopes == []
            )
            if (route.get("RouteId") != rows[logical_id].get("PhysicalResourceId")
                or route.get("AuthorizationType") != auth_type
                or route.get("AuthorizerId") != expected_authorizer
                or not scopes_match
                or route.get("Target") != f"integrations/{integration_id}"):
                _fail("accepted_runtime_invalid")

        fn_reply = read("lambda", "get_function", FunctionName=FUNCTION)
        configuration = fn_reply.get("Configuration")
        exact_role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-handler-role"
        if (not isinstance(configuration, Mapping)
            or configuration.get("FunctionArn") != function_arn
            or configuration.get("Role") != exact_role):
            _fail("accepted_runtime_invalid")

        policy_reply = read("lambda", "get_policy", FunctionName=FUNCTION)
        policy = hosted._strict_template_body(policy_reply.get("Policy"))
        statements = policy.get("Statement") if isinstance(policy, Mapping) else None
        expected_paths = {
            "POST/mcp", "GET/.well-known/oauth-protected-resource/mcp",
            "GET/.well-known/oauth-authorization-server",
        }
        if type(statements) is not list or len(statements) != 3:
            _fail("accepted_runtime_invalid")
        seen_paths = set()
        for statement in statements:
            if not isinstance(statement, Mapping):
                _fail("accepted_runtime_invalid")
            condition = statement.get("Condition")
            source_arn = condition.get("ArnLike", {}).get("AWS:SourceArn") if isinstance(condition, Mapping) else None
            prefix = f"arn:aws:execute-api:{REGION}:{account}:{api_id}/$default/"
            path = source_arn[len(prefix):] if type(source_arn) is str and source_arn.startswith(prefix) else None
            if (path not in expected_paths or path in seen_paths
                or statement.get("Effect") != "Allow"
                or statement.get("Action") != "lambda:InvokeFunction"
                or statement.get("Resource") != function_arn
                or statement.get("Principal") != {"Service": "apigateway.amazonaws.com"}
                or condition.get("StringEquals") != {"AWS:SourceAccount": account}
                or set(statement) != {"Sid", "Effect", "Action", "Resource", "Principal", "Condition"}):
                _fail("accepted_runtime_invalid")
            seen_paths.add(path)
        if seen_paths != expected_paths:
            _fail("accepted_runtime_invalid")
    except AcceptedContinuationError:
        raise
    except Exception:
        _fail("accepted_runtime_invalid")


def _run_arm_probe(archive_path, manifest, receipt, tokens, user_state, *, clock=time.time):
    try:
        from scripts import probe_aws_dev_multiuser_arm as probe
        # The probe's mock Lambda clock must be based on the newly minted
        # tokens, not the deployed five-minute window chosen before CFN update.
        probe_start = _safe_now(clock)
        payload = {
            "checks": list(probe.CHECKS), "manifest_sha256": receipt.manifest_sha256,
            "jwks_sha256": receipt.jwks_sha256, "source_sha": receipt.source_sha,
            "user_pool_id": receipt.user_pool_id, "client_id": receipt.client_id,
            "account_id": user_state["account_id"], "api_id": receipt.api_id,
            "start": probe_start, "end": probe_start + RUNTIME_SECONDS,
            "now": probe_start + 60,
            "keys": {"a": manifest["tenants"][0]["key"], "b": manifest["tenants"][1]["key"]},
            "tokens": {"a": tokens[user_state["slots"][0]["username"]],
                       "b": tokens[user_state["slots"][1]["username"]]},
        }
        result = probe.probe_candidate_archive(archive_path, context=probe.docker_helpers._docker_context(), payload=payload)
        return result.get("success") is not True or result.get("category") != "multiuser_arm_probe_passed"
    except Exception:
        return True


__all__ = ["AcceptedContinuationInputs", "AcceptedContinuationError",
           "validate_accepted_pair_lineage", "run_accepted_runtime_continuation"]
