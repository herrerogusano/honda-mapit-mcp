"""Private source-gated runner for closed multi-user DEV setup, never PROD.

The seven-field authorization and existing exact DEV role bindings must be
operator-private files outside Git/OneDrive. Every operation gets a fresh
journal directory. This runner has no opening, user/password or tool path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles
from scripts.dev_multiuser_closed_update import ClosedDevUpdate, APP, ROLES, CONTROLS
from scripts.build_aws_retained_dev_support import build_retained_dev_controls
from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
from scripts.dev_multiuser_journal import PlainFileJournal as FileJournal
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization, validate_private_location, validate_source_and_ci, _build_clients,
)
from scripts.run_aws_retained_dev_role_bootstrap import _load_bindings
from scripts.dev_multiuser_readback import verify_role_pair, verify_closed_setup

CALLBACK = "http://localhost:39031/callback"


def _build_setup_readback_clients(base_clients):
    """Add only regional read-only Cognito/DynamoDB clients to core clients."""
    try:
        import boto3
        from botocore.config import Config
        config = Config(region_name="eu-west-1", connect_timeout=2, read_timeout=3,
                        retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        session = boto3.Session(region_name="eu-west-1")
        result = dict(base_clients)
        result["cognito"] = session.client("cognito-idp", region_name="eu-west-1", endpoint_url="https://cognito-idp.eu-west-1.amazonaws.com", config=config, verify=True)
        result["dynamodb"] = session.client("dynamodb", region_name="eu-west-1", endpoint_url="https://dynamodb.eu-west-1.amazonaws.com", config=config, verify=True)
        result["apigateway"] = result["apigatewayv2"]
        return {key: result[key] for key in ("cloudformation", "cognito", "apigateway", "dynamodb")}
    except Exception:
        raise ValueError("setup_readback_clients_failed") from None


def _load_app_binding(path, *, acl_checker=None):
    path = validate_private_location(Path(path), acl_checker=acl_checker)
    size = path.stat().st_size
    if not 0 < size <= 2048:
        raise ValueError("app_binding_invalid")
    from scripts.run_aws_retained_dev_role_bootstrap import _unique
    with path.open("rb") as stream:
        raw = stream.read(2049)
    if len(raw) != size or len(raw) > 2048:
        raise ValueError("app_binding_invalid")
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) != {"stack_arn", "original_creation_run_id"}
        or type(value["original_creation_run_id"]) is not int
        or isinstance(value["original_creation_run_id"], bool) or value["original_creation_run_id"] <= 0
        or type(value["stack_arn"]) is not str):
        raise ValueError("app_binding_invalid")
    if re.fullmatch(rf"arn:aws:cloudformation:eu-west-1:[0-9]{{12}}:stack/{APP}/[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}", value["stack_arn"]) is None:
        raise ValueError("app_binding_invalid")
    return value


def _discover_setup_ids(cloudformation_client, stack_arn, account):
    try:
        response = cloudformation_client.describe_stack_resources(StackName=stack_arn)
    except Exception:
        raise ValueError("setup_resource_discovery_failed") from None
    metadata = response.get("ResponseMetadata") if isinstance(response, dict) else None
    rows = response.get("StackResources") if isinstance(response, dict) else None
    if (not isinstance(metadata, dict) or type(metadata.get("HTTPStatusCode")) is not int
        or metadata.get("HTTPStatusCode") != 200 or not isinstance(rows, list)
        or len(rows) != 11 or response.get("NextToken") not in (None, "")
        or response.get("Marker") not in (None, "")):
        raise ValueError("setup_resource_discovery_failed")
    expected_types = {
        "McpApi": "AWS::ApiGatewayV2::Api",
        "McpApiStage": "AWS::ApiGatewayV2::Stage",
        "McpHandlerRole": "AWS::IAM::Role",
        "McpHandlerLogGroup": "AWS::Logs::LogGroup",
        "McpHandler": "AWS::Lambda::Function",
        "McpUserPool": "AWS::Cognito::UserPool",
        "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
        "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
        "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
        "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
        "McpTenantsTable": "AWS::DynamoDB::Table",
    }
    by = {}
    for row in rows:
        if (not isinstance(row, dict) or row.get("LogicalResourceId") in by
            or row.get("LogicalResourceId") not in expected_types
            or row.get("ResourceType") != expected_types[row["LogicalResourceId"]]
            or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
            raise ValueError("setup_resource_discovery_failed")
        by[row["LogicalResourceId"]] = row
    if set(by) != {"McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler", "McpUserPool", "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding", "McpTenantsTable"}:
        raise ValueError("setup_resource_discovery_failed")
    return by["McpUserPool"]["PhysicalResourceId"], by["McpUserPoolClient"]["PhysicalResourceId"]


def run(authorization_path, bindings_path, state_dir, *, operation, step,
        roles_binding_path=None,
        source_validator=validate_source_and_ci, client_factory=_build_clients,
        acl_checker=None, journal_factory=FileJournal, role_verifier=verify_role_pair,
        setup_readback_client_factory=_build_setup_readback_clients,
        setup_verifier=verify_closed_setup, app_binding_path=None):
    """Fail with fixed categories, never raw SDK/provider payloads."""
    try:
        if operation not in {"roles", "setup", "controls"} or step not in {"preflight", "update", "readback"}:
            raise ValueError("step_invalid")
        auth = load_authorization(validate_private_location(Path(authorization_path), acl_checker=acl_checker))
        bindings = _load_bindings(validate_private_location(Path(bindings_path), acl_checker=acl_checker))
        directory = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        if bindings["account_id"] != auth["account"]:
            raise ValueError("binding_invalid")
        app_binding = None
        if operation == "setup":
            # The application stack binding is an independent private receipt.
            # Validate it before constructing any AWS client or invoking the
            # update core, for every setup phase (including preflight/update).
            if app_binding_path is None:
                raise ValueError("setup_readback_binding_required")
            app_binding = _load_app_binding(app_binding_path, acl_checker=acl_checker)
            expected_app_stack = rf"arn:aws:cloudformation:eu-west-1:{auth['account']}:stack/{APP}/"
            if (re.fullmatch(expected_app_stack + r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", app_binding["stack_arn"]) is None
                or app_binding["stack_arn"] != bindings["stack_arn"]):
                raise ValueError("setup_readback_binding_required")
        # Reuse the pure exact account/stack/API/bucket/provider validation for
        # both paths; a malformed private binding must not construct clients.
        reviewed_prior_roles = build_cd_retained_dev_roles(**bindings)
        source_validator(auth)
        expected_directory = f"{operation}-{auth['run_id']}-{auth['source_sha'][:12]}"
        if directory.name != expected_directory:
            raise ValueError("journal_namespace_invalid")
        token = "dev-multiuser-" + hashlib.sha256(
            f"{operation}:{auth['run_id']}:{auth['source_sha']}".encode()).hexdigest()[:32]
        journal = journal_factory(directory)
        with journal.locked():
            existing = journal.load()
            if step == "preflight" and existing is not None:
                raise ValueError("fresh_journal_required")
            if step != "preflight" and existing is None:
                raise ValueError("preflight_required")
            if existing is not None and (type(existing) is not dict or set(existing) != {"binding", "phase"}
                or existing["phase"] not in {"ready", "intent", "acknowledged", "accepted"}
                or type(existing["binding"]) is not dict
                or any(existing["binding"].get(key) != expected for key, expected in (
                    ("source", auth["source_sha"]), ("account", auth["account"]),
                    ("caller", auth["expected_caller_arn"]), ("start", auth["start"]),
                    ("end", auth["end"]), ("token", token)))):
                raise ValueError("journal_binding_invalid")
        if operation in {"roles", "controls", "setup"}:
            if roles_binding_path is None:
                raise ValueError("roles_binding_required")
            path = validate_private_location(Path(roles_binding_path), acl_checker=acl_checker)
            size = path.stat().st_size
            if not 0 < size <= 4096:
                raise ValueError("roles_binding_invalid")
            from scripts.run_aws_retained_dev_role_bootstrap import _unique
            with path.open("rb") as stream:
                raw = stream.read(4097)
            if len(raw) != size or len(raw) > 4096:
                raise ValueError("roles_binding_invalid")
            role_binding = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
            bound_name = CONTROLS if operation == "controls" else ROLES
            if (type(role_binding) is not dict
                or set(role_binding) != {"stack_arn", "original_creation_run_id"}
                or type(role_binding["original_creation_run_id"]) is not int
                or role_binding["original_creation_run_id"] <= 0
                or type(role_binding["stack_arn"]) is not str
                or re.fullmatch(rf"arn:aws:cloudformation:eu-west-1:{auth['account']}:stack/{bound_name}/"
                                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", role_binding["stack_arn"]) is None):
                raise ValueError("roles_binding_invalid")
        if operation in {"roles", "controls"}:
            if operation == "roles":
                from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
                prior = reviewed_prior_roles
                target = build_cd_retained_dev_multiuser_roles(**bindings)
            else:
                api = bindings["api_arn"].rsplit("/", 1)[1]
                prior = build_retained_dev_controls(api)
                target = build_dev_multiuser_timed_controls(api)
            stack_name, role = bound_name, None
            stack = role_binding["stack_arn"]
        else:
            api = bindings["api_arn"].rsplit("/", 1)[1]
            prior = build_retained_dev_template()
            target = build_retained_dev_multiuser_setup(api_id=api, callback_url=CALLBACK)
            stack_name = APP
            role = f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update"
            stack = bindings["stack_arn"]
        clients = client_factory()
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        if operation == "roles" and step in {"preflight", "update"}:
            expected_roles = reviewed_prior_roles
        elif operation == "setup":
            from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
            expected_roles = build_cd_retained_dev_multiuser_roles(**bindings)
        else:
            expected_roles = None
        if expected_roles is not None:
            receipt = role_verifier({"iam": clients["iam"]}, expected_roles, account=auth["account"],
                roles_stack_arn=role_binding["stack_arn"], original_creation_run_id=role_binding["original_creation_run_id"])
            if receipt.get("success") is not True:
                return {"ok": False, "category": "role_readback_failed"}
        core = ClosedDevUpdate(clients, journal, account=auth["account"],
            caller_arn=auth["expected_caller_arn"], stack_arn=stack, prior_template=prior,
            target_template=target, service_role_arn=role, source_sha=auth["source_sha"],
            start=auth["start"], end=auth["end"], token=token)
        result = core.run(step)
        if operation == "setup" and step == "readback" and result.get("phase") == "accepted":
            if app_binding is None or app_binding["stack_arn"] != stack:
                return {"ok": False, "category": "setup_readback_binding_required"}
            user_pool_id, client_id = _discover_setup_ids(clients["cloudformation"], app_binding["stack_arn"], auth["account"])
            setup_clients = setup_readback_client_factory(clients)
            setup_receipt = setup_verifier(
                setup_clients, account=auth["account"], stack_arn=stack,
                api_id=bindings["api_arn"].rsplit("/", 1)[1],
                user_pool_id=user_pool_id, client_id=client_id,
                callback_url=CALLBACK,
                original_creation_run_id=app_binding["original_creation_run_id"],
            )
            if setup_receipt.get("success") is not True:
                return {"ok": False, "category": "setup_readback_failed"}
            result["setup_readback"] = True
        if operation == "roles" and step == "readback" and result.get("phase") == "accepted":
            receipt = role_verifier({"iam": clients["iam"]}, target, account=auth["account"],
                roles_stack_arn=role_binding["stack_arn"], original_creation_run_id=role_binding["original_creation_run_id"])
            if receipt.get("success") is not True:
                return {"ok": False, "category": "role_readback_failed"}
            result["role_readback"] = True
        return result
    except Exception as exc:
        from scripts.dev_multiuser_closed_update import ClosedUpdateError
        category = str(exc) if isinstance(exc, ClosedUpdateError) else "closed_update_failed"
        return {"ok": False, "category": category}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--roles-binding", type=Path)
    parser.add_argument("--app-binding", type=Path)
    parser.add_argument("--operation", choices=("roles", "setup", "controls"), required=True)
    parser.add_argument("--step", choices=("preflight", "update", "readback"), required=True)
    args = parser.parse_args(argv)
    result = run(args.authorization, args.bindings, args.state_dir, operation=args.operation, step=args.step,
                 roles_binding_path=args.roles_binding, app_binding_path=args.app_binding)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
