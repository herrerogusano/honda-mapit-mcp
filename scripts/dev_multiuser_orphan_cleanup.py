"""Injected, one-shot cleanup of one orphaned retained-DEV JWT authorizer.

The caller supplies already-constructed clients and a private journal.  This
module never constructs an SDK client, discovers an account, retries a delete,
or returns provider payloads.  A durable delete intent fences every ambiguous
outcome before the single destructive API call.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from typing import Any


_REGION = "eu-west-1"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_TOKEN = re.compile(r"dev-multiuser-[0-9a-f]{32}\Z")
_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:(?P<account>[0-9]{12}):stack/honda-mapit-mcp-dev-retained/[0-9a-f-]{36}\Z")
_KIND = "retained-dev-orphan-authorizer-cleanup"
_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
_FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
_LOGICAL_ID = "McpJwtAuthorizer"
_MAX_CALLS = 13


class _ReadFailure(Exception):
    pass


class _WindowFailure(Exception):
    pass


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def _safe(success: bool, category: str, calls: int) -> dict[str, Any]:
    return {"success": success, "category": category, "calls": calls}


def _ok(response: Any, status: int = 200) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    return (isinstance(metadata, Mapping)
            and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == status)


def _no_page(response: Mapping[str, Any]) -> bool:
    truncated = response.get("IsTruncated")
    return (response.get("NextToken") in (None, "")
            and response.get("NextMarker") in (None, "")
            and response.get("Marker") in (None, "")
            and (truncated is None or (type(truncated) is bool and truncated is False)))


def _parse_template(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return dict(value)
    if type(value) is not str or len(value.encode("utf-8")) > 512 * 1024:
        return None

    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        return None
    return dict(parsed) if isinstance(parsed, Mapping) else None


def _binding(*, account: str, caller: str, stack: str, api_id: str, region: str,
             source: str, token: str, lineage_token: str, start: int, end: int,
             authorizer_name: str, issuer: str, audience: str) -> dict[str, Any]:
    return {
        "account_id": account, "caller_arn": caller, "stack_arn": stack,
        "api_id": api_id, "region": region, "source_sha": source,
        "runtime_token": token, "lineage_token": lineage_token,
        "authorized_from_epoch": start,
        "authorized_until_epoch": end, "authorizer_name": authorizer_name,
        "issuer": issuer, "audience": audience,
    }


def _journal_context(journal: Any):
    return journal.locked()


def _valid_inputs(clients: Any, journal: Any, auth: Any, *, app_stack: Any,
                  api_id: Any, expected_template: Any, authorizer_name: Any,
                  issuer: Any, audience: Any, lineage_token: Any) -> tuple[dict[str, Any], Mapping[str, Any]] | None:
    if (not isinstance(clients, Mapping)
        or set(clients) != {"sts", "cloudformation", "apigatewayv2", "lambda"}
        or any(clients.get(name) is None for name in clients)
        or not all(callable(getattr(clients[name], method, None)) for name, method in (
            ("sts", "get_caller_identity"), ("cloudformation", "describe_stacks"),
            ("cloudformation", "describe_stack_resources"), ("cloudformation", "get_template"),
            ("cloudformation", "describe_stack_events"), ("apigatewayv2", "get_api"),
            ("apigatewayv2", "get_authorizers"), ("apigatewayv2", "get_routes"),
            ("apigatewayv2", "get_integrations"), ("apigatewayv2", "delete_authorizer"),
            ("lambda", "get_function_concurrency")))):
        return None
    if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
        return None
    if type(auth) is not dict:
        return None
    fields = {"account", "expected_caller_arn", "region", "source_sha", "token",
              "start", "end", "binding_sha256"}
    if set(auth) != fields:
        return None
    account, caller, region = auth["account"], auth["expected_caller_arn"], auth["region"]
    source, token = auth["source_sha"], auth["token"]
    start, end = auth["start"], auth["end"]
    if (type(account) is not str or _ACCOUNT.fullmatch(account) is None
        or account == "0" * 12 or type(caller) is not str
        or re.fullmatch(rf"(?:arn:aws:iam::{account}:(?:user|role)/[^\s:]+|arn:aws:sts::{account}:assumed-role/[^\s:/]+/[^\s:/]+)", caller) is None
        or type(region) is not str or region != _REGION
        or type(source) is not str or _SHA1.fullmatch(source) is None
        or type(token) is not str or _TOKEN.fullmatch(token) is None
        or type(lineage_token) is not str or _TOKEN.fullmatch(lineage_token) is None
        or type(start) is not int or isinstance(start, bool) or type(end) is not int
        or isinstance(end, bool) or not 0 < end - start <= 3600
        or type(app_stack) is not str or _STACK.fullmatch(app_stack) is None
        or _STACK.fullmatch(app_stack).group("account") != account
        or type(api_id) is not str or _API.fullmatch(api_id) is None
        or type(authorizer_name) is not str or not authorizer_name or len(authorizer_name) > 128
        or type(issuer) is not str or not issuer.startswith("https://") or len(issuer) > 512
        or type(audience) is not str or not audience.startswith("https://") or len(audience) > 512
        or not isinstance(expected_template, Mapping)):
        return None
    resources = expected_template.get("Resources")
    if (not isinstance(resources, Mapping) or len(resources) != 11
        or any(not isinstance(value, Mapping) or type(value.get("Type")) is not str
               for value in resources.values())):
        return None
    expected = _binding(account=account, caller=caller, stack=app_stack, api_id=api_id,
                        region=region, source=source, token=token, lineage_token=lineage_token,
                        start=start, end=end,
                        authorizer_name=authorizer_name, issuer=issuer, audience=audience)
    try:
        expected_sha = _digest(expected)
    except Exception:
        return None
    if (type(auth["binding_sha256"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}\Z", auth["binding_sha256"]) is None
        or auth["binding_sha256"] != expected_sha):
        return None
    return auth, expected_template


def _terminal(journal: Any, *, binding: Mapping[str, Any], authorizer_id: str,
              phase: str, revision: int) -> bool:
    value = {
        "schema": 1, "kind": _KIND, "revision": revision, "phase": phase,
        "binding_sha256": _digest(binding), "binding": dict(binding),
        "authorizer_id": authorizer_id,
    }
    try:
        journal.save(value)
        return True
    except Exception:
        return False


def cleanup_orphan_authorizer(
    clients: Mapping[str, Any], journal: Any, *, auth: dict[str, Any],
    app_stack: str, api_id: str, expected_template: Mapping[str, Any],
    authorizer_name: str, issuer: str, audience: str, lineage_token: str,
    wall_clock: Any = time.time,
) -> dict[str, Any]:
    """Delete exactly one proven orphan authorizer, or fail closed.

    The journal must be empty for a fresh attempt.  Any pre-existing intent or
    terminal record is never replayed, including after an ambiguous delete.
    """
    validated = _valid_inputs(
        clients, journal, auth, app_stack=app_stack, api_id=api_id,
        expected_template=expected_template, authorizer_name=authorizer_name,
        issuer=issuer, audience=audience, lineage_token=lineage_token,
    )
    if validated is None or not callable(wall_clock):
        return _safe(False, "cleanup_inputs_invalid", 0)
    auth, expected_template = validated
    try:
        now = wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool)
            or not math.isfinite(float(now)) or not auth["start"] <= now < auth["end"]):
            return _safe(False, "cleanup_window_invalid", 0)
        last_now = float(now)
    except Exception:
        return _safe(False, "cleanup_window_invalid", 0)
    calls = 0
    try:
        with _journal_context(journal):
            existing = journal.load()
            if existing is not None:
                return _safe(False, "cleanup_journal_not_fresh", 0)

            def guard() -> None:
                nonlocal last_now
                value = wall_clock()
                if (type(value) not in (int, float) or isinstance(value, bool)
                    or not math.isfinite(float(value)) or not auth["start"] <= value < auth["end"]
                    or float(value) < last_now):
                    raise _WindowFailure
                last_now = float(value)

            def call(client: Any, method: str, **kwargs: Any) -> Mapping[str, Any]:
                nonlocal calls
                guard()
                if calls >= _MAX_CALLS:
                    raise RuntimeError("budget")
                calls += 1
                try:
                    response = getattr(client, method)(**kwargs)
                except Exception:
                    raise _ReadFailure from None
                guard()
                if not isinstance(response, Mapping) or not _ok(response) or not _no_page(response):
                    raise _ReadFailure
                return response

            identity = call(clients["sts"], "get_caller_identity")
            if identity.get("Account") != auth["account"] or identity.get("Arn") != auth["expected_caller_arn"]:
                return _safe(False, "cleanup_identity_mismatch", calls)

            stacks = call(clients["cloudformation"], "describe_stacks", StackName=app_stack).get("Stacks")
            if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
                return _safe(False, "cleanup_readback_failed", calls)
            stack = stacks[0]
            role = f"arn:aws:iam::{auth['account']}:role/{_ROLE_NAME}"
            if (stack.get("StackId") != app_stack or stack.get("StackName") != "honda-mapit-mcp-dev-retained"
                or stack.get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
                or stack.get("RoleARN") != role or stack.get("EnableTerminationProtection") is not True):
                return _safe(False, "cleanup_readback_failed", calls)

            template_reply = call(clients["cloudformation"], "get_template", StackName=app_stack, TemplateStage="Original")
            actual_template = _parse_template(template_reply.get("TemplateBody"))
            if actual_template is None or _digest(actual_template) != _digest(expected_template):
                return _safe(False, "cleanup_lineage_mismatch", calls)

            resources = call(clients["cloudformation"], "describe_stack_resources", StackName=app_stack).get("StackResources")
            expected_resources = expected_template.get("Resources")
            pool_id = issuer.rsplit("/", 1)[-1]
            if (type(pool_id) is not str or _POOL.fullmatch(pool_id) is None
                or type(resources) is not list or len(resources) != 11
                or not isinstance(expected_resources, Mapping) or len(expected_resources) != 11):
                return _safe(False, "cleanup_lineage_mismatch", calls)
            resource_map = {}
            for row in resources:
                if (not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str
                    or row["LogicalResourceId"] in resource_map or row["LogicalResourceId"] not in expected_resources
                    or row.get("ResourceType") != expected_resources[row["LogicalResourceId"]].get("Type")
                    or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                    or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
                    return _safe(False, "cleanup_lineage_mismatch", calls)
                resource_map[row["LogicalResourceId"]] = row
            if set(resource_map) != set(expected_resources):
                return _safe(False, "cleanup_lineage_mismatch", calls)
            expected_physical = {
                "McpApi": api_id, "McpApiStage": "$default",
                "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
                "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
                "McpHandler": _FUNCTION_NAME, "McpUserPool": pool_id,
            }
            if any(resource_map[key].get("PhysicalResourceId") != value
                   for key, value in expected_physical.items()):
                return _safe(False, "cleanup_lineage_mismatch", calls)

            api = call(clients["apigatewayv2"], "get_api", ApiId=api_id)
            if (api.get("ApiId") != api_id or api.get("ProtocolType") != "HTTP"
                or api.get("DisableExecuteApiEndpoint") is not True):
                return _safe(False, "cleanup_readback_failed", calls)
            authorizers = call(clients["apigatewayv2"], "get_authorizers", ApiId=api_id, MaxResults="100").get("Items")
            if type(authorizers) is not list or len(authorizers) != 1 or not isinstance(authorizers[0], Mapping):
                return _safe(False, "cleanup_authorizer_mismatch", calls)
            authorizer = authorizers[0]
            authorizer_id = authorizer.get("AuthorizerId")
            if (type(authorizer_id) is not str or not authorizer_id
                or ("ApiId" in authorizer and authorizer.get("ApiId") != api_id)
                or authorizer.get("Name") != authorizer_name or authorizer.get("AuthorizerType") != "JWT"
                or authorizer.get("JwtConfiguration") != {"Audience": [audience], "Issuer": issuer}):
                return _safe(False, "cleanup_authorizer_mismatch", calls)

            routes = call(clients["apigatewayv2"], "get_routes", ApiId=api_id, MaxResults="100").get("Items")
            integrations = call(clients["apigatewayv2"], "get_integrations", ApiId=api_id, MaxResults="100").get("Items")
            if type(routes) is not list or routes or type(integrations) is not list or integrations:
                return _safe(False, "cleanup_children_present", calls)

            concurrency = call(clients["lambda"], "get_function_concurrency", FunctionName=_FUNCTION_NAME)
            if type(concurrency.get("ReservedConcurrentExecutions")) is not int or concurrency["ReservedConcurrentExecutions"] != 0:
                return _safe(False, "cleanup_runtime_not_closed", calls)

            events = call(clients["cloudformation"], "describe_stack_events", StackName=app_stack).get("StackEvents")
            if type(events) is not list or len(events) > 256:
                return _safe(False, "cleanup_lineage_mismatch", calls)
            matching = [row for row in events if isinstance(row, Mapping)
                        and row.get("StackId") == app_stack
                        and row.get("ResourceType") == "AWS::ApiGatewayV2::Authorizer"
                        and row.get("LogicalResourceId") == _LOGICAL_ID
                        and row.get("PhysicalResourceId") == authorizer_id
                        and row.get("ClientRequestToken") == lineage_token]
            if (sum(row.get("ResourceStatus") == "CREATE_COMPLETE" for row in matching) != 1
                or sum(row.get("ResourceStatus") == "DELETE_SKIPPED" for row in matching) != 1):
                return _safe(False, "cleanup_lineage_mismatch", calls)

            binding = dict(auth)
            binding.update({"authorizer_name": authorizer_name, "issuer": issuer,
                            "audience": audience, "authorizer_id": authorizer_id,
                            "lineage_token": lineage_token,
                            "expected_template_sha256": _digest(expected_template)})
            binding_sha = _digest(binding)
            intent = {
                "schema": 1, "kind": _KIND, "revision": 1, "phase": "delete_intent",
                "binding_sha256": binding_sha, "binding": dict(binding),
                "authorizer_id": authorizer_id,
            }
            try:
                journal.save(intent)
            except Exception:
                return _safe(False, "cleanup_journal_failed", calls)

            guard()
            calls += 1
            try:
                deleted = clients["apigatewayv2"].delete_authorizer(ApiId=api_id, AuthorizerId=authorizer_id)
            except Exception:
                _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="outcome_unknown", revision=2)
                return _safe(False, "cleanup_outcome_unknown", calls)
            try:
                guard()
            except _WindowFailure:
                _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="outcome_unknown", revision=2)
                return _safe(False, "cleanup_outcome_unknown", calls)
            if not _ok(deleted, 204):
                _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="outcome_unknown", revision=2)
                return _safe(False, "cleanup_outcome_unknown", calls)

            try:
                reread = call(clients["apigatewayv2"], "get_authorizers", ApiId=api_id, MaxResults="100").get("Items")
            except (_ReadFailure, _WindowFailure):
                _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="outcome_unknown", revision=2)
                return _safe(False, "cleanup_outcome_unknown", calls)
            if type(reread) is not list or reread:
                _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="outcome_unknown", revision=2)
                return _safe(False, "cleanup_outcome_unknown", calls)
            if not _terminal(journal, binding=binding, authorizer_id=authorizer_id, phase="complete", revision=2):
                return _safe(False, "cleanup_outcome_unknown", calls)
            return _safe(True, "cleanup_verified", calls)
    except _WindowFailure:
        return _safe(False, "cleanup_window_invalid", calls)
    except _ReadFailure:
        return _safe(False, "cleanup_read_failed", calls)
    except Exception:
        return _safe(False, "cleanup_internal_failed", calls)


__all__ = ["cleanup_orphan_authorizer"]
