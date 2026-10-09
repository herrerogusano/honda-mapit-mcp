"""Injected, single-attempt coordinator for the isolated DEV owner OAuth stack.

No SDK clients are constructed here. Source, owner-pool context and Cognito
readback are supplied by required trusted callbacks; this module only permits
one exact CloudFormation CreateStack after fresh preflight and durable intent.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable

from scripts.build_aws_dev_owner_oauth import (
    REGION,
    STACK_NAME,
    build_dev_owner_oauth_template,
)
from scripts.build_aws_dev_oauth_template import _validate_callback

MAX_AUTHORITY_SECONDS = 600
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 16
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,45}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9]{8,128}\Z")
_STACK_ARN = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\Z"
)
_RESOURCE_TYPES = {
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}
_CATEGORIES = frozenset({
    "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid", "window_expired",
    "step_invalid", "source_unverified", "context_unverified", "preflight_verified",
    "preflight_required", "preflight_conflict", "stack_exists", "resource_server_exists",
    "create_intent_saved", "create_intent_present", "create_outcome_unknown", "create_acknowledged",
    "stack_in_progress", "stack_not_complete", "stack_readback_mismatch", "readback_verified",
    "aws_call_failed", "aws_response_invalid", "journal_failed", "operator_internal_error",
})


class DevOwnerOAuthBootstrapError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _status_ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata.get("HTTPStatusCode") == 200)


def _aws_error(exc: Exception) -> tuple[str, int | None, str]:
    try:
        response = getattr(exc, "response", None)
        error = response.get("Error") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        code = error.get("Code") if isinstance(error, Mapping) else None
        message = error.get("Message") if isinstance(error, Mapping) else None
        status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
        return (code if type(code) is str else "",
                status if type(status) is int and not isinstance(status, bool) else None,
                message if type(message) is str else "")
    except Exception:
        return "", None, ""


class DevOwnerOAuthBootstrapCoordinator:
    """One-attempt preflight/create/readback flow for the isolated DEV stack."""

    STEPS = ("preflight", "create", "readback")

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, account_id: str,
                 operator_user_arn: str, owner_pool_id: str, api_id: str,
                 callback_url: str, source_sha: str, run_id: str,
                 authorized_from_epoch: int, authorized_until_epoch: int,
                 expected_context_sha256: str,
                 context_reader: Callable[[str | None], Mapping[str, Any]],
                 source_checker: Callable[[], Any],
                 readback_validator: Callable[[str, Mapping[str, Any], str, int, int, Mapping[str, str]], Mapping[str, Any]],
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        required_clients = {"cloudformation", "cognito"}
        if (not isinstance(clients, Mapping) or set(clients) != required_clients
                or any(clients.get(name) is None for name in required_clients)
                or not callable(getattr(clients.get("cloudformation"), "describe_stacks", None))
                or not callable(getattr(clients.get("cloudformation"), "create_stack", None))
                or not callable(getattr(clients.get("cloudformation"), "get_template", None))
                or not callable(getattr(clients.get("cloudformation"), "describe_stack_resources", None))
                or not callable(getattr(clients.get("cloudformation"), "describe_stack_events", None))
                or not callable(getattr(clients.get("cognito"), "describe_resource_server", None))):
            raise DevOwnerOAuthBootstrapError("clients_invalid")
        if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        if not all(callable(value) for value in (context_reader, source_checker, readback_validator, wall_clock, monotonic)):
            raise DevOwnerOAuthBootstrapError("binding_invalid")

        if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000"
                or type(operator_user_arn) is not str
                or re.fullmatch(rf"arn:aws:iam::{account_id}:user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+", operator_user_arn) is None
                or type(owner_pool_id) is not str or _POOL.fullmatch(owner_pool_id) is None
                or type(api_id) is not str or _API.fullmatch(api_id) is None
                or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
                or type(run_id) is not str or _UUID.fullmatch(run_id) is None
                or type(expected_context_sha256) is not str or _SHA256.fullmatch(expected_context_sha256) is None
                or type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
                or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
                or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS):
            raise DevOwnerOAuthBootstrapError("binding_invalid")
        try:
            callback = _validate_callback(callback_url)
            port = int(callback.rsplit(":", 1)[1].split("/", 1)[0])
        except Exception:
            raise DevOwnerOAuthBootstrapError("binding_invalid") from None
        if port in {8785, 8786}:
            raise DevOwnerOAuthBootstrapError("binding_invalid")
        try:
            template = build_dev_owner_oauth_template(
                account_id=account_id, api_id=api_id,
                owner_pool_id=owner_pool_id, callback_url=callback,
            )
            template_bytes = _canonical(template)
        except Exception:
            raise DevOwnerOAuthBootstrapError("binding_invalid") from None

        self.clients = dict(clients)
        self.journal = journal
        self.account_id, self.operator_user_arn = account_id, operator_user_arn
        self.owner_pool_id, self.api_id, self.callback_url = owner_pool_id, api_id, callback
        self.resource_uri = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
        self.source_sha, self.run_id = source_sha, run_id
        self.start, self.end = authorized_from_epoch, authorized_until_epoch
        self.expected_context_sha256 = expected_context_sha256
        self.template, self.template_bytes = template, template_bytes
        self.template_sha256 = hashlib.sha256(template_bytes).hexdigest()
        self.context_reader, self.source_checker, self.readback_validator = context_reader, source_checker, readback_validator
        self.wall_clock, self.monotonic = wall_clock, monotonic
        binding = {
            "account_id": account_id, "operator_user_arn": operator_user_arn,
            "owner_pool_id": owner_pool_id, "api_id": api_id, "callback_url": callback,
            "source_sha": source_sha, "run_id": run_id, "start": self.start, "end": self.end,
            "context_sha256": expected_context_sha256, "template_sha256": self.template_sha256,
        }
        self.authority_sha256 = hashlib.sha256(_canonical(binding)).hexdigest()
        self._started: float | None = None
        self._last_mono = 0.0
        self._last_epoch = 0
        self._calls = 0

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise DevOwnerOAuthBootstrapError("window_invalid")
        epoch = int(value)
        if epoch < self._last_epoch:
            raise DevOwnerOAuthBootstrapError("window_invalid")
        self._last_epoch = epoch
        if not self.start <= epoch < self.end:
            raise DevOwnerOAuthBootstrapError("window_expired")
        return epoch

    def _budget(self) -> None:
        value = self.monotonic()
        if (type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value)
                or value < self._last_mono):
            raise DevOwnerOAuthBootstrapError("window_invalid")
        self._last_mono = float(value)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            raise DevOwnerOAuthBootstrapError("window_expired")
        if self._calls >= MAX_CALLS_PER_STEP:
            raise DevOwnerOAuthBootstrapError("aws_call_failed")

    def _call(self, client: str, method: str, *, allow_next_token: bool = False,
              **kwargs: Any) -> Mapping[str, Any]:
        self._budget()
        self._now()
        self._calls += 1
        try:
            response = getattr(self.clients[client], method)(**kwargs)
        except Exception:
            self._now()
            self._budget()
            raise DevOwnerOAuthBootstrapError("aws_call_failed") from None
        if (not _status_ok(response) or not isinstance(response, Mapping)
                or any(key in response for key in ("Marker", "PaginationToken"))
                or (not allow_next_token and "NextToken" in response)
                or (allow_next_token and "NextToken" in response
                    and (type(response["NextToken"]) is not str or not 1 <= len(response["NextToken"]) <= 2048))):
            raise DevOwnerOAuthBootstrapError("aws_response_invalid")
        self._now()
        self._budget()
        return response

    def _absent(self, client: str, method: str, *, absence: str, **kwargs: Any) -> None:
        self._budget()
        self._now()
        self._calls += 1
        try:
            response = getattr(self.clients[client], method)(**kwargs)
        except Exception as exc:
            code, status, message = _aws_error(exc)
            exact = ((absence == "stack" and code == "ValidationError" and status in {400, 404}
                      and message == f"Stack with id {STACK_NAME} does not exist")
                     or (absence == "resource_server" and code == "ResourceNotFoundException" and status == 400))
            self._now()
            self._budget()
            if exact:
                return
            raise DevOwnerOAuthBootstrapError("aws_call_failed") from None
        if not _status_ok(response):
            raise DevOwnerOAuthBootstrapError("aws_response_invalid")
        self._now()
        raise DevOwnerOAuthBootstrapError("stack_exists" if absence == "stack" else "resource_server_exists")

    def _load(self) -> dict[str, Any] | None:
        try:
            state = self.journal.load()
        except Exception:
            raise DevOwnerOAuthBootstrapError("journal_invalid") from None
        if state is None:
            return None
        required = {"schema", "kind", "authority_sha256", "template_sha256", "phase",
                    "last_observed_epoch", "intent", "ack_stack_id", "readback"}
        if not isinstance(state, Mapping) or set(state) != required:
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        if (type(state.get("schema")) is not int or state["schema"] != 1
                or state.get("kind") != "dev-owner-oauth-bootstrap"
                or state.get("authority_sha256") != self.authority_sha256
                or state.get("template_sha256") != self.template_sha256
                or state.get("phase") not in {"preflight", "create_intent", "create_acknowledged", "readback_verified"}
                or type(state.get("last_observed_epoch")) is not int
                or isinstance(state.get("last_observed_epoch"), bool)
                or state["last_observed_epoch"] <= 0):
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        intent, ack, receipt = state.get("intent"), state.get("ack_stack_id"), state.get("readback")
        if state["phase"] == "preflight" and (intent is not None or ack is not None or receipt is not None):
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        if state["phase"] in {"create_intent", "create_acknowledged", "readback_verified"}:
            expected_token = self._request_token()
            if (not isinstance(intent, Mapping) or set(intent) != {"token", "stack_name", "template_sha256"}
                    or intent.get("token") != expected_token or intent.get("stack_name") != STACK_NAME
                    or intent.get("template_sha256") != self.template_sha256):
                raise DevOwnerOAuthBootstrapError("journal_invalid")
        if state["phase"] == "create_intent" and (ack is not None or receipt is not None):
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        if state["phase"] in {"create_acknowledged", "readback_verified"}:
            if type(ack) is not str or not self._valid_stack_id(ack):
                raise DevOwnerOAuthBootstrapError("journal_invalid")
        if state["phase"] != "readback_verified" and receipt is not None:
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        if state["phase"] == "readback_verified" and not self._valid_readback_receipt(receipt):
            raise DevOwnerOAuthBootstrapError("journal_invalid")
        return dict(state)

    def _save(self, phase: str, *, intent: Mapping[str, Any] | None,
              ack_stack_id: str | None, readback: Mapping[str, Any] | None) -> None:
        self._budget()
        self._now()
        value = {
            "schema": 1, "kind": "dev-owner-oauth-bootstrap",
            "authority_sha256": self.authority_sha256,
            "template_sha256": self.template_sha256,
            "phase": phase, "last_observed_epoch": self._last_epoch,
            "intent": dict(intent) if intent is not None else None,
            "ack_stack_id": ack_stack_id,
            "readback": dict(readback) if readback is not None else None,
        }
        try:
            self.journal.save(value)
        except Exception:
            raise DevOwnerOAuthBootstrapError("journal_failed") from None
        self._now()
        self._budget()

    def _request_token(self) -> str:
        return hashlib.sha256(f"{self.account_id}:{self.source_sha}:{self.run_id}:{self.template_sha256}".encode("ascii")).hexdigest()

    def _valid_stack_id(self, value: Any) -> bool:
        match = _STACK_ARN.fullmatch(value) if type(value) is str else None
        return match is not None and match.group(1) == self.account_id

    def _source(self) -> None:
        self._now()
        try:
            result = self.source_checker()
        except Exception:
            raise DevOwnerOAuthBootstrapError("source_unverified") from None
        self._now()
        if result is not True:
            raise DevOwnerOAuthBootstrapError("source_unverified")

    def _context(self, *, exclude_client_id: str | None = None) -> None:
        self._now()
        try:
            result = self.context_reader(exclude_client_id)
        except Exception:
            raise DevOwnerOAuthBootstrapError("context_unverified") from None
        self._now()
        expected_fields = {"verified", "account_id", "owner_pool_id", "api_id", "context_sha256"}
        if (not isinstance(result, Mapping) or set(result) != expected_fields
                or result.get("verified") is not True
                or result.get("account_id") != self.account_id
                or result.get("owner_pool_id") != self.owner_pool_id
                or result.get("api_id") != self.api_id
                or result.get("context_sha256") != self.expected_context_sha256):
            raise DevOwnerOAuthBootstrapError("context_unverified")

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                initial = self.monotonic()
                if type(initial) not in (int, float) or isinstance(initial, bool) or not math.isfinite(initial) or initial < 0:
                    raise DevOwnerOAuthBootstrapError("window_invalid")
                self._started = self._last_mono = float(initial)
                self._calls = 0
                state = self._load()
                self._last_epoch = state.get("last_observed_epoch", 0) if state is not None else 0
                self._now()
                self._source()
                if step == "preflight":
                    return self._preflight(state)
                if step == "create":
                    return self._create(state)
                return self._readback(state)
        except DevOwnerOAuthBootstrapError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "operator_internal_error")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None:
            raise DevOwnerOAuthBootstrapError("preflight_conflict")
        self._context()
        self._absent("cloudformation", "describe_stacks", absence="stack", StackName=STACK_NAME)
        self._absent("cognito", "describe_resource_server", absence="resource_server",
                     UserPoolId=self.owner_pool_id, Identifier=self.resource_uri)
        self._save("preflight", intent=None, ack_stack_id=None, readback=None)
        return self._safe("preflight", True, "preflight_verified")

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("phase") != "preflight":
            if state is not None and state.get("intent") is not None:
                raise DevOwnerOAuthBootstrapError("create_intent_present")
            raise DevOwnerOAuthBootstrapError("preflight_required")
        self._source()
        self._context()
        intent = {"token": self._request_token(), "stack_name": STACK_NAME,
                  "template_sha256": self.template_sha256}
        self._save("create_intent", intent=intent, ack_stack_id=None, readback=None)
        # Durable intent consumes this create attempt even if the dispatch is
        # never made or its outcome cannot be observed.
        self._source()
        self._context()
        self._now()
        self._budget()
        self._calls += 1
        try:
            response = self.clients["cloudformation"].create_stack(
                StackName=STACK_NAME,
                TemplateBody=self.template_bytes.decode("ascii"),
                Tags=[
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "dev"},
                    {"Key": "Purpose", "Value": "owner-oauth-client"},
                    {"Key": "OperatorRunId", "Value": self.run_id},
                ],
                ClientRequestToken=intent["token"],
                EnableTerminationProtection=True,
            )
        except Exception:
            self._now()
            raise DevOwnerOAuthBootstrapError("create_outcome_unknown") from None
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        if not _status_ok(response) or not self._valid_stack_id(stack_id):
            self._now()
            raise DevOwnerOAuthBootstrapError("create_outcome_unknown")
        self._now()
        self._save("create_acknowledged", intent=intent, ack_stack_id=stack_id, readback=None)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise DevOwnerOAuthBootstrapError("preflight_required")
        reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        stacks = reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        stack = stacks[0]
        stack_id = stack.get("StackId")
        if not self._valid_stack_id(stack_id) or stack.get("StackName") != STACK_NAME:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        if state.get("ack_stack_id") is not None and stack_id != state.get("ack_stack_id"):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        if stack.get("StackStatus") in {"CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"}:
            raise DevOwnerOAuthBootstrapError("stack_in_progress")
        if (stack.get("StackStatus") != "CREATE_COMPLETE"
                or stack.get("EnableTerminationProtection") is not True
                or stack.get("RoleARN") not in (None, "")):
            raise DevOwnerOAuthBootstrapError("stack_not_complete")
        expected_tags = {
            "Project": "honda-mapit-mcp", "Environment": "dev",
            "Purpose": "owner-oauth-client", "OperatorRunId": self.run_id,
        }
        tags = stack.get("Tags")
        if (type(tags) is not list or len(tags) != len(expected_tags)
                or {row.get("Key"): row.get("Value") for row in tags if isinstance(row, Mapping)} != expected_tags):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")

        template_reply = self._call("cloudformation", "get_template", StackName=stack_id,
                                    TemplateStage="Original")
        template_body = template_reply.get("TemplateBody")
        try:
            if type(template_body) is str:
                template_body = json.loads(template_body, object_pairs_hook=_pairs)
            if not isinstance(template_body, Mapping) or _canonical(template_body) != self.template_bytes:
                raise ValueError
        except Exception:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch") from None

        resources_reply = self._call("cloudformation", "describe_stack_resources", StackName=stack_id)
        rows = resources_reply.get("StackResources")
        if type(rows) is not list or len(rows) != 3:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        by_id: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if (not isinstance(row, Mapping) or row.get("StackId") != stack_id
                    or row.get("ResourceStatus") != "CREATE_COMPLETE"):
                raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
            logical = row.get("LogicalResourceId")
            if type(logical) is not str or logical in by_id:
                raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
            by_id[logical] = row
        if set(by_id) != set(_RESOURCE_TYPES):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        for logical, expected_type in _RESOURCE_TYPES.items():
            row = by_id[logical]
            if (row.get("ResourceType") != expected_type
                    or type(row.get("PhysicalResourceId")) is not str
                    or not row["PhysicalResourceId"] or len(row["PhysicalResourceId"]) > 1024):
                raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")

        event_reply = self._call("cloudformation", "describe_stack_events", allow_next_token=True,
                                  StackName=stack_id)
        events = event_reply.get("StackEvents")
        if type(events) is not list or not 1 <= len(events) <= 100:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        matching_root_events = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or event.get("ClientRequestToken") != state["intent"]["token"]
                    or event.get("StackId") != stack_id
                    or event.get("StackName") != STACK_NAME
                    or event.get("LogicalResourceId") != STACK_NAME
                    or event.get("PhysicalResourceId") != stack_id
                    or event.get("ResourceType") != "AWS::CloudFormation::Stack"
                    or event.get("ResourceStatus") != "CREATE_COMPLETE"):
                continue
            matching_root_events.append(event)
        if len(matching_root_events) != 1:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        event = matching_root_events[0]
        timestamp = event.get("Timestamp")
        if (not isinstance(timestamp, datetime) or timestamp.tzinfo is None
                or timestamp.utcoffset() is None):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        try:
            event_epoch = timestamp.astimezone(timezone.utc).timestamp()
        except Exception:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch") from None
        if not self.start <= event_epoch < self.end:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")

        self._source()
        try:
            physical_ids = {logical: row["PhysicalResourceId"] for logical, row in by_id.items()}
            receipt = self.readback_validator(
                stack_id, self.template, self.run_id, self.start, self.end, physical_ids,
            )
        except Exception:
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch") from None
        if (not self._valid_readback_receipt(receipt)
                or receipt["client_id"] != physical_ids["McpUserPoolClient"]):
            raise DevOwnerOAuthBootstrapError("stack_readback_mismatch")
        self._context(exclude_client_id=receipt["client_id"])
        safe_receipt = {"verified": True, "client_id": receipt["client_id"],
                        "readback_sha256": receipt["readback_sha256"]}
        self._save("readback_verified", intent=state["intent"],
                   ack_stack_id=stack_id, readback=safe_receipt)
        return self._safe("readback", True, "readback_verified")

    @staticmethod
    def _valid_readback_receipt(value: Any) -> bool:
        return (isinstance(value, Mapping) and set(value) == {"verified", "client_id", "readback_sha256"}
                and value.get("verified") is True and type(value.get("client_id")) is str
                and _CLIENT_ID.fullmatch(value["client_id"]) is not None
                and type(value.get("readback_sha256")) is str
                and _SHA256.fullmatch(value["readback_sha256"]) is not None)


__all__ = ["DevOwnerOAuthBootstrapCoordinator", "DevOwnerOAuthBootstrapError"]
