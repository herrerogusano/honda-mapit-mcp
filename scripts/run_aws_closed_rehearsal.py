"""One-step-at-a-time runner for the closed, synthetic AWS rehearsal.

No AWS SDK is imported or called at module import. Each CLI invocation runs
exactly one named step; AWS calls are single-attempt and output is a closed
status projection. The supplied state directory must already have an ACL
verified for the current operator and SYSTEM, and must be outside Git/OneDrive.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

# Direct execution puts only `scripts/` on sys.path. Add the fixed checkout
# roots so the CLI and pytest use the same local modules.
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _import_root in (str(_REPO_ROOT), str(_REPO_ROOT / "src")):
    if _import_root not in sys.path:
        sys.path.insert(0, _import_root)

from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template

REGION = "eu-west-1"
APP_STACK_NAME = "honda-mapit-mcp-dev"
CONTROL_STACK_NAME = "honda-mapit-mcp-dev-control"
FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
HANDLER_ROLE_NAME = "honda-mapit-mcp-dev-handler-role"
LOG_GROUP_NAME = "/aws/lambda/honda-mapit-mcp-dev-handler"
API_NAME = "honda-mapit-mcp-dev-api"
USER_POOL_NAME = "honda-mapit-mcp-dev-users"
CONTROL_ROLE_NAMES = (
    "honda-mapit-mcp-dev-shutdown-workflow",
    "honda-mapit-mcp-dev-shutdown-scheduler",
    "honda-mapit-mcp-dev-request-tripwire",
    "honda-mapit-mcp-dev-bootstrap-delete",
    "honda-mapit-mcp-dev-bootstrap-cleanup-scheduler",
)
SCHEDULE_GROUP_NAMES = ("honda-mapit-mcp-dev-safety", "honda-mapit-mcp-dev-bootstrap-cleanup")
SCHEDULE_NAMES = ("honda-mapit-mcp-dev-close-once", "honda-mapit-mcp-dev-bootstrap-delete-once")
STATE_MACHINE_NAME = "honda-mapit-mcp-dev-shutdown"
ALARM_NAME = "honda-mapit-mcp-dev-request-tripwire"
EVENT_RULE_NAME = "honda-mapit-mcp-dev-request-tripwire-alarm-rule"
RUN_TAG = "ClosedRehearsalRunId"
MAX_STATE_BYTES = 128 * 1024
STEP_BUDGET_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 2
READ_TIMEOUT_SECONDS = 3
STEPS = (
    "preflight", "create-app", "check-app", "create-controls", "check-controls",
    "arm-shutdown", "check-shutdown", "arm-cleanup", "check-cleanup",
    "fallback-delete-app", "delete-controls", "check-final",
)
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_IDENTITY_ARN = re.compile(r"^arn:aws:(?:iam|sts)::([0-9]{12}):(?:user|role|assumed-role)/[A-Za-z0-9+=,.@_/-]+$")


class RehearsalError(RuntimeError):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


class _AwsFailure(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message.casefold()


def _safe_result(step: str, ok: bool, category: str, calls: int, **counts: int) -> dict[str, Any]:
    if step not in STEPS or type(ok) is not bool or type(calls) is not int or calls < 0:
        return {"step": "unknown", "ok": False, "category": "runner_internal_error", "calls": 0}
    safe_counts = {key: value for key, value in counts.items() if type(value) is int and value >= 0}
    return {"step": step, "ok": ok, "category": category, "calls": calls, **safe_counts}


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and type(error.get("Code")) is str:
            return error["Code"][:80]
    return type(exc).__name__[:80]


def _error_message(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and type(error.get("Message")) is str:
            return error["Message"][:512]
    return str(exc)[:512]


def _is_not_found(exc: _AwsFailure) -> bool:
    return exc.code in {
        "ResourceNotFoundException", "ResourceNotFound", "NotFoundException",
        "NoSuchEntity", "LogGroupNotFoundException", "StateMachineDoesNotExist",
    } or (exc.code == "ValidationError" and ("does not exist" in exc.message or "not found" in exc.message))


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & reparse)


def _is_onedrive_part(part: str) -> bool:
    folded = part.casefold()
    return folded == "onedrive" or folded.startswith("onedrive - ")


class FileJournal:
    """Bounded durable runner state in a pre-created private directory."""

    def __init__(self, state_dir: Path):
        self.repo = Path(__file__).resolve().parents[1]
        self.state_dir = Path(state_dir)
        if not self.state_dir.is_dir() or _is_reparse_or_symlink(self.state_dir):
            raise RehearsalError("state_directory_unavailable")
        try:
            resolved = self.state_dir.resolve(strict=True)
            repo = self.repo.resolve(strict=True)
            resolved.relative_to(repo)
            raise RehearsalError("state_directory_not_private_location")
        except ValueError:
            pass
        except OSError:
            raise RehearsalError("state_directory_unavailable") from None
        if any(_is_onedrive_part(p) for p in resolved.parts):
            raise RehearsalError("state_directory_not_private_location")
        self.path = resolved / "rehearsal-state.json"
        self.lock_path = resolved / "rehearsal-state.lock"
        if _is_reparse_or_symlink(self.path) or _is_reparse_or_symlink(self.lock_path):
            raise RehearsalError("state_file_invalid")

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        try:
            stream = self.lock_path.open("a+b")
        except OSError:
            raise RehearsalError("state_lock_failed") from None
        locked = False
        try:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                if stream.tell() == 0 and self.lock_path.stat().st_size == 0:
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError:
                    raise RehearsalError("runner_already_active") from None
                locked = True
            else:
                import fcntl
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise RehearsalError("runner_already_active") from None
                locked = True
            yield
        finally:
            if locked:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            stream.close()

    def load(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        if _is_reparse_or_symlink(self.path):
            raise RehearsalError("state_file_invalid")
        try:
            size = self.path.stat().st_size
            if size <= 0 or size > MAX_STATE_BYTES:
                raise RehearsalError("state_file_invalid")
            with self.path.open("rb") as stream:
                raw = stream.read(MAX_STATE_BYTES + 1)
            if len(raw) != size or len(raw) > MAX_STATE_BYTES:
                raise RehearsalError("state_file_invalid")
            state = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_duplicate_reject)
        except RehearsalError:
            raise
        except Exception:
            raise RehearsalError("state_file_invalid") from None
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise RehearsalError("state_file_invalid")
        return state

    def save(self, state: dict[str, Any]) -> None:
        raw = _json_bytes(state)
        if len(raw) > MAX_STATE_BYTES or _is_reparse_or_symlink(self.path):
            raise RehearsalError("state_file_invalid")
        temp = self.state_dir / "rehearsal-state.next"
        if _is_reparse_or_symlink(temp):
            raise RehearsalError("state_file_invalid")
        try:
            fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        except FileExistsError:
            raise RehearsalError("state_write_pending_file_exists") from None
        except OSError:
            raise RehearsalError("state_write_failed") from None


class MemoryJournal:
    """Test-only in-memory journal implementing the same runner contract."""

    def __init__(self):
        self.value: dict[str, Any] | None = None

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        yield

    def load(self) -> dict[str, Any] | None:
        return json.loads(_json_bytes(self.value)) if self.value is not None else None

    def save(self, state: dict[str, Any]) -> None:
        self.value = json.loads(_json_bytes(state))


class AwsClosedRehearsal:
    """Single-step runner; clients are injected and never rebuilt/retried here."""

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: FileJournal | MemoryJournal,
        expected_account_id: str,
        *,
        authorized_until_epoch: int | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if type(expected_account_id) is not str or not _ACCOUNT_ID.fullmatch(expected_account_id):
            raise RehearsalError("expected_account_invalid")
        required = {"sts", "cloudformation", "lambda", "apigatewayv2", "cognito", "iam", "logs", "scheduler", "events", "cloudwatch", "stepfunctions"}
        if not isinstance(clients, Mapping) or not required <= clients.keys():
            raise RehearsalError("clients_invalid")
        self.clients = clients
        self.journal = journal
        self.expected_account_id = expected_account_id
        if authorized_until_epoch is not None and (type(authorized_until_epoch) is not int or authorized_until_epoch <= 0):
            raise RehearsalError("authorization_window_invalid")
        self.authorized_until_epoch = authorized_until_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.started = 0.0
        self.calls = 0

    def _call(self, service: str, operation: str, **kwargs: Any) -> Any:
        if self.monotonic() - self.started >= STEP_BUDGET_SECONDS:
            raise RehearsalError("step_budget_exhausted")
        self.calls += 1
        try:
            return getattr(self.clients[service], operation)(**kwargs)
        except Exception as exc:
            raise _AwsFailure(_error_code(exc), _error_message(exc)) from None

    def _require_state(self) -> dict[str, Any]:
        state = self.journal.load()
        if state is None or state.get("schema") != 1 or state.get("region") != REGION:
            raise RehearsalError("preflight_required")
        return state

    def _check_write_window(self, state: Mapping[str, Any]) -> None:
        saved_deadline = state.get("authorized_until_epoch")
        configured_deadline = self.authorized_until_epoch
        if type(saved_deadline) is not int or type(configured_deadline) is not int:
            raise RehearsalError("authorization_window_invalid")
        # A later CLI invocation may shorten the effective window, never extend
        # the immutable deadline recorded during preflight.
        deadline = min(saved_deadline, configured_deadline)
        now = self.wall_clock()
        if type(now) not in (int, float) or now >= deadline:
            raise RehearsalError("authorization_window_expired")

    def _check_identity(self, state: dict[str, Any] | None = None) -> None:
        identity = self._call("sts", "get_caller_identity")
        account = identity.get("Account") if isinstance(identity, Mapping) else None
        arn = identity.get("Arn") if isinstance(identity, Mapping) else None
        if type(account) is not str or account != self.expected_account_id:
            raise RehearsalError("account_mismatch")
        match = _IDENTITY_ARN.fullmatch(arn) if type(arn) is str else None
        if match is None or match.group(1) != account or arn.endswith(":root"):
            raise RehearsalError("root_identity_rejected")
        if state is not None and account != state.get("account_id"):
            raise RehearsalError("account_mismatch")

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in STEPS:
            return _safe_result("unknown", False, "step_invalid", 0)
        try:
            with self.journal.locked():
                self.started = self.monotonic()
                self.calls = 0
                result = getattr(self, f"_step_{step.replace('-', '_')}")()
                return _safe_result(step, result[0], result[1], self.calls, **result[2])
        except RehearsalError as exc:
            return _safe_result(step, False, exc.category, self.calls)
        except _AwsFailure:
            return _safe_result(step, False, "aws_call_failed", self.calls)
        except Exception:
            return _safe_result(step, False, "runner_internal_error", self.calls)

    def _step_preflight(self) -> tuple[bool, str, dict[str, int]]:
        if self.journal.load() is not None:
            raise RehearsalError("run_already_initialized")
        self._check_identity()
        limits = self._call("lambda", "get_account_settings")
        account_limit = limits.get("AccountLimit", {}) if isinstance(limits, Mapping) else {}
        total = account_limit.get("ConcurrentExecutions") if isinstance(account_limit, Mapping) else None
        unreserved = account_limit.get("UnreservedConcurrentExecutions") if isinstance(account_limit, Mapping) else None
        if type(total) is not int or total != 10 or type(unreserved) is not int or unreserved != 10:
            raise RehearsalError("capacity_preflight_failed")
        for stack_name in (APP_STACK_NAME, CONTROL_STACK_NAME):
            try:
                response = self._call("cloudformation", "describe_stacks", StackName=stack_name)
            except _AwsFailure as exc:
                if exc.code == "ValidationError" and ("does not exist" in exc.message or "not found" in exc.message):
                    continue
                raise
            if not isinstance(response, Mapping) or type(response.get("Stacks")) is not list:
                raise RehearsalError("stack_inventory_invalid")
            stacks = response["Stacks"]
            if stacks:
                raise RehearsalError("preexisting_stack_rejected")

        self._expect_absent("lambda", "get_function", {"FunctionName": FUNCTION_NAME})
        self._expect_absent("iam", "get_role", {"RoleName": HANDLER_ROLE_NAME})
        logs = self._call("logs", "describe_log_groups", logGroupNamePrefix=LOG_GROUP_NAME)
        if not isinstance(logs, Mapping) or type(logs.get("logGroups")) is not list:
            raise RehearsalError("resource_inventory_invalid")
        groups = logs.get("logGroups", []) if isinstance(logs, Mapping) else []
        if any(isinstance(x, Mapping) and x.get("logGroupName") == LOG_GROUP_NAME for x in groups):
            raise RehearsalError("preexisting_resource_rejected")
        if isinstance(logs, Mapping) and logs.get("nextToken"):
            raise RehearsalError("resource_inventory_incomplete")
        apis = self._call("apigatewayv2", "get_apis", MaxResults="100")
        if not isinstance(apis, Mapping) or type(apis.get("Items")) is not list:
            raise RehearsalError("resource_inventory_invalid")
        items = apis.get("Items", []) if isinstance(apis, Mapping) else []
        if any(isinstance(x, Mapping) and x.get("Name") == API_NAME for x in items):
            raise RehearsalError("preexisting_resource_rejected")
        if isinstance(apis, Mapping) and apis.get("NextToken"):
            raise RehearsalError("resource_inventory_incomplete")
        pools = self._call("cognito", "list_user_pools", MaxResults=60)
        if not isinstance(pools, Mapping) or type(pools.get("UserPools")) is not list:
            raise RehearsalError("resource_inventory_invalid")
        user_pools = pools.get("UserPools", []) if isinstance(pools, Mapping) else []
        if any(isinstance(x, Mapping) and x.get("Name") == USER_POOL_NAME for x in user_pools):
            raise RehearsalError("preexisting_resource_rejected")
        if isinstance(pools, Mapping) and pools.get("NextToken"):
            raise RehearsalError("resource_inventory_incomplete")

        for role_name in CONTROL_ROLE_NAMES:
            self._expect_absent("iam", "get_role", {"RoleName": role_name})
        for group_name in SCHEDULE_GROUP_NAMES:
            try:
                self._call("scheduler", "get_schedule_group", Name=group_name)
            except _AwsFailure as exc:
                if _is_not_found(exc):
                    continue
                raise
            raise RehearsalError("preexisting_resource_rejected")
        for group_name, schedule_name in zip(SCHEDULE_GROUP_NAMES, SCHEDULE_NAMES, strict=True):
            try:
                self._call("scheduler", "get_schedule", Name=schedule_name, GroupName=group_name)
            except _AwsFailure as exc:
                if _is_not_found(exc):
                    continue
                raise
            raise RehearsalError("preexisting_resource_rejected")
        try:
            self._call(
                "stepfunctions", "describe_state_machine",
                stateMachineArn=f"arn:aws:states:{REGION}:{self.expected_account_id}:stateMachine:{STATE_MACHINE_NAME}",
            )
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            raise RehearsalError("preexisting_resource_rejected")
        alarms = self._call("cloudwatch", "describe_alarms", AlarmNames=[ALARM_NAME])
        if not isinstance(alarms, Mapping) or type(alarms.get("MetricAlarms")) is not list:
            raise RehearsalError("resource_inventory_invalid")
        if alarms["MetricAlarms"]:
            raise RehearsalError("preexisting_resource_rejected")
        try:
            self._call("events", "describe_rule", Name=EVENT_RULE_NAME)
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            raise RehearsalError("preexisting_resource_rejected")

        state = {
            "schema": 1,
            "region": REGION,
            "account_id": self.expected_account_id,
            "authorized_until_epoch": self.authorized_until_epoch,
            "run_id": str(uuid.uuid4()),
            "app_client_token": uuid.uuid4().hex,
            "control_client_token": uuid.uuid4().hex,
            "app_create_attempted": False,
            "control_create_attempted": False,
            "app_verified": False,
            "controls_verified": False,
            "shutdown_arm_attempted": False,
            "shutdown_verified": False,
            "cleanup_arm_attempted": False,
            "app_deleted_verified": False,
            "control_delete_attempted": False,
        }
        self.journal.save(state)
        return True, "preflight_passed", {"stacks_absent": 2, "named_resources_absent": 17}

    def _expect_absent(self, service: str, operation: str, kwargs: dict[str, Any]) -> None:
        try:
            self._call(service, operation, **kwargs)
        except _AwsFailure as exc:
            if _is_not_found(exc):
                return
            raise
        raise RehearsalError("preexisting_resource_rejected")

    def _step_create_app(self) -> tuple[bool, str, dict[str, int]]:
        state = self._require_state()
        self._check_write_window(state)
        self._check_identity(state)
        if state.get("app_create_attempted"):
            raise RehearsalError("write_already_attempted")
        template = fixed_bootstrap_template()
        started = int(self.wall_clock())
        state["resource_started_epoch"] = started
        state["app_create_attempted"] = True
        self.journal.save(state)
        try:
            self._check_write_window(state)
            result = self._call(
                "cloudformation", "create_stack",
                StackName=APP_STACK_NAME,
                TemplateBody=_json_bytes(template).decode("utf-8"),
                Parameters=[{"ParameterKey": "EnvironmentName", "ParameterValue": "dev"}],
                Capabilities=["CAPABILITY_NAMED_IAM"],
                OnFailure="DO_NOTHING",
                Tags=[{"Key": RUN_TAG, "Value": state["run_id"]}],
                ClientRequestToken=state["app_client_token"],
            )
        except _AwsFailure:
            state["app_create_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("app_create_ambiguous") from None
        stack_id = result.get("StackId") if isinstance(result, Mapping) else None
        try:
            stack_id = self._validate_stack_arn(stack_id, self.expected_account_id, APP_STACK_NAME)
        except RehearsalError:
            state["app_create_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("app_create_response_invalid")
        state["app_stack_id"] = stack_id
        self.journal.save(state)
        return True, "app_create_requested", {"resources_requested": 6}

    def _step_check_app(self) -> tuple[bool, str, dict[str, int]]:
        state = self._require_state()
        self._check_identity(state)
        if not state.get("app_create_attempted"):
            raise RehearsalError("app_create_not_attempted")
        stack_id = state.get("app_stack_id")
        lookup = stack_id if type(stack_id) is str else APP_STACK_NAME
        try:
            response = self._call("cloudformation", "describe_stacks", StackName=lookup)
        except _AwsFailure as exc:
            if _is_not_found(exc):
                raise RehearsalError("app_creation_unresolved") from None
            raise
        stacks = response.get("Stacks", []) if isinstance(response, Mapping) else []
        if len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RehearsalError("app_stack_readback_invalid")
        stack = stacks[0]
        if stack.get("StackName") != APP_STACK_NAME or not self._has_run_tag(stack.get("Tags"), state["run_id"]):
            raise RehearsalError("stack_ownership_unverified")
        actual_id = stack.get("StackId")
        if type(actual_id) is not str or (stack_id is not None and actual_id != stack_id):
            raise RehearsalError("app_stack_readback_invalid")
        if stack_id is None:
            events = self._call("cloudformation", "describe_stack_events", StackName=actual_id)
            records = events.get("StackEvents", []) if isinstance(events, Mapping) else []
            if not any(isinstance(x, Mapping) and x.get("ClientRequestToken") == state["app_client_token"] for x in records):
                raise RehearsalError("stack_ownership_unverified")
            state["app_stack_id"] = actual_id
            self.journal.save(state)
        status = stack.get("StackStatus")
        if status != "CREATE_COMPLETE":
            if status in {"CREATE_IN_PROGRESS", "REVIEW_IN_PROGRESS"}:
                return False, "app_create_pending", {"resources_verified": 0}
            raise RehearsalError("app_create_failed")
        stack_uuid = self._stack_uuid(actual_id)
        resource_response = self._call("cloudformation", "describe_stack_resources", StackName=actual_id)
        resources = resource_response.get("StackResources", []) if isinstance(resource_response, Mapping) else []
        expected = {
            "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
        }
        if any(not isinstance(item, Mapping) for item in resources):
            raise RehearsalError("app_resources_unverified")
        by_name = {x.get("LogicalResourceId"): x for x in resources if isinstance(x, Mapping)}
        if set(by_name) != expected or any(item.get("ResourceStatus") != "CREATE_COMPLETE" for item in by_name.values()):
            raise RehearsalError("app_resources_unverified")
        api_id = by_name["McpApi"].get("PhysicalResourceId")
        pool_id = by_name["McpUserPool"].get("PhysicalResourceId")
        if by_name["McpHandler"].get("PhysicalResourceId") != FUNCTION_NAME:
            raise RehearsalError("app_resource_id_invalid")
        if by_name["McpHandlerRole"].get("PhysicalResourceId") != HANDLER_ROLE_NAME:
            raise RehearsalError("app_resource_id_invalid")
        if by_name["McpHandlerLogGroup"].get("PhysicalResourceId") != LOG_GROUP_NAME:
            raise RehearsalError("app_resource_id_invalid")
        if type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id):
            raise RehearsalError("app_resource_id_invalid")
        if type(pool_id) is not str or not re.fullmatch(r"eu-west-1_[A-Za-z0-9]{9,45}", pool_id):
            raise RehearsalError("app_resource_id_invalid")
        api = self._call("apigatewayv2", "get_api", ApiId=api_id)
        if not isinstance(api, Mapping):
            raise RehearsalError("app_endpoint_readback_invalid")
        if api.get("DisableExecuteApiEndpoint") is not True or api.get("Name") != API_NAME:
            raise RehearsalError("app_endpoint_not_closed")
        routes = self._call("apigatewayv2", "get_routes", ApiId=api_id, MaxResults="100")
        if not isinstance(routes, Mapping) or type(routes.get("Items")) is not list:
            raise RehearsalError("app_routes_unverified")
        if routes.get("Items") or routes.get("NextToken"):
            raise RehearsalError("app_routes_unexpected")
        function = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
        if not isinstance(function, Mapping):
            raise RehearsalError("app_function_readback_invalid")
        reserved = function.get("ReservedConcurrentExecutions")
        if type(reserved) is not int or reserved != 0:
            raise RehearsalError("app_function_not_reserved_zero")
        users = self._call("cognito", "list_users", UserPoolId=pool_id, Limit=1)
        clients = self._call("cognito", "list_user_pool_clients", UserPoolId=pool_id, MaxResults=1)
        if not isinstance(users, Mapping) or type(users.get("Users")) is not list:
            raise RehearsalError("app_identity_readback_invalid")
        if not isinstance(clients, Mapping) or type(clients.get("UserPoolClients")) is not list:
            raise RehearsalError("app_identity_readback_invalid")
        if users.get("Users") or users.get("PaginationToken") or clients.get("UserPoolClients") or clients.get("NextToken"):
            raise RehearsalError("app_identity_resources_unexpected")
        state.update({"app_verified": True, "app_stack_id": actual_id, "stack_uuid": stack_uuid, "api_id": api_id, "user_pool_id": pool_id})
        self.journal.save(state)
        return True, "app_verified_closed", {"resources_verified": 6, "routes": 0, "users": 0, "clients": 0}

    @staticmethod
    def _has_run_tag(tags: Any, run_id: str) -> bool:
        return isinstance(tags, list) and any(
            isinstance(tag, Mapping) and tag.get("Key") == RUN_TAG and tag.get("Value") == run_id
            for tag in tags
        )

    @staticmethod
    def _stack_uuid(stack_id: str) -> str:
        suffix = stack_id.rsplit("/", 1)[-1]
        try:
            parsed = uuid.UUID(suffix)
        except (ValueError, AttributeError):
            raise RehearsalError("app_stack_id_invalid") from None
        if str(parsed) != suffix or parsed.int == 0:
            raise RehearsalError("app_stack_id_invalid")
        return suffix

    def _control_template(self, state: Mapping[str, Any]) -> dict[str, Any]:
        policy = AwsDevShutdownPolicy(state.get("api_id"), region=REGION)
        return build_dev_bootstrap_control_bundle(
            policy,
            user_pool_id=state.get("user_pool_id"),
            stack_uuid=state.get("stack_uuid"),
            resource_started_epoch=state.get("resource_started_epoch"),
            activation_start_epoch=state.get("activation_start_epoch"),
            now_epoch=state.get("controls_created_at_epoch"),
        )

    def _owned_stack(self, *, stack_name: str, stack_id_key: str, token_key: str, state: dict[str, Any]) -> tuple[str, Mapping[str, Any]]:
        saved_id = state.get(stack_id_key)
        lookup = saved_id if type(saved_id) is str else stack_name
        response = self._call("cloudformation", "describe_stacks", StackName=lookup)
        stacks = response.get("Stacks") if isinstance(response, Mapping) else None
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RehearsalError("stack_readback_invalid")
        stack = stacks[0]
        actual_id = self._validate_stack_arn(stack.get("StackId"), self.expected_account_id, stack_name)
        if stack.get("StackName") != stack_name or not self._has_run_tag(stack.get("Tags"), state["run_id"]):
            raise RehearsalError("stack_ownership_unverified")
        if saved_id is not None and saved_id != actual_id:
            raise RehearsalError("stack_readback_invalid")
        if saved_id is None:
            events = self._call("cloudformation", "describe_stack_events", StackName=actual_id)
            records = events.get("StackEvents") if isinstance(events, Mapping) else None
            if type(records) is not list or not any(
                isinstance(item, Mapping) and item.get("ClientRequestToken") == state.get(token_key)
                for item in records
            ):
                raise RehearsalError("stack_ownership_unverified")
            state[stack_id_key] = actual_id
            self.journal.save(state)
        return actual_id, stack

    def _resource_map(self, stack_id: str, expected: set[str]) -> dict[str, Mapping[str, Any]]:
        response = self._call("cloudformation", "describe_stack_resources", StackName=stack_id)
        resources = response.get("StackResources") if isinstance(response, Mapping) else None
        if type(resources) is not list or any(not isinstance(item, Mapping) for item in resources):
            raise RehearsalError("stack_resources_invalid")
        mapping = {item.get("LogicalResourceId"): item for item in resources}
        if set(mapping) != expected or any(item.get("ResourceStatus") != "CREATE_COMPLETE" for item in mapping.values()):
            raise RehearsalError("stack_resources_unverified")
        return mapping

    def _schedule_readback(self, name: str, group: str) -> Mapping[str, Any]:
        response = self._call("scheduler", "get_schedule", Name=name, GroupName=group)
        if not isinstance(response, Mapping):
            raise RehearsalError("schedule_readback_invalid")
        return response

    @staticmethod
    def _schedule_update_args(response: Mapping[str, Any], state: str) -> dict[str, Any]:
        required = ("Name", "GroupName", "ScheduleExpression", "FlexibleTimeWindow", "Target")
        if any(key not in response for key in required):
            raise RehearsalError("schedule_readback_invalid")
        args = {key: response[key] for key in required}
        args["State"] = state
        for key in ("ScheduleExpressionTimezone", "Description", "StartDate", "EndDate", "KmsKeyArn"):
            if key in response:
                args[key] = response[key]
        return args

    def _verify_app_closed(self, state: Mapping[str, Any]) -> None:
        api_id = state.get("api_id")
        if type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id):
            raise RehearsalError("app_resource_id_invalid")
        api = self._call("apigatewayv2", "get_api", ApiId=api_id)
        function = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
        if not isinstance(api, Mapping) or api.get("DisableExecuteApiEndpoint") is not True:
            raise RehearsalError("app_endpoint_not_closed")
        if not isinstance(function, Mapping) or type(function.get("ReservedConcurrentExecutions")) is not int or function["ReservedConcurrentExecutions"] != 0:
            raise RehearsalError("app_function_not_reserved_zero")

    def _verify_schedule_safety(self, response: Mapping[str, Any], *, kind: str, desired_state: str) -> None:
        target = response.get("Target")
        if not isinstance(target, Mapping):
            raise RehearsalError("schedule_readback_invalid")
        if set(target) != {"Arn", "RoleArn", "Input", "RetryPolicy"}:
            raise RehearsalError("schedule_target_unverified")
        retry = target.get("RetryPolicy")
        if not isinstance(retry, Mapping) or type(retry.get("MaximumRetryAttempts")) is not int or retry.get("MaximumRetryAttempts") != 0:
            raise RehearsalError("schedule_retry_policy_invalid")
        if type(retry.get("MaximumEventAgeInSeconds")) is not int or retry.get("MaximumEventAgeInSeconds") != 60:
            raise RehearsalError("schedule_retry_policy_invalid")
        if response.get("State") != desired_state or response.get("ScheduleExpressionTimezone") != "UTC":
            raise RehearsalError("schedule_readback_invalid")
        if response.get("FlexibleTimeWindow") != {"Mode": "OFF"}:
            raise RehearsalError("schedule_readback_invalid")
        account = self.expected_account_id
        if kind == "shutdown":
            expected_name, expected_group = SCHEDULE_NAMES[0], SCHEDULE_GROUP_NAMES[0]
            expected_arn = f"arn:aws:states:{REGION}:{account}:stateMachine:{STATE_MACHINE_NAME}"
            expected_role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-shutdown-scheduler"
            expected_input = "{}"
        else:
            expected_name, expected_group = SCHEDULE_NAMES[1], SCHEDULE_GROUP_NAMES[1]
            expected_arn = "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
            expected_role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-bootstrap-cleanup-scheduler"
            expected_input = None
        if response.get("Name") != expected_name or response.get("GroupName") != expected_group:
            raise RehearsalError("schedule_readback_invalid")
        if target.get("Arn") != expected_arn or target.get("RoleArn") != expected_role:
            raise RehearsalError("schedule_target_unverified")
        if kind == "shutdown" and target.get("Input") != expected_input:
            raise RehearsalError("schedule_target_unverified")
        if kind == "cleanup":
            try:
                payload = json.loads(target.get("Input"), object_pairs_hook=_duplicate_reject)
            except Exception:
                raise RehearsalError("schedule_target_unverified") from None
            expected_payload = {
                "StackName": self._require_state().get("app_stack_id"),
                "RoleARN": f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-bootstrap-delete",
            }
            if not isinstance(payload, Mapping) or dict(payload) != expected_payload:
                raise RehearsalError("schedule_target_unverified")

    @staticmethod
    def _schedule_expression_for_epoch(epoch: int) -> str:
        try:
            stamp = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except (OverflowError, OSError, ValueError):
            raise RehearsalError("schedule_time_invalid") from None
        return f"at({stamp})"

    def _verify_app_resources_absent(self) -> None:
        self._expect_absent("lambda", "get_function", {"FunctionName": FUNCTION_NAME})
        self._expect_absent("iam", "get_role", {"RoleName": HANDLER_ROLE_NAME})
        logs = self._call("logs", "describe_log_groups", logGroupNamePrefix=LOG_GROUP_NAME)
        groups = logs.get("logGroups") if isinstance(logs, Mapping) else None
        if type(groups) is not list or logs.get("nextToken"):
            raise RehearsalError("resource_inventory_invalid")
        if any(isinstance(item, Mapping) and item.get("logGroupName") == LOG_GROUP_NAME for item in groups):
            raise RehearsalError("app_resource_remains")
        apis = self._call("apigatewayv2", "get_apis", MaxResults="100")
        items = apis.get("Items") if isinstance(apis, Mapping) else None
        if type(items) is not list or apis.get("NextToken"):
            raise RehearsalError("resource_inventory_invalid")
        if any(isinstance(item, Mapping) and item.get("Name") == API_NAME for item in items):
            raise RehearsalError("app_resource_remains")
        pools = self._call("cognito", "list_user_pools", MaxResults=60)
        user_pools = pools.get("UserPools") if isinstance(pools, Mapping) else None
        if type(user_pools) is not list or pools.get("NextToken"):
            raise RehearsalError("resource_inventory_invalid")
        if any(isinstance(item, Mapping) and item.get("Name") == USER_POOL_NAME for item in user_pools):
            raise RehearsalError("app_resource_remains")

    def _verify_control_resources_absent(self) -> None:
        for role_name in CONTROL_ROLE_NAMES:
            self._expect_absent("iam", "get_role", {"RoleName": role_name})
        for group_name in SCHEDULE_GROUP_NAMES:
            try:
                self._call("scheduler", "get_schedule_group", Name=group_name)
            except _AwsFailure as exc:
                if _is_not_found(exc):
                    continue
                raise
            raise RehearsalError("control_resource_remains")
        for group_name, schedule_name in zip(SCHEDULE_GROUP_NAMES, SCHEDULE_NAMES, strict=True):
            try:
                self._call("scheduler", "get_schedule", Name=schedule_name, GroupName=group_name)
            except _AwsFailure as exc:
                if _is_not_found(exc):
                    continue
                raise
            raise RehearsalError("control_resource_remains")
        machine_arn = f"arn:aws:states:{REGION}:{self.expected_account_id}:stateMachine:{STATE_MACHINE_NAME}"
        try:
            self._call("stepfunctions", "describe_state_machine", stateMachineArn=machine_arn)
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            raise RehearsalError("control_resource_remains")
        alarms = self._call("cloudwatch", "describe_alarms", AlarmNames=[ALARM_NAME])
        items = alarms.get("MetricAlarms") if isinstance(alarms, Mapping) else None
        if type(items) is not list or any(not isinstance(item, Mapping) for item in items):
            raise RehearsalError("resource_inventory_invalid")
        if any(item.get("AlarmName") == ALARM_NAME for item in items):
            raise RehearsalError("control_resource_remains")
        try:
            self._call("events", "describe_rule", Name=EVENT_RULE_NAME)
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            raise RehearsalError("control_resource_remains")

    @staticmethod
    def _validate_stack_arn(stack_id: Any, account_id: str, stack_name: str) -> str:
        if type(stack_id) is not str:
            raise RehearsalError("stack_id_invalid")
        parts = stack_id.split(":", 5)
        if len(parts) != 6 or parts[:5] != ["arn", "aws", "cloudformation", REGION, account_id]:
            raise RehearsalError("stack_id_invalid")
        resource_parts = parts[5].split("/")
        if len(resource_parts) != 3 or resource_parts[0] != "stack" or resource_parts[1] != stack_name:
            raise RehearsalError("stack_id_invalid")
        AwsClosedRehearsal._stack_uuid(resource_parts[2])
        return stack_id

    def _step_create_controls(self):
        state = self._require_state()
        self._check_identity(state)
        self._check_write_window(state)
        if not state.get("app_verified") or state.get("controls_create_attempted"):
            raise RehearsalError("controls_create_not_authorized")
        self._verify_app_closed(state)
        now = int(self.wall_clock())
        activation_start = now + 180
        template = build_dev_bootstrap_control_bundle(
            AwsDevShutdownPolicy(state.get("api_id"), region=REGION),
            user_pool_id=state.get("user_pool_id"),
            stack_uuid=state.get("stack_uuid"),
            resource_started_epoch=state.get("resource_started_epoch"),
            activation_start_epoch=activation_start,
            now_epoch=now,
        )
        state.update({
            "activation_start_epoch": activation_start,
            "controls_created_at_epoch": now,
            "controls_create_attempted": True,
            "shutdown_schedule_expression": template["Resources"]["ShutdownSchedule"]["Properties"]["ScheduleExpression"],
            "cleanup_schedule_expression": template["Resources"]["BootstrapCleanupSchedule"]["Properties"]["ScheduleExpression"],
        })
        self.journal.save(state)
        try:
            self._check_write_window(state)
            response = self._call(
                "cloudformation", "create_stack",
                StackName=CONTROL_STACK_NAME,
                TemplateBody=_json_bytes(template).decode("utf-8"),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                OnFailure="DO_NOTHING",
                Tags=[{"Key": RUN_TAG, "Value": state["run_id"]}],
                ClientRequestToken=state["control_client_token"],
            )
        except _AwsFailure:
            state["controls_create_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("controls_create_ambiguous") from None
        control_id = response.get("StackId") if isinstance(response, Mapping) else None
        try:
            control_id = self._validate_stack_arn(control_id, self.expected_account_id, CONTROL_STACK_NAME)
        except RehearsalError:
            state["controls_create_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("controls_create_response_invalid") from None
        state["control_stack_id"] = control_id
        self.journal.save(state)
        return True, "controls_create_requested", {"resources_requested": 12}

    def _step_check_controls(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("controls_create_attempted"):
            raise RehearsalError("controls_create_not_attempted")
        stack_id, stack = self._owned_stack(
            stack_name=CONTROL_STACK_NAME, stack_id_key="control_stack_id",
            token_key="control_client_token", state=state,
        )
        if stack.get("StackStatus") != "CREATE_COMPLETE":
            return False, "controls_create_pending", {"resources_verified": 0}
        expected_template = self._control_template(state)
        template_response = self._call("cloudformation", "get_template", StackName=stack_id, TemplateStage="Original")
        body = template_response.get("TemplateBody") if isinstance(template_response, Mapping) else None
        try:
            deployed = json.loads(body, object_pairs_hook=_duplicate_reject) if type(body) is str else body
        except Exception:
            raise RehearsalError("controls_template_unverified") from None
        if not isinstance(deployed, Mapping) or _json_bytes(deployed) != _json_bytes(expected_template):
            raise RehearsalError("controls_template_unverified")
        expected_names = set(expected_template["Resources"])
        by_name = self._resource_map(stack_id, expected_names)
        self._verify_app_closed(state)
        shutdown_group = by_name["SchedulerGroup"].get("PhysicalResourceId")
        cleanup_group = by_name["BootstrapCleanupScheduleGroup"].get("PhysicalResourceId")
        if shutdown_group != SCHEDULE_GROUP_NAMES[0] or cleanup_group != SCHEDULE_GROUP_NAMES[1]:
            raise RehearsalError("control_resource_id_invalid")
        shutdown_schedule = self._schedule_readback(SCHEDULE_NAMES[0], SCHEDULE_GROUP_NAMES[0])
        cleanup_schedule = self._schedule_readback(SCHEDULE_NAMES[1], SCHEDULE_GROUP_NAMES[1])
        if shutdown_schedule.get("State") != "DISABLED" or shutdown_schedule.get("ScheduleExpression") != state.get("shutdown_schedule_expression"):
            raise RehearsalError("shutdown_schedule_unverified")
        if cleanup_schedule.get("State") != "DISABLED" or cleanup_schedule.get("ScheduleExpression") != state.get("cleanup_schedule_expression"):
            raise RehearsalError("cleanup_schedule_unverified")
        alarm = self._call("cloudwatch", "describe_alarms", AlarmNames=[ALARM_NAME])
        alarms = alarm.get("MetricAlarms") if isinstance(alarm, Mapping) else None
        if type(alarms) is not list or len(alarms) != 1 or not isinstance(alarms[0], Mapping):
            raise RehearsalError("tripwire_alarm_unverified")
        alarm = alarms[0]
        expected_dimensions = [
            {"Name": "ApiId", "Value": state["api_id"]},
            {"Name": "Stage", "Value": "$default"},
        ]
        if not (
            alarm.get("AlarmName") == ALARM_NAME
            and alarm.get("Namespace") == "AWS/ApiGateway"
            and alarm.get("MetricName") == "Count"
            and alarm.get("Dimensions") == expected_dimensions
            and alarm.get("Period") == 60
            and alarm.get("Statistic") == "SampleCount"
            and alarm.get("Threshold") == 100.0
            and alarm.get("ComparisonOperator") == "GreaterThanOrEqualToThreshold"
            and alarm.get("EvaluationPeriods") == 1
            and alarm.get("DatapointsToAlarm") == 1
            and alarm.get("TreatMissingData") == "notBreaching"
            and alarm.get("ActionsEnabled") is False
            and alarm.get("AlarmActions") == []
        ):
            raise RehearsalError("tripwire_alarm_unverified")
        rule = self._call("events", "describe_rule", Name=EVENT_RULE_NAME)
        if not isinstance(rule, Mapping) or rule.get("State") != "DISABLED" or rule.get("Name") != EVENT_RULE_NAME:
            raise RehearsalError("tripwire_rule_unverified")
        try:
            pattern = json.loads(rule.get("EventPattern"), object_pairs_hook=_duplicate_reject)
        except Exception:
            raise RehearsalError("tripwire_rule_unverified") from None
        alarm_arn = alarm.get("AlarmArn")
        expected_pattern = {
            "source": ["aws.cloudwatch"],
            "detail-type": ["CloudWatch Alarm State Change"],
            "account": [self.expected_account_id],
            "region": [REGION],
            "resources": [alarm_arn],
            "detail": {"alarmName": [ALARM_NAME], "state": {"value": ["ALARM"]}},
        }
        if type(alarm_arn) is not str or not isinstance(pattern, Mapping) or dict(pattern) != expected_pattern:
            raise RehearsalError("tripwire_rule_unverified")
        targets_response = self._call("events", "list_targets_by_rule", Rule=EVENT_RULE_NAME)
        targets = targets_response.get("Targets") if isinstance(targets_response, Mapping) else None
        expected_event_target = {
            "Id": "StartFixedDevShutdownWorkflow",
            "Arn": state["state_machine_arn"],
            "RoleArn": f"arn:aws:iam::{self.expected_account_id}:role/honda-mapit-mcp-dev-request-tripwire",
            "Input": "{}",
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        }
        if type(targets) is not list or len(targets) != 1 or not isinstance(targets[0], Mapping) or dict(targets[0]) != expected_event_target:
            raise RehearsalError("tripwire_target_unverified")
        machine_arn = by_name["ShutdownStateMachine"].get("PhysicalResourceId")
        if type(machine_arn) is not str or machine_arn != f"arn:aws:states:{REGION}:{self.expected_account_id}:stateMachine:{STATE_MACHINE_NAME}":
            raise RehearsalError("shutdown_machine_unverified")
        machine = self._call("stepfunctions", "describe_state_machine", stateMachineArn=machine_arn)
        if not isinstance(machine, Mapping) or machine.get("status") != "ACTIVE":
            raise RehearsalError("shutdown_machine_unverified")
        state.update({"controls_verified": True, "control_stack_id": stack_id, "state_machine_arn": machine_arn})
        self.journal.save(state)
        return True, "controls_verified_disabled", {"resources_verified": 12, "schedules_disabled": 2}

    def _step_arm_shutdown(self):
        state = self._require_state()
        self._check_identity(state)
        self._check_write_window(state)
        if not state.get("controls_verified") or state.get("shutdown_arm_attempted"):
            raise RehearsalError("shutdown_arm_not_authorized")
        self._verify_app_closed(state)
        expected_at = state.get("shutdown_schedule_expression")
        response = self._schedule_readback(SCHEDULE_NAMES[0], SCHEDULE_GROUP_NAMES[0])
        if response.get("ScheduleExpression") != expected_at:
            raise RehearsalError("shutdown_schedule_unverified")
        self._verify_schedule_safety(response, kind="shutdown", desired_state="DISABLED")
        now = int(self.wall_clock())
        activation_start = now + 180
        fresh_template = build_dev_bootstrap_control_bundle(
            AwsDevShutdownPolicy(state.get("api_id"), region=REGION),
            user_pool_id=state.get("user_pool_id"), stack_uuid=state.get("stack_uuid"),
            resource_started_epoch=state.get("resource_started_epoch"),
            activation_start_epoch=activation_start, now_epoch=now,
        )
        fresh_expression = fresh_template["Resources"]["ShutdownSchedule"]["Properties"]["ScheduleExpression"]
        update = self._schedule_update_args(response, "ENABLED")
        update["ScheduleExpression"] = fresh_expression
        state["shutdown_arm_attempted"] = True
        state["shutdown_armed_schedule_expression"] = fresh_expression
        state["shutdown_armed_at_epoch"] = now
        self.journal.save(state)
        try:
            self._check_write_window(state)
            self._call("scheduler", "update_schedule", **update)
        except _AwsFailure:
            state["shutdown_arm_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("shutdown_arm_ambiguous") from None
        state["shutdown_arm_call_returned"] = True
        self.journal.save(state)
        return True, "shutdown_arm_requested", {"schedule_updates": 1}

    def _step_check_shutdown(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("shutdown_arm_attempted"):
            raise RehearsalError("shutdown_not_armed")
        schedule = self._schedule_readback(SCHEDULE_NAMES[0], SCHEDULE_GROUP_NAMES[0])
        if schedule.get("ScheduleExpression") != state.get("shutdown_armed_schedule_expression"):
            raise RehearsalError("shutdown_schedule_not_enabled")
        self._verify_schedule_safety(schedule, kind="shutdown", desired_state="ENABLED")
        self._verify_app_closed(state)
        machine_arn = state.get("state_machine_arn")
        executions = self._call("stepfunctions", "list_executions", stateMachineArn=machine_arn, maxResults=1)
        items = executions.get("executions") if isinstance(executions, Mapping) else None
        if type(items) is not list:
            raise RehearsalError("shutdown_execution_readback_invalid")
        if not items:
            return False, "shutdown_pending", {"executions": 0}
        item = items[0]
        if not isinstance(item, Mapping) or item.get("status") in {"RUNNING", "PENDING_REDRIVE"}:
            return False, "shutdown_pending", {"executions": 1}
        if item.get("status") != "SUCCEEDED":
            raise RehearsalError("shutdown_execution_failed")
        execution_arn = item.get("executionArn")
        if type(execution_arn) is not str or not execution_arn.startswith(f"arn:aws:states:{REGION}:{self.expected_account_id}:execution:{STATE_MACHINE_NAME}:"):
            raise RehearsalError("shutdown_execution_readback_invalid")
        execution = self._call("stepfunctions", "describe_execution", executionArn=execution_arn)
        if not isinstance(execution, Mapping) or execution.get("stateMachineArn") != machine_arn or execution.get("status") != "SUCCEEDED":
            raise RehearsalError("shutdown_execution_readback_invalid")
        output_raw = execution.get("output") if isinstance(execution, Mapping) else None
        try:
            output = json.loads(output_raw, object_pairs_hook=_duplicate_reject) if type(output_raw) is str else None
        except Exception:
            raise RehearsalError("shutdown_execution_readback_invalid") from None
        if not isinstance(output, Mapping):
            raise RehearsalError("shutdown_execution_readback_invalid")
        for key in ("verified", "api_closed", "function_reserved", "api_write_call_returned", "function_write_call_returned"):
            if type(output.get(key)) is not bool or output[key] is not True:
                raise RehearsalError("shutdown_execution_unverified")
        if output.get("category") != "shutdown_verified":
            raise RehearsalError("shutdown_execution_unverified")
        self._verify_app_closed(state)
        state["shutdown_verified"] = True
        self.journal.save(state)
        return True, "shutdown_verified_closed", {"executions": 1}

    def _step_arm_cleanup(self):
        state = self._require_state()
        self._check_identity(state)
        self._check_write_window(state)
        if not state.get("controls_verified") or not state.get("shutdown_verified") or state.get("cleanup_arm_attempted"):
            raise RehearsalError("cleanup_arm_not_authorized")
        self._verify_app_closed(state)
        expected_at = state.get("cleanup_schedule_expression")
        response = self._schedule_readback(SCHEDULE_NAMES[1], SCHEDULE_GROUP_NAMES[1])
        if response.get("ScheduleExpression") != expected_at:
            raise RehearsalError("cleanup_schedule_unverified")
        self._verify_schedule_safety(response, kind="cleanup", desired_state="DISABLED")
        now = int(self.wall_clock())
        cleanup_deadline = state.get("resource_started_epoch")
        if type(cleanup_deadline) is not int:
            raise RehearsalError("schedule_time_invalid")
        cleanup_epoch = cleanup_deadline + 2700
        new_epoch = now + 120
        if new_epoch >= cleanup_epoch:
            raise RehearsalError("cleanup_window_expired")
        fresh_expression = self._schedule_expression_for_epoch(new_epoch)
        update = self._schedule_update_args(response, "ENABLED")
        update["ScheduleExpression"] = fresh_expression
        state["cleanup_arm_attempted"] = True
        state["cleanup_armed_schedule_expression"] = fresh_expression
        state["cleanup_armed_at_epoch"] = now
        self.journal.save(state)
        try:
            self._check_write_window(state)
            self._call("scheduler", "update_schedule", **update)
        except _AwsFailure:
            state["cleanup_arm_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("cleanup_arm_ambiguous") from None
        state["cleanup_arm_call_returned"] = True
        self.journal.save(state)
        return True, "cleanup_arm_requested", {"schedule_updates": 1}

    def _step_check_cleanup(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("cleanup_arm_attempted") and not state.get("app_delete_attempted"):
            raise RehearsalError("cleanup_not_armed")
        if state.get("cleanup_arm_attempted"):
            schedule = self._schedule_readback(SCHEDULE_NAMES[1], SCHEDULE_GROUP_NAMES[1])
            if schedule.get("ScheduleExpression") != state.get("cleanup_armed_schedule_expression"):
                raise RehearsalError("cleanup_schedule_not_enabled")
            self._verify_schedule_safety(schedule, kind="cleanup", desired_state="ENABLED")
        try:
            response = self._call("cloudformation", "describe_stacks", StackName=state.get("app_stack_id"))
        except _AwsFailure as exc:
            if _is_not_found(exc):
                self._verify_app_resources_absent()
                state["app_deleted_verified"] = True
                self.journal.save(state)
                return True, "app_deleted_verified", {"stacks_remaining": 0}
            raise
        stacks = response.get("Stacks") if isinstance(response, Mapping) else None
        if type(stacks) is not list:
            raise RehearsalError("app_delete_readback_invalid")
        if not stacks:
            self._verify_app_resources_absent()
            state["app_deleted_verified"] = True
            self.journal.save(state)
            return True, "app_deleted_verified", {"stacks_remaining": 0}
        if len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RehearsalError("app_delete_readback_invalid")
        if (stacks[0].get("StackId") != state.get("app_stack_id")
                or stacks[0].get("StackName") != APP_STACK_NAME
                or not self._has_run_tag(stacks[0].get("Tags"), state.get("run_id"))):
            raise RehearsalError("stack_ownership_unverified")
        status = stacks[0].get("StackStatus")
        if status == "DELETE_COMPLETE":
            resources = self._call("cloudformation", "describe_stack_resources", StackName=state.get("app_stack_id"))
            entries = resources.get("StackResources") if isinstance(resources, Mapping) else None
            if type(entries) is not list or any(not isinstance(item, Mapping) for item in entries):
                raise RehearsalError("app_delete_readback_invalid")
            if any(item.get("ResourceStatus") != "DELETE_COMPLETE" for item in entries):
                raise RehearsalError("app_delete_failed")
            self._verify_app_resources_absent()
            state["app_deleted_verified"] = True
            self.journal.save(state)
            return True, "app_deleted_verified", {"stacks_remaining": 0}
        if status in {"DELETE_FAILED", "ROLLBACK_COMPLETE", "CREATE_FAILED"}:
            raise RehearsalError("app_delete_failed")
        return False, "app_delete_pending", {"stacks_remaining": 1}

    def _step_fallback_delete_app(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("app_create_attempted") or state.get("app_deleted_verified"):
            raise RehearsalError("app_delete_not_authorized")
        if state.get("app_delete_attempted"):
            raise RehearsalError("app_delete_already_attempted")
        stack_id = state.get("app_stack_id")
        lookup = stack_id if type(stack_id) is str else APP_STACK_NAME
        response = self._call("cloudformation", "describe_stacks", StackName=lookup)
        stacks = response.get("Stacks") if isinstance(response, Mapping) else None
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RehearsalError("app_stack_readback_invalid")
        stack = stacks[0]
        actual_id = self._validate_stack_arn(stack.get("StackId"), self.expected_account_id, APP_STACK_NAME)
        if stack.get("StackName") != APP_STACK_NAME or not self._has_run_tag(stack.get("Tags"), state["run_id"]):
            raise RehearsalError("stack_ownership_unverified")
        if stack_id is not None and actual_id != stack_id:
            raise RehearsalError("app_stack_readback_invalid")
        if stack_id is None:
            events = self._call("cloudformation", "describe_stack_events", StackName=actual_id)
            records = events.get("StackEvents") if isinstance(events, Mapping) else None
            if type(records) is not list or not any(
                isinstance(x, Mapping) and x.get("ClientRequestToken") == state.get("app_client_token")
                for x in records
            ):
                raise RehearsalError("stack_ownership_unverified")
            state["app_stack_id"] = actual_id
        resource_response = self._call("cloudformation", "describe_stack_resources", StackName=actual_id)
        resources = resource_response.get("StackResources") if isinstance(resource_response, Mapping) else None
        if type(resources) is not list or any(not isinstance(x, Mapping) for x in resources):
            raise RehearsalError("app_resources_unverified")
        allowed_logical = {"McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"}
        if any(x.get("LogicalResourceId") not in allowed_logical for x in resources):
            raise RehearsalError("app_resources_unexpected")
        api_resources = [x for x in resources if x.get("LogicalResourceId") == "McpApi"]
        function_resources = [x for x in resources if x.get("LogicalResourceId") == "McpHandler"]
        if len(api_resources) > 1 or len(function_resources) > 1:
            raise RehearsalError("app_resources_unexpected")
        if api_resources:
            api_id = api_resources[0].get("PhysicalResourceId")
            if api_id is None or api_id == "":
                api_id = None
            elif type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id):
                raise RehearsalError("app_resource_id_invalid")
            if api_id is not None:
                try:
                    api = self._call("apigatewayv2", "get_api", ApiId=api_id)
                except _AwsFailure as exc:
                    if not _is_not_found(exc):
                        raise
                else:
                    if not isinstance(api, Mapping) or api.get("DisableExecuteApiEndpoint") is not True:
                        raise RehearsalError("app_endpoint_not_closed")
        if function_resources:
            physical_function = function_resources[0].get("PhysicalResourceId")
            if physical_function is None or physical_function == "":
                physical_function = None
            elif physical_function != FUNCTION_NAME:
                raise RehearsalError("app_resource_id_invalid")
            if physical_function is not None:
                try:
                    concurrency = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
                except _AwsFailure as exc:
                    if not _is_not_found(exc):
                        raise
                else:
                    if not isinstance(concurrency, Mapping) or type(concurrency.get("ReservedConcurrentExecutions")) is not int or concurrency["ReservedConcurrentExecutions"] != 0:
                        raise RehearsalError("app_function_not_reserved_zero")
        state["app_delete_attempted"] = True
        state["app_stack_id"] = actual_id
        self.journal.save(state)
        try:
            self._call("cloudformation", "delete_stack", StackName=actual_id)
        except _AwsFailure:
            state["app_delete_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("app_delete_ambiguous") from None
        state["app_delete_call_returned"] = True
        self.journal.save(state)
        return True, "app_delete_requested", {"delete_calls": 1}

    def _step_delete_controls(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("app_deleted_verified") or not state.get("controls_create_attempted"):
            raise RehearsalError("control_delete_not_authorized")
        if state.get("control_delete_attempted"):
            raise RehearsalError("control_delete_already_attempted")
        try:
            app_response = self._call("cloudformation", "describe_stacks", StackName=state.get("app_stack_id"))
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            app_stacks = app_response.get("Stacks") if isinstance(app_response, Mapping) else None
            if type(app_stacks) is not list:
                raise RehearsalError("app_delete_readback_invalid")
            if app_stacks:
                if len(app_stacks) != 1 or not isinstance(app_stacks[0], Mapping) or app_stacks[0].get("StackStatus") != "DELETE_COMPLETE":
                    raise RehearsalError("app_not_deleted")
        control_id, _ = self._owned_stack(
            stack_name=CONTROL_STACK_NAME, stack_id_key="control_stack_id",
            token_key="control_client_token", state=state,
        )
        resource_response = self._call("cloudformation", "describe_stack_resources", StackName=control_id)
        resources = resource_response.get("StackResources") if isinstance(resource_response, Mapping) else None
        allowed_names = {
            "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup", "SchedulerInvokeRole",
            "ShutdownSchedule", "RequestTripwireAlarm", "RequestTripwireEventRole", "RequestTripwireAlarmRule",
            "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup", "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
        }
        if type(resources) is not list or any(not isinstance(item, Mapping) for item in resources):
            raise RehearsalError("control_resources_unverified")
        if any(item.get("LogicalResourceId") not in allowed_names for item in resources):
            raise RehearsalError("control_resources_unexpected")
        state["control_delete_attempted"] = True
        self.journal.save(state)
        try:
            self._call("cloudformation", "delete_stack", StackName=control_id)
        except _AwsFailure:
            state["control_delete_ambiguous"] = True
            self.journal.save(state)
            raise RehearsalError("control_delete_ambiguous") from None
        state["control_delete_call_returned"] = True
        self.journal.save(state)
        return True, "control_delete_requested", {"delete_calls": 1}

    def _step_check_final(self):
        state = self._require_state()
        self._check_identity(state)
        if not state.get("app_deleted_verified"):
            raise RehearsalError("final_readback_not_authorized")
        if not state.get("controls_create_attempted"):
            self._verify_app_resources_absent()
            self._verify_control_resources_absent()
            return True, "rehearsal_resources_removed", {"stacks_remaining": 0}
        if not state.get("control_delete_attempted"):
            raise RehearsalError("final_readback_not_authorized")
        try:
            app_response = self._call("cloudformation", "describe_stacks", StackName=state.get("app_stack_id"))
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
        else:
            app_stacks = app_response.get("Stacks") if isinstance(app_response, Mapping) else None
            if type(app_stacks) is not list:
                raise RehearsalError("final_readback_invalid")
            if app_stacks and (len(app_stacks) != 1 or not isinstance(app_stacks[0], Mapping) or app_stacks[0].get("StackStatus") != "DELETE_COMPLETE"):
                return False, "app_delete_pending", {"stacks_remaining": 1}
        try:
            control_response = self._call("cloudformation", "describe_stacks", StackName=state.get("control_stack_id"))
        except _AwsFailure as exc:
            if not _is_not_found(exc):
                raise
            control_stacks = []
        else:
            control_stacks = control_response.get("Stacks") if isinstance(control_response, Mapping) else None
            if type(control_stacks) is not list:
                raise RehearsalError("final_readback_invalid")
        if not control_stacks:
            self._verify_app_resources_absent()
            self._verify_control_resources_absent()
            return True, "rehearsal_resources_removed", {"stacks_remaining": 0}
        if len(control_stacks) != 1 or not isinstance(control_stacks[0], Mapping):
            raise RehearsalError("final_readback_invalid")
        if control_stacks[0].get("StackStatus") == "DELETE_FAILED":
            raise RehearsalError("control_delete_failed")
        if control_stacks[0].get("StackStatus") != "DELETE_COMPLETE":
            return False, "control_delete_pending", {"stacks_remaining": 1}
        resources_response = self._call("cloudformation", "describe_stack_resources", StackName=state.get("control_stack_id"))
        resources = resources_response.get("StackResources") if isinstance(resources_response, Mapping) else None
        if type(resources) is not list or any(not isinstance(item, Mapping) for item in resources):
            raise RehearsalError("final_readback_invalid")
        if any(item.get("ResourceStatus") != "DELETE_COMPLETE" for item in resources):
            raise RehearsalError("control_delete_failed")
        self._verify_app_resources_absent()
        self._verify_control_resources_absent()
        return True, "rehearsal_resources_removed", {"stacks_remaining": 0}


def _build_clients() -> dict[str, Any]:
    """Create lazy CLI SDK clients with one attempt and short socket timeouts."""
    try:
        import boto3
        from botocore.config import Config
        config = Config(
            retries={"mode": "standard", "total_max_attempts": 1},
            connect_timeout=CONNECT_TIMEOUT_SECONDS,
            read_timeout=READ_TIMEOUT_SECONDS,
        )
        session = boto3.Session(region_name=REGION)
        return {
            "sts": session.client("sts", region_name=REGION, config=config),
            "cloudformation": session.client("cloudformation", region_name=REGION, config=config),
            "lambda": session.client("lambda", region_name=REGION, config=config),
            "apigatewayv2": session.client("apigatewayv2", region_name=REGION, config=config),
            "cognito": session.client("cognito-idp", region_name=REGION, config=config),
            "iam": session.client("iam", region_name=REGION, config=config),
            "logs": session.client("logs", region_name=REGION, config=config),
            "scheduler": session.client("scheduler", region_name=REGION, config=config),
            "events": session.client("events", region_name=REGION, config=config),
            "cloudwatch": session.client("cloudwatch", region_name=REGION, config=config),
            "stepfunctions": session.client("stepfunctions", region_name=REGION, config=config),
        }
    except Exception:
        raise RehearsalError("sdk_setup_failed") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one explicit step of the closed dev rehearsal.")
    parser.add_argument("--step", required=True, choices=STEPS)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        expected = os.environ.get("MAPIT_EXPECTED_AWS_ACCOUNT_ID")
        if type(expected) is not str or not _ACCOUNT_ID.fullmatch(expected):
            raise RehearsalError("expected_account_invalid")
        until_raw = os.environ.get("MAPIT_AUTHORIZED_UNTIL_EPOCH")
        writes_requiring_authority = {"preflight", "create-app", "create-controls", "arm-shutdown", "arm-cleanup"}
        if step_requires_authority := args.step in writes_requiring_authority:
            if type(until_raw) is not str or not re.fullmatch(r"[1-9][0-9]{9,10}", until_raw):
                raise RehearsalError("authorization_window_invalid")
            authorized_until = int(until_raw)
        elif type(until_raw) is str and re.fullmatch(r"[1-9][0-9]{9,10}", until_raw):
            authorized_until = int(until_raw)
        else:
            # Readbacks and owned-resource cleanup remain possible after the
            # authorization window; these paths never call _check_write_window.
            authorized_until = 1
        if step_requires_authority and authorized_until <= int(time.time()):
            raise RehearsalError("authorization_window_invalid")
        journal = FileJournal(args.state_dir)
        runner = AwsClosedRehearsal(_build_clients(), journal, expected, authorized_until_epoch=authorized_until)
        result = runner.run_step(args.step)
    except RehearsalError as exc:
        result = _safe_result(args.step, False, exc.category, 0)
    except Exception:
        result = _safe_result(args.step, False, "runner_setup_failed", 0)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
