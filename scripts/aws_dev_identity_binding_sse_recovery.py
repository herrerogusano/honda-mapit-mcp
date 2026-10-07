"""One-shot recovery of the dedicated DEV identity table's encryption mode.

This is a separate continuation operator. It never edits historical journals,
roles, policies, users, or the retained application stack. The only CloudFormation
delta is the existing table's SSEEnabled flag changing from true to false (AWS-
owned encryption remains enabled). All clients and journals are injected.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import math
import re
import time
from typing import Any, Callable

from scripts.aws_dev_identity_binding_bootstrap import (
    APP_STACK_NAME, REGION, DevIdentityBindingBootstrapCoordinator,
    IdentityBindingBootstrapError, _canonical, _digest,
)
from scripts.build_aws_dev_identity_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_ROLE_NAME, STACK_NAME,
)
from scripts.build_aws_dev_identity_binding_sse_recovery import templates as _pure_templates
from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS
from scripts.run_aws_closed_rehearsal import RehearsalError
from scripts.run_aws_retained_dev_bootstrap import RetainedDevRunnerError, validate_authorization
from scripts.run_dev_identity_binding_storage_probe import (
    _STATE_FIELDS as _PROBE_FIELDS, _exercise_receipt_flags,
    _SYNTHETIC_CONFIG, _load_keys, _parameter_metadata, _readback_receipt_flags,
    _verify_assumed_client_set, _window_bound_clients, _assume_clients, _make_registry,
    _new_publish_adapter, _synthetic_identity_context, StorageProbeError,
)
from mapit.enrolled_provider import EnrolledCloudServicesProvider, EnrolledProviderError
from mapit.identity_binding import IdentityBindingError

_RECOVERY_FIELDS = frozenset({
    "table_id", "table_creation_time", "bootstrap_state_sha256",
    "probe_state_sha256", "key_state_sha256", "sse_key_arn", "runtime_policy_physical_id",
})
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_TABLE_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_STACK_ID = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}\Z"
)
_TABLE_ARN = re.compile(
    r"arn:aws:dynamodb:eu-west-1:([0-9]{12}):table/honda-mapit-mcp-dev-identity-bindings\Z"
)
_STEPS = ("preflight", "update", "readback", "exercise", "verify")
_CATEGORIES = frozenset({
    "binding_invalid", "authorization_invalid", "lineage_invalid", "clients_invalid",
    "journal_invalid", "window_invalid", "window_expired", "source_ci_failed",
    "protection_failed", "preflight_conflict", "preflight_verified", "preflight_required",
    "update_intent_saved", "update_outcome_unknown", "update_acknowledged",
    "update_in_progress", "update_readback_unverified", "sse_recovery_accepted", "probe_intent_saved",
    "storage_exercise_unverified", "storage_exercise_verified", "readback_unverified",
    "readback_verified", "probe_consumed", "aws_call_failed", "aws_response_invalid",
    "journal_failed", "operator_internal_error", "step_invalid",
})
_BASE_CLIENTS = frozenset({
    "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
    "apigatewayv2", "lambda", "kms",
})
_SERVICE_META = {
    "sts": ("sts", "eu-west-1", "https://sts.eu-west-1.amazonaws.com"),
    "cloudformation": ("cloudformation", "eu-west-1", "https://cloudformation.eu-west-1.amazonaws.com"),
    "iam": ("iam", "us-east-1", "https://iam.amazonaws.com"),
    "dynamodb": ("dynamodb", "eu-west-1", "https://dynamodb.eu-west-1.amazonaws.com"),
    "ssm": ("ssm", "eu-west-1", "https://ssm.eu-west-1.amazonaws.com"),
    "cognito": ("cognito-idp", "eu-west-1", "https://cognito-idp.eu-west-1.amazonaws.com"),
    "apigatewayv2": ("apigatewayv2", "eu-west-1", "https://apigateway.eu-west-1.amazonaws.com"),
    "lambda": ("lambda", "eu-west-1", "https://lambda.eu-west-1.amazonaws.com"),
    "kms": ("kms", "eu-west-1", "https://kms.eu-west-1.amazonaws.com"),
}


class SseRecoveryError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _state_digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc_epoch(value: Any) -> int:
    if type(value) is not str or len(value) > 64:
        raise ValueError
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError
    return int(parsed.astimezone(timezone.utc).timestamp())


def validate_recovery_lineage(
    binding: Mapping[str, Any],
    accepted_bootstrap_state: Any,
    accepted_probe_state: Any,
    accepted_key_state: Any,
    recovery_binding: Any,
) -> dict[str, str]:
    """Validate read-only consumed history and exact table identity metadata.

    Historical journals are inputs only. The returned mapping is suitable for
    internal comparison; callers must not print its identifiers or digests.
    """
    try:
        if type(binding) is not dict or set(binding) != _BINDING_FIELDS:
            raise ValueError
        if type(recovery_binding) is not dict or set(recovery_binding) != _RECOVERY_FIELDS:
            raise ValueError
        if any(type(recovery_binding.get(name)) is not str or _SHA.fullmatch(recovery_binding[name]) is None
               for name in ("bootstrap_state_sha256", "probe_state_sha256", "key_state_sha256")):
            raise ValueError
        if type(recovery_binding.get("table_id")) is not str or _TABLE_ID.fullmatch(recovery_binding["table_id"]) is None:
            raise ValueError
        expected_sse_arn = rf"arn:aws:kms:{REGION}:{binding['account_id']}:key/[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}"
        if (type(recovery_binding.get("sse_key_arn")) is not str
            or re.fullmatch(expected_sse_arn, recovery_binding["sse_key_arn"]) is None):
            raise ValueError
        if (type(recovery_binding.get("runtime_policy_physical_id")) is not str
            or not 1 <= len(recovery_binding["runtime_policy_physical_id"]) <= 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in recovery_binding["runtime_policy_physical_id"])):
            raise ValueError
        created = _utc_epoch(recovery_binding.get("table_creation_time"))
        bootstrap_sha, stack_id = _accepted_bootstrap(accepted_bootstrap_state, binding)
        if (_state_digest(accepted_bootstrap_state) != recovery_binding["bootstrap_state_sha256"]
            or _state_digest(accepted_probe_state) != recovery_binding["probe_state_sha256"]
            or _state_digest(accepted_key_state) != recovery_binding["key_state_sha256"]):
            raise ValueError
        if not accepted_bootstrap_state["authorized_from_epoch"] <= created < accepted_bootstrap_state["authorized_until_epoch"]:
            raise ValueError
        expected_tenant_sha = hashlib.sha256(_canonical(list(binding["tenant_keys"]))).hexdigest()
        probe = accepted_probe_state
        if (type(probe) is not dict or set(probe) != _PROBE_FIELDS
            or type(probe.get("schema")) is not int or probe.get("schema") != 1
            or probe.get("operation") != "dev_identity_binding_storage_probe"
            or probe.get("account") != binding["account_id"]
            or probe.get("caller") != binding["operator_user_arn"]
            or type(probe.get("source")) is not str or _HEX40.fullmatch(probe["source"]) is None
            or type(probe.get("run_id")) is not int or isinstance(probe.get("run_id"), bool) or probe["run_id"] <= 0
            or type(probe.get("start")) is not int or isinstance(probe.get("start"), bool)
            or type(probe.get("end")) is not int or isinstance(probe.get("end"), bool)
            or not 0 < probe["end"] - probe["start"] <= 3600
            or probe.get("bootstrap_sha256") != bootstrap_sha
            or probe.get("tenant_keys_sha256") != expected_tenant_sha
            or probe.get("bootstrap_stack_id") != stack_id
            or probe.get("phase") != "intent_saved" or probe.get("intent") != "storage_exercise"
            or type(probe.get("flags")) is not dict
            or set(probe["flags"]) != {"preflight", "intent_saved"}
            or any(type(value) is not bool or value is not True for value in probe["flags"].values())):
            raise ValueError
        key = accepted_key_state
        expected_key_fields = {"schema", "operation", "account", "source", "run_id", "bootstrap_sha256",
                               "parameter_path", "start", "end", "phase"}
        if (type(key) is not dict or set(key) != expected_key_fields
            or type(key.get("schema")) is not int or key["schema"] != 1
            or key.get("operation") != "dev_identity_binding_key_publication"
            or key.get("account") != binding["account_id"]
            or key.get("source") != probe["source"]
            or type(key.get("run_id")) is not int or isinstance(key.get("run_id"), bool)
            or key["run_id"] <= 0 or key.get("run_id") != probe["run_id"]
            or key.get("bootstrap_sha256") != bootstrap_sha
            or key.get("parameter_path") != CONFIG_PARAMETER or key.get("phase") != "accepted"
            or type(key.get("start")) is not int or isinstance(key.get("start"), bool)
            or type(key.get("end")) is not int or isinstance(key.get("end"), bool)
            or not 0 < key["end"] - key["start"] <= 3600
            or key["start"] != probe["start"] or key["end"] != probe["end"]):
            raise ValueError
        table_arn = f"arn:aws:dynamodb:{REGION}:{binding['account_id']}:table/honda-mapit-mcp-dev-identity-bindings"
        return {"bootstrap_sha256": bootstrap_sha, "stack_id": stack_id,
                "table_arn": table_arn, "table_id": recovery_binding["table_id"],
                "sse_key_arn": recovery_binding["sse_key_arn"],
                "runtime_policy_physical_id": recovery_binding["runtime_policy_physical_id"],
                "target_template_sha256": _target_template(binding)[1]}
    except Exception:
        raise SseRecoveryError("lineage_invalid") from None


def _accepted_bootstrap(state: Any, binding: Mapping[str, Any]) -> tuple[str, str]:
    from scripts.run_dev_identity_binding_storage_probe import _bootstrap_receipt
    try:
        template_sha, stack_id = _bootstrap_receipt(state, binding)
        if (state.get("readback") is not True or state.get("acknowledged") is not True
            or state.get("preflight") is not True):
            raise ValueError
        return template_sha, stack_id
    except Exception:
        raise ValueError from None


def _templates(binding: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, str, str]:
    return _pure_templates(binding)


def _target_template(binding: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    from scripts.build_aws_dev_identity_binding_sse_recovery import target_template
    return target_template(binding)


class DevIdentityBindingSseRecoveryCoordinator:
    """Fresh single-attempt transition plus same-window synthetic storage proof."""

    STEPS = _STEPS

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, probe_journal: Any,
                 authorization: Mapping[str, Any],
                 binding: Mapping[str, Any], recovery_binding: Mapping[str, Any],
                 accepted_bootstrap_state: Any, accepted_probe_state: Any, accepted_key_state: Any,
                 accepted_runtime_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
                 explicit_client_factory: Callable[[Mapping[str, str]], Mapping[str, Any]],
                 source_ci_validator: Callable[[Mapping[str, Any]], None],
                 protection_validator: Callable[[Mapping[str, Any]], None],
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(clients, Mapping) or set(clients) != _BASE_CLIENTS:
            raise SseRecoveryError("clients_invalid")
        try:
            for name, client in clients.items():
                service, region, endpoint = _SERVICE_META[name]
                meta, cfg = client.meta, client.meta.config
                if (meta.service_model.service_name != service or meta.region_name != region
                    or meta.endpoint_url != endpoint or cfg.retries.get("total_max_attempts") != 1
                    or type(cfg.retries.get("total_max_attempts")) is not int
                    or any(type(x) not in (int, float) or isinstance(x, bool)
                           or not math.isfinite(x) or not 0 < x <= 3 for x in (cfg.connect_timeout, cfg.read_timeout))):
                    raise ValueError
        except Exception:
            raise SseRecoveryError("clients_invalid") from None
        if (not all(callable(getattr(journal, key, None)) for key in ("load", "save", "locked"))
            or not all(callable(getattr(probe_journal, key, None)) for key in ("load", "save", "locked"))
            or journal is probe_journal):
            raise SseRecoveryError("journal_invalid")
        if not callable(explicit_client_factory) or not callable(source_ci_validator) or not callable(protection_validator):
            raise SseRecoveryError("binding_invalid")
        try:
            auth = validate_authorization(dict(authorization))
            lineage = validate_recovery_lineage(binding, accepted_bootstrap_state, accepted_probe_state,
                                                accepted_key_state, recovery_binding)
            if auth["account"] != binding["account_id"] or auth["expected_caller_arn"] != binding["operator_user_arn"]:
                raise ValueError
            original, target, original_bytes, target_bytes, original_sha, target_sha = _templates(binding)
            if (accepted_bootstrap_state.get("template_sha256") != original_sha
                or lineage["target_template_sha256"] != target_sha):
                raise ValueError
        except Exception:
            raise SseRecoveryError("binding_invalid") from None
        self.clients = dict(clients)
        self.journal = journal
        self.probe_journal = probe_journal
        self.auth = auth
        self.binding = dict(binding)
        self.recovery_binding = dict(recovery_binding)
        self.accepted_bootstrap_state = accepted_bootstrap_state
        self.accepted_probe_state = accepted_probe_state
        self.accepted_key_state = accepted_key_state
        self.lineage = lineage
        self.original_template, self.target_template = original, target
        self.original_bytes, self.target_bytes = original_bytes, target_bytes
        self.original_sha, self.target_sha = original_sha, target_sha
        self.runtime_verifier = accepted_runtime_verifier
        self.explicit_client_factory = explicit_client_factory
        self.source_ci_validator, self.protection_validator = source_ci_validator, protection_validator
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started = 0.0
        self._last_mono = 0.0
        self._last_epoch = 0
        self._calls = [0]
        self._active_clients: Mapping[str, Any] = self.clients

    def _safe(self, step: str, ok: bool, category: str, **flags: bool) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls[0], "flags": flags}

    def _guard(self) -> None:
        try:
            epoch, mono = self.wall_clock(), self.monotonic()
            if (type(epoch) not in (int, float) or isinstance(epoch, bool) or not math.isfinite(epoch)
                or epoch < self._last_epoch or type(mono) not in (int, float) or isinstance(mono, bool)
                or not math.isfinite(mono) or mono < self._last_mono or mono - self._started >= 90.0):
                raise SseRecoveryError("window_invalid")
            if not self.auth["start"] <= epoch < self.auth["end"]:
                raise SseRecoveryError("window_expired")
            if self._calls[0] >= 160:
                raise SseRecoveryError("aws_call_failed")
            self._last_epoch, self._last_mono = int(epoch), float(mono)
        except SseRecoveryError:
            raise
        except Exception:
            raise SseRecoveryError("window_invalid") from None

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._guard()
        try:
            response = getattr(self._active_clients[service], method)(**kwargs)
        except Exception:
            self._guard()
            raise SseRecoveryError("aws_call_failed") from None
        if (not isinstance(response, Mapping) or not isinstance(response.get("ResponseMetadata"), Mapping)
            or type(response["ResponseMetadata"].get("HTTPStatusCode")) is not int
            or response["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise SseRecoveryError("aws_response_invalid")
        self._guard()
        return response

    def _absent_parameter(self, name: str) -> None:
        self._guard()
        try:
            response = self._active_clients["ssm"].get_parameter(Name=name, WithDecryption=False)
        except Exception as exc:
            response = getattr(exc, "response", None)
            error = response.get("Error") if isinstance(response, Mapping) else None
            meta = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
            if (isinstance(error, Mapping) and error.get("Code") == "ParameterNotFound"
                and isinstance(meta, Mapping) and type(meta.get("HTTPStatusCode")) is int
                and meta["HTTPStatusCode"] == 400):
                self._guard()
                return
            self._guard()
            raise SseRecoveryError("aws_call_failed") from None
        self._guard()
        if (not isinstance(response, Mapping) or not isinstance(response.get("ResponseMetadata"), Mapping)
            or response["ResponseMetadata"].get("HTTPStatusCode") != 200):
            raise SseRecoveryError("aws_response_invalid")
        raise SseRecoveryError("preflight_conflict")

    def _source(self) -> None:
        self._guard()
        try:
            if self.source_ci_validator(self.auth) is False:
                raise ValueError
        except Exception:
            raise SseRecoveryError("source_ci_failed") from None
        try:
            if self.protection_validator(self.binding) is False:
                raise ValueError
        except Exception:
            raise SseRecoveryError("protection_failed") from None
        self._guard()

    def _bootstrap_checker(self):
        checker = DevIdentityBindingBootstrapCoordinator(
            self._active_clients, _MemoryJournal(), binding={key: self.binding[key] for key in _BINDING_FIELDS
                if key not in {"github_owner_id", "github_repository_id"}},
            source_sha=self.auth["source_sha"], run_id=self.auth["run_id"],
            expected_caller_arn=self.auth["expected_caller_arn"],
            authorized_from_epoch=self.auth["start"], authorized_until_epoch=self.auth["end"],
            accepted_runtime_verifier=self.runtime_verifier, wall_clock=self.wall_clock,
            monotonic=self.monotonic,
        )
        checker._started = self._started
        checker._last_mono = self._last_mono
        checker._last_epoch = self._last_epoch
        checker._calls = 0
        checker._accepted_calls = 0
        return checker

    def _state_base(self, phase: str, *, intent: Mapping[str, Any] | None = None,
                    update_token: str | None = None,
                    ack: bool = False, flags: Mapping[str, bool] | None = None) -> dict[str, Any]:
        if update_token is None and isinstance(intent, Mapping) and intent.get("kind") == "table_sse_update":
            update_token = intent.get("token")
        return {
            "schema": 1, "operation": "dev_identity_binding_sse_recovery",
            "account": self.binding["account_id"], "source": self.auth["source_sha"],
            "run_id": self.auth["run_id"], "caller": self.auth["expected_caller_arn"],
            "start": self.auth["start"], "end": self.auth["end"],
            "binding_sha256": _state_digest({key: value for key, value in self.binding.items()
                                               if key not in {"github_owner_id", "github_repository_id", "tenant_keys"}}),
            "recovery_binding_sha256": _state_digest(self.recovery_binding),
            "bootstrap_state_sha256": self.recovery_binding["bootstrap_state_sha256"],
            "probe_state_sha256": self.recovery_binding["probe_state_sha256"],
            "key_state_sha256": self.recovery_binding["key_state_sha256"],
            "bootstrap_sha256": self.lineage["bootstrap_sha256"],
            "stack_id": self.lineage["stack_id"], "table_arn": self.lineage["table_arn"],
            "table_id": self.recovery_binding["table_id"],
            "table_creation_time": self.recovery_binding["table_creation_time"],
            "update_token": update_token,
            "original_template_sha256": self.original_sha, "target_template_sha256": self.target_sha,
            "last_observed_epoch": int(self._last_epoch), "phase": phase,
            "intent": dict(intent) if intent is not None else None, "update_acknowledged": ack,
            "flags": dict(flags or {}),
        }

    def _load(self, journal: Any | None = None) -> dict[str, Any] | None:
        journal = self.journal if journal is None else journal
        state = journal.load()
        if state is None:
            return None
        expected = set(self._state_base("x"))
        if type(state) is not dict or set(state) != expected:
            raise SseRecoveryError("journal_invalid")
        update_state = self.journal.load()
        if journal is self.probe_journal:
            update_token = (update_state.get("intent", {}).get("token")
                            if isinstance(update_state, Mapping) and isinstance(update_state.get("intent"), Mapping)
                            else None)
        else:
            intent_for_update = state.get("intent")
            update_token = (intent_for_update.get("token")
                            if isinstance(intent_for_update, Mapping)
                            and intent_for_update.get("kind") == "table_sse_update" else None)
        template = self._state_base(state.get("phase"), update_token=update_token)
        for key, value in template.items():
            if key in {"last_observed_epoch", "intent", "update_acknowledged", "flags"}:
                continue
            if type(state.get(key)) is not type(value) or state[key] != value:
                raise SseRecoveryError("journal_invalid")
        for name in ("schema", "run_id", "start", "end", "last_observed_epoch"):
            if type(state.get(name)) is not int or isinstance(state[name], bool):
                raise SseRecoveryError("journal_invalid")
        if (type(state.get("update_acknowledged")) is not bool or type(state.get("flags")) is not dict
            or any(type(v) is not bool for v in state["flags"].values())):
            raise SseRecoveryError("journal_invalid")
        phase = state.get("phase")
        expected_flags = {
            "preflight_verified": ({"preflight": True}, None, False),
            "update_intent_saved": ({"preflight": True, "update_intent_saved": True}, "table_sse_update", False),
            "update_outcome_unknown": ({"preflight": True, "update_intent_saved": True, "update_outcome_unknown": True}, "table_sse_update", False),
            "update_acknowledged": ({"preflight": True, "update_intent_saved": True, "update_acknowledged": True}, "table_sse_update", True),
            "sse_recovery_accepted": ({"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                                        "sse_recovery_accepted": True}, "table_sse_update", True),
            "probe_intent_saved": ({"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                                    "sse_recovery_accepted": True, "probe_intent_saved": True}, "storage_exercise", True),
            "storage_exercise_verified": ({"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                                           "sse_recovery_accepted": True, "probe_intent_saved": True,
                                           **_exercise_receipt_flags()}, "storage_exercise", True),
            "readback_verified": ({"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                                   "sse_recovery_accepted": True, "probe_intent_saved": True,
                                   **_exercise_receipt_flags(), **_readback_receipt_flags()}, "storage_exercise", True),
        }.get(phase)
        if expected_flags is None or state["flags"] != expected_flags[0] or state.get("update_acknowledged") != expected_flags[2]:
            raise SseRecoveryError("journal_invalid")
        intent = state.get("intent")
        if intent is not None:
            if type(intent) is not dict or set(intent) != {"token", "stack_name", "kind"}:
                raise SseRecoveryError("journal_invalid")
            if (intent.get("stack_name") != STACK_NAME or intent.get("kind") not in {"table_sse_update", "storage_exercise"}
                or type(intent.get("token")) is not str
                or re.fullmatch(r"dev-sse-recovery-[0-9a-f]{32}", intent["token"]) is None):
                raise SseRecoveryError("journal_invalid")
        if intent != ({"token": intent.get("token"), "stack_name": STACK_NAME, "kind": expected_flags[1]}
                      if intent is not None else None):
            raise SseRecoveryError("journal_invalid")
        if expected_flags[1] == "table_sse_update":
            if state.get("update_token") != state["intent"].get("token"):
                raise SseRecoveryError("journal_invalid")
        elif expected_flags[1] is None:
            if state.get("update_token") is not None:
                raise SseRecoveryError("journal_invalid")
        elif (type(state.get("update_token")) is not str
              or re.fullmatch(r"dev-sse-recovery-[0-9a-f]{32}", state["update_token"]) is None):
            raise SseRecoveryError("journal_invalid")
        if type(state.get("last_observed_epoch")) is not int or not self.auth["start"] <= state["last_observed_epoch"] < self.auth["end"]:
            raise SseRecoveryError("journal_invalid")
        return state

    def _save(self, state: Mapping[str, Any], journal: Any | None = None) -> None:
        journal = self.journal if journal is None else journal
        self._guard()
        try:
            journal.save(dict(state))
        except Exception:
            raise SseRecoveryError("journal_failed") from None
        self._guard()

    def _verify_table(self, *, owned: bool, require_empty: bool = True) -> None:
        table = self._call("dynamodb", "describe_table", TableName="honda-mapit-mcp-dev-identity-bindings").get("Table")
        created_text = self.recovery_binding["table_creation_time"]
        expected_created = datetime.fromisoformat(created_text[:-1] + "+00:00" if created_text.endswith("Z") else created_text)
        if expected_created.tzinfo is None:
            raise SseRecoveryError("preflight_conflict")
        expected_arn = self.lineage["table_arn"]
        if (not isinstance(table, Mapping) or table.get("TableName") != "honda-mapit-mcp-dev-identity-bindings"
            or table.get("TableArn") != expected_arn or table.get("TableId") != self.recovery_binding["table_id"]
            or table.get("TableStatus") != "ACTIVE" or table.get("CreationDateTime") != expected_created
            or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("OnDemandThroughput") != {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100}
            or table.get("KeySchema") != [{"AttributeName": "key", "KeyType": "HASH"}]
            or table.get("AttributeDefinitions") != [{"AttributeName": "key", "AttributeType": "S"}]
            or table.get("DeletionProtectionEnabled") is not True
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("LocalSecondaryIndexes") not in (None, [])):
            raise SseRecoveryError("preflight_conflict")
        sse = table.get("SSEDescription")
        if owned:
            if sse is not None:
                raise SseRecoveryError("update_readback_unverified")
        else:
            if (not isinstance(sse, Mapping) or sse.get("Status") != "ENABLED" or sse.get("SSEType") != "KMS"
                or sse.get("KMSMasterKeyArn") != self.recovery_binding["sse_key_arn"]):
                raise SseRecoveryError("preflight_conflict")
        tags = self._call("dynamodb", "list_tags_of_resource", ResourceArn=expected_arn).get("Tags")
        expected_tags = {
            "Project": "honda-mapit-mcp", "Environment": "dev",
            "Purpose": "mapit-identity-bindings",
            "OperatorRunId": str(self.accepted_bootstrap_state["run_id"]),
        }
        if (type(tags) is not list or len(tags) != len(expected_tags)
            or any(not isinstance(item, Mapping) or set(item) != {"Key", "Value"}
                                          for item in tags)
            or len({item["Key"] for item in tags}) != len(tags)
            or any(not any(item["Key"] == key and item["Value"] == value for item in tags)
                   for key, value in expected_tags.items())):
            raise SseRecoveryError("preflight_conflict" if not owned else "update_readback_unverified")
        if require_empty:
            item = self._call("dynamodb", "get_item", TableName=expected_arn,
                              Key={"key": {"S": "identity-bindings-v1"}}, ConsistentRead=True,
                              ReturnConsumedCapacity="NONE")
            if set(item) - {"ResponseMetadata", "Item"} or item.get("Item") is not None:
                raise SseRecoveryError("preflight_conflict")

    def _verify_stack(self, *, target: bool, require_events: bool, require_empty: bool = True) -> None:
        bootstrap = self._bootstrap_checker()
        stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME).get("Stacks")
        if type(stack) is not list or len(stack) != 1 or not isinstance(stack[0], Mapping):
            raise SseRecoveryError("preflight_conflict")
        row = stack[0]
        desired_status = "UPDATE_COMPLETE" if target else "CREATE_COMPLETE"
        if target and row.get("StackStatus") in {
            "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
            "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
        }:
            raise SseRecoveryError("update_in_progress")
        old_state = self.accepted_bootstrap_state
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                         "Purpose": "mapit-identity-bindings", "OperatorRunId": str(old_state["run_id"])}
        tags = row.get("Tags")
        if (row.get("StackName") != STACK_NAME or row.get("StackId") != self.lineage["stack_id"]
            or row.get("StackStatus") != desired_status or row.get("EnableTerminationProtection") is not True
            or row.get("RoleARN") not in (None, "") or type(tags) is not list
            or len(tags) != len(expected_tags) or any(not isinstance(t, Mapping) or set(t) != {"Key", "Value"} for t in tags)
            or {t["Key"]: t["Value"] for t in tags} != expected_tags):
            raise SseRecoveryError("preflight_conflict" if not target else "update_readback_unverified")
        self._verify_current_app(bootstrap)
        actual = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original").get("TemplateBody")
        if type(actual) is str:
            from scripts.aws_dev_identity_binding_bootstrap import _document
            actual = _document(actual)
        expected_template = self.target_template if target else self.original_template
        if not isinstance(actual, Mapping) or _canonical(actual) != _canonical(expected_template):
            raise SseRecoveryError("preflight_conflict" if not target else "update_readback_unverified")
        if require_events:
            events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME).get("StackEvents")
            state = self.journal.load()
            token = state["intent"]["token"] if state and state.get("intent") else None
            matching_completion = False
            if type(events) is list and 1 <= len(events) <= 100 and type(token) is str:
                for event in events:
                    if not isinstance(event, Mapping):
                        continue
                    timestamp = event.get("Timestamp")
                    if (event.get("ClientRequestToken") == token
                        and event.get("StackId") == self.lineage["stack_id"]
                        and event.get("StackName") == STACK_NAME
                        and event.get("LogicalResourceId") == STACK_NAME
                        and event.get("PhysicalResourceId") == self.lineage["stack_id"]
                        and event.get("ResourceType") == "AWS::CloudFormation::Stack"
                        and event.get("ResourceStatus") == "UPDATE_COMPLETE"
                        and isinstance(timestamp, datetime) and timestamp.tzinfo is not None
                        and self.auth["start"] <= timestamp.timestamp() < self.auth["end"]):
                        matching_completion = True
                        break
            if not matching_completion:
                raise SseRecoveryError("update_readback_unverified")
        resources = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME).get("StackResources")
        expected_resources = {
            "MapitIdentityBindings": ("AWS::DynamoDB::Table", "honda-mapit-mcp-dev-identity-bindings"),
            "IdentityEnrollerBoundary": ("AWS::IAM::ManagedPolicy", f"arn:aws:iam::{self.binding['account_id']}:policy/honda-mapit-mcp-dev-identity-enroller-boundary"),
            "IdentityEnrollerRole": ("AWS::IAM::Role", OPERATOR_ROLE_NAME),
            "RuntimeIdentityBindingPolicy": ("AWS::IAM::Policy", self.lineage["runtime_policy_physical_id"]),
        }
        if type(resources) is not list or len(resources) != 4:
            raise SseRecoveryError("preflight_conflict")
        seen: dict[str, Mapping[str, Any]] = {}
        for resource in resources:
            name = resource.get("LogicalResourceId") if isinstance(resource, Mapping) else None
            if (type(name) is not str or name in seen or name not in expected_resources
                or resource.get("ResourceType") != expected_resources[name][0]
                or resource.get("PhysicalResourceId") != expected_resources[name][1]
                or resource.get("StackId") != self.lineage["stack_id"]
                or resource.get("StackName") != STACK_NAME
                or resource.get("ResourceStatus") not in ({"CREATE_COMPLETE", "UPDATE_COMPLETE"} if target else {"CREATE_COMPLETE"})):
                raise SseRecoveryError("preflight_conflict" if not target else "update_readback_unverified")
            seen[name] = resource
        if set(seen) != set(expected_resources):
            raise SseRecoveryError("preflight_conflict")
        table = seen["MapitIdentityBindings"]
        if target and table.get("ResourceStatus") != "UPDATE_COMPLETE":
            raise SseRecoveryError("update_readback_unverified")
        self._verify_table(owned=target, require_empty=require_empty)
        if target:
            self._verify_parameters(require_tenant_absent=require_empty)

    def _verify_current_app(self, bootstrap: DevIdentityBindingBootstrapCoordinator) -> None:
        # The retained application is read-only in this operation. Its existing
        # accepted verifier binds the closed 19-resource runtime and third
        # runtime-read policy; it never receives an app template or write call.
        bootstrap._verify_current_app(include_runtime_policy=True)
        bootstrap._verify_iam(f"arn:aws:iam::{self.binding['account_id']}:policy/honda-mapit-mcp-dev-identity-enroller-boundary")
        bootstrap._verify_ssm_key()

    def _verify_parameters(self, *, require_tenant_absent: bool) -> None:
        if require_tenant_absent:
            for key in self.binding["tenant_keys"]:
                self._absent_parameter(f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token")
        response = self._call("ssm", "get_parameter", Name=CONFIG_PARAMETER, WithDecryption=False)
        parameter = response.get("Parameter")
        expected_arn = f"arn:aws:ssm:{REGION}:{self.binding['account_id']}:parameter/honda-mapit-mcp/dev/identity-binding-config"
        modified = parameter.get("LastModifiedDate") if isinstance(parameter, Mapping) else None
        key_start = self.accepted_key_state.get("start")
        key_end = self.accepted_key_state.get("end")
        if (not isinstance(modified, datetime) or modified.tzinfo is None
            or modified.utcoffset() is None
            or type(key_start) is not int or isinstance(key_start, bool)
            or type(key_end) is not int or isinstance(key_end, bool)
            or not key_start <= modified.astimezone(timezone.utc).timestamp() < key_end):
            raise SseRecoveryError("preflight_conflict")
        if (not isinstance(parameter, Mapping) or parameter.get("Name") != CONFIG_PARAMETER
            or parameter.get("ARN") != expected_arn or parameter.get("Type") != "SecureString"
            or type(parameter.get("Version")) is not int or parameter["Version"] != 1
            or parameter.get("DataType") != "text"):
            raise SseRecoveryError("preflight_conflict")

    def _verify_operator_identity(self) -> None:
        reply = self._call("sts", "get_caller_identity")
        if (reply.get("Account") != self.binding["account_id"]
            or reply.get("Arn") != self.auth["expected_caller_arn"]):
            raise SseRecoveryError("preflight_conflict")

    def _prepare(self) -> None:
        try:
            self._source()
            self._verify_operator_identity()
            self._verify_stack(target=False, require_events=False)
            self._verify_parameters(require_tenant_absent=True)
        except SseRecoveryError:
            raise
        except Exception:
            raise SseRecoveryError("preflight_conflict") from None

    def _update(self, state: dict[str, Any]) -> dict[str, Any]:
        if state is None or state["phase"] != "preflight_verified":
            raise SseRecoveryError("preflight_required")
        self._prepare()
        self._guard()
        token = "dev-sse-recovery-" + __import__("uuid").uuid4().hex
        intent = {"token": token, "stack_name": STACK_NAME, "kind": "table_sse_update"}
        flags = {"preflight": True, "update_intent_saved": True}
        self._save(self._state_base("update_intent_saved", intent=intent, flags=flags))
        self._guard()
        try:
            response = self._call("cloudformation", "update_stack",
                StackName=STACK_NAME, TemplateBody=self.target_bytes.decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=token,
            )
        except Exception:
            # The durable intent consumes this update. Even a timeout may have
            # reached CloudFormation; only a read-only readback can reconcile it.
            unknown_flags = {**flags, "update_outcome_unknown": True}
            self._save(self._state_base("update_outcome_unknown", intent=intent, flags=unknown_flags))
            return self._safe("update", False, "update_outcome_unknown")
        if (not isinstance(response, Mapping) or not isinstance(response.get("ResponseMetadata"), Mapping)
            or response["ResponseMetadata"].get("HTTPStatusCode") != 200
            or response.get("StackId") != self.lineage["stack_id"]):
            unknown_flags = {**flags, "update_outcome_unknown": True}
            self._save(self._state_base("update_outcome_unknown", intent=intent, flags=unknown_flags))
            return self._safe("update", False, "update_outcome_unknown")
        ack_flags = {**flags, "update_acknowledged": True}
        self._save(self._state_base("update_acknowledged", intent=intent, ack=True, flags=ack_flags))
        return self._safe("update", True, "update_acknowledged", update_acknowledged=True)

    def _verify_transition(self, state: dict[str, Any]) -> dict[str, Any]:
        if state is None or state["phase"] not in {"update_intent_saved", "update_outcome_unknown", "update_acknowledged"}:
            raise SseRecoveryError("preflight_required")
        self._source()
        self._verify_operator_identity()
        self._verify_stack(target=True, require_events=True, require_empty=True)
        flags = {"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                 "sse_recovery_accepted": True}
        receipt = self._state_base("sse_recovery_accepted", intent=state["intent"], ack=True, flags=flags)
        self._save(receipt)
        return self._safe("readback", True, "sse_recovery_accepted", sse_recovery_accepted=True)

    def _assumed(self) -> tuple[dict[str, Any], dict[str, Any]]:
        from scripts.run_dev_identity_binding_storage_probe import _verify_client_set as verify_client_set
        # Base operator calls use the same immutable window, monotonic guard,
        # TLS endpoints and one-attempt clients as the reviewed storage runner.
        # run_step already wrapped every base client with the shared immutable
        # window/call budget. Reuse those wrappers; a second wrapper would
        # double-count and could obscure deadline checks.
        base = dict(self._active_clients)
        assumed = _assume_clients(base, self.auth, self.binding, self.explicit_client_factory,
                                  self.wall_clock, self._calls, self.monotonic, self._started)
        _verify_assumed_client_set(assumed)
        if set(assumed) != {"sts", "dynamodb", "ssm"}:
            raise SseRecoveryError("clients_invalid")
        return base, assumed

    def _exercise_storage(self, state: dict[str, Any]) -> dict[str, Any]:
        if state is None or state["phase"] != "sse_recovery_accepted":
            raise SseRecoveryError("preflight_required")
        if self.probe_journal.load() is not None:
            raise SseRecoveryError("probe_consumed")
        self._source()
        self._verify_operator_identity()
        self._verify_stack(target=True, require_events=True, require_empty=True)
        self._verify_parameters(require_tenant_absent=True)
        _, assumed = self._assumed()
        # Do not inspect or re-publish the historical key material until the
        # one-shot storage intent is durable.
        intent = {"token": "dev-sse-recovery-" + __import__("uuid").uuid4().hex,
                  "stack_name": STACK_NAME, "kind": "storage_exercise"}
        flags = {"preflight": True, "update_intent_saved": True, "update_acknowledged": True,
                 "sse_recovery_accepted": True, "probe_intent_saved": True}
        update_state = self._load(self.journal)
        if update_state is None or update_state.get("phase") != "sse_recovery_accepted":
            raise SseRecoveryError("preflight_required")
        update_token = update_state["intent"]["token"]
        probe_state = self._state_base("probe_intent_saved", intent=intent,
                                       update_token=update_token, ack=True, flags=flags)
        self._save(probe_state, self.probe_journal)
        material = _load_keys(assumed, self.binding, _SYNTHETIC_CONFIG, monotonic=self.monotonic)
        try:
            outcome = self._exercise_fresh_readers(assumed, material)
            if (type(outcome) is not dict or set(outcome) != {
                "tenant_a_enrolled", "tenant_b_enrolled", "tenant_results_isolated",
                "tenant_a_revoked", "tenant_b_remained_active",
            } or any(v is not True for v in outcome.values())):
                raise SseRecoveryError("storage_exercise_unverified")
            done_flags = {**flags, **_exercise_receipt_flags()}
            self._save(self._state_base("storage_exercise_verified", intent=intent,
                                        update_token=update_token, ack=True, flags=done_flags),
                       self.probe_journal)
            return self._safe("exercise", True, "storage_exercise_verified", **outcome)
        except SseRecoveryError:
            raise
        except Exception:
            raise SseRecoveryError("storage_exercise_unverified") from None

    def _exercise_fresh_readers(self, assumed: Mapping[str, Any], material: Any) -> dict[str, bool]:
        """Exercise synthetic tenants with per-operation 13s backend leases.

        Each registry/provider has a fresh absolute lease; no cached reader is
        reused across the paced A/B business calls or post-revocation checks.
        """
        from scripts.run_dev_identity_binding_storage_probe import _synthetic_identity_context

        context = _synthetic_identity_context(self.binding["tenant_keys"], material,
                                              wall_clock=self.wall_clock)

        def make_service(index: int):
            registry = _make_registry(assumed, self.binding, context, material,
                                      monotonic=self.monotonic, writer=False)
            provider = EnrolledCloudServicesProvider(
                registry, authority=context.authority, grant=context.grants[index],
                durable_guard=context.guard, snapshot=context.snapshots[index],
                ssm_client=assumed["ssm"], account_id=self.binding["account_id"],
                auth_transport=context.auth_transport, mapit_transport=context.mapit_transport,
                deadline=self.monotonic() + 13.0, monotonic=self.monotonic,
            )
            return provider.get()

        try:
            for index in range(2):
                registry = _make_registry(assumed, self.binding, context, material,
                                          monotonic=self.monotonic, writer=True)
                publisher = _new_publish_adapter(
                    assumed, self.binding, context, context.grants[index],
                    context.snapshots[index], monotonic=self.monotonic,
                )
                registry.enroll(context.grants[index], context.snapshots[index],
                                context.refresh_tokens[index], publisher=publisher)

            statuses = [make_service(i).get_vehicle_status().status for i in range(2)]
            distances = [make_service(i).get_distance("2026-01-01", "2026-02-01").distance
                         for i in range(2)]
            if statuses != ["synthetic-tenant-a", "synthetic-tenant-b"] or distances != [10, 17]:
                raise ValueError

            revoker = _make_registry(assumed, self.binding, context, material,
                                     monotonic=self.monotonic, writer=True)
            revoker.revoke(context.grants[0], context.snapshots[0])
            revoked_registry = _make_registry(assumed, self.binding, context, material,
                                              monotonic=self.monotonic, writer=False)
            try:
                revoked_registry.get_binding(context.grants[0], context.snapshots[0])
            except IdentityBindingError as exc:
                if exc.category != "identity_binding_revoked":
                    raise
            else:
                raise ValueError
            # The provider boundary must independently deny a cached-style
            # business call after the exact durable revoked status is proven.
            try:
                make_service(0).get_vehicle_status()
            except EnrolledProviderError:
                pass
            else:
                raise ValueError
            if make_service(1).get_vehicle_status().status != "synthetic-tenant-b":
                raise ValueError
            return {
                "tenant_a_enrolled": True, "tenant_b_enrolled": True,
                "tenant_results_isolated": True, "tenant_a_revoked": True,
                "tenant_b_remained_active": True,
            }
        finally:
            context.connection.close()

    def _verify_storage(self, state: dict[str, Any]) -> dict[str, Any]:
        if state is None or state["phase"] != "storage_exercise_verified":
            raise SseRecoveryError("readback_unverified")
        self._source()
        self._verify_operator_identity()
        self._verify_stack(target=True, require_events=True, require_empty=False)
        self._verify_parameters(require_tenant_absent=False)
        _, assumed = self._assumed()
        material = _load_keys(assumed, self.binding, _SYNTHETIC_CONFIG, monotonic=self.monotonic)
        flags = self._readback_fresh_readers(assumed, material)
        if type(flags) is not dict or set(flags) != {
            "tenant_a_revoked", "tenant_b_active", "tenant_parameter_versions_verified",
        } or any(value is not True for value in flags.values()):
            raise SseRecoveryError("readback_unverified")
        final_flags = {**state["flags"], "tenant_b_active": True,
                       "tenant_parameter_versions_verified": True}
        self._save(self._state_base("readback_verified", intent=state["intent"],
                                    update_token=state["update_token"], ack=True, flags=final_flags),
                   self.probe_journal)
        return self._safe("verify", True, "readback_verified", **flags)

    def _readback_fresh_readers(self, assumed: Mapping[str, Any], material: Any) -> dict[str, bool]:
        from scripts.run_dev_identity_binding_storage_probe import _synthetic_identity_context

        context = _synthetic_identity_context(self.binding["tenant_keys"], material,
                                              wall_clock=self.wall_clock)
        try:
            statuses = []
            for grant, snapshot in zip(context.grants, context.snapshots, strict=True):
                registry = _make_registry(assumed, self.binding, context, material,
                                          monotonic=self.monotonic, writer=False)
                try:
                    registry.get_binding(grant, snapshot)
                except Exception as exc:
                    category = getattr(exc, "category", None)
                    statuses.append("revoked" if category == "identity_binding_revoked" else "invalid")
                else:
                    statuses.append("active")
            if statuses != ["revoked", "active"]:
                raise ValueError
            for key in self.binding["tenant_keys"]:
                if not _parameter_metadata(assumed["ssm"], self.binding["account_id"], key):
                    raise ValueError
                self._verify_current_tenant_parameter(assumed["ssm"], key)
            return {"tenant_a_revoked": True, "tenant_b_active": True,
                    "tenant_parameter_versions_verified": True}
        except Exception:
            raise SseRecoveryError("readback_unverified") from None
        finally:
            context.connection.close()

    def _verify_current_tenant_parameter(self, client: Any, key: str) -> None:
        path = f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
        response = self._call("ssm", "get_parameter", Name=path, WithDecryption=False)
        parameter = response.get("Parameter") if isinstance(response, Mapping) else None
        modified = parameter.get("LastModifiedDate") if isinstance(parameter, Mapping) else None
        if (not isinstance(response, Mapping)
            or not isinstance(response.get("ResponseMetadata"), Mapping)
            or response["ResponseMetadata"].get("HTTPStatusCode") != 200
            or not isinstance(parameter, Mapping)
            or parameter.get("Name") != path
            or parameter.get("ARN") != f"arn:aws:ssm:{REGION}:{self.binding['account_id']}:parameter{path}"
            or parameter.get("Type") != "SecureString"
            or parameter.get("DataType") != "text"
            or type(parameter.get("Version")) is not int or parameter["Version"] != 1
            or "Selector" in parameter or "SourceResult" in parameter
            or not isinstance(modified, datetime) or modified.tzinfo is None
            or modified.utcoffset() is None
            or not self.auth["start"] <= modified.astimezone(timezone.utc).timestamp() < self.auth["end"]):
            raise ValueError

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            active_journal = self.probe_journal if step in {"exercise", "verify"} else self.journal
            with active_journal.locked():
                started = self.monotonic()
                if type(started) not in (int, float) or isinstance(started, bool) or not math.isfinite(started):
                    raise SseRecoveryError("window_invalid")
                self._started = self._last_mono = float(started)
                self._last_epoch = 0
                self._calls[0] = 0
                self._active_clients = _window_bound_clients(
                    self.clients, self.auth, self.wall_clock, calls=self._calls,
                    monotonic=self.monotonic, mono_start=self._started,
                )
                state = self._load(self.probe_journal if step in {"exercise", "verify"} else self.journal)
                self._guard()
                if step == "preflight":
                    if state is not None or self.probe_journal.load() is not None:
                        raise SseRecoveryError("probe_consumed")
                    self._prepare()
                    flags = {"preflight": True}
                    self._save(self._state_base("preflight_verified", flags=flags))
                    return self._safe(step, True, "preflight_verified", preflight=True)
                if step == "update":
                    return self._update(state)
                if step == "readback":
                    return self._verify_transition(state)
                if step == "exercise":
                    update_state = self._load(self.journal)
                    if state is not None:
                        raise SseRecoveryError("probe_consumed")
                    return self._exercise_storage(update_state)
                return self._verify_storage(state)
        except SseRecoveryError as exc:
            return self._safe(step, False, exc.category)
        except (IdentityBindingBootstrapError, StorageProbeError, RetainedDevRunnerError, RehearsalError):
            return self._safe(step, False, "operator_internal_error")
        except Exception:
            return self._safe(step, False, "operator_internal_error")


class _MemoryJournal:
    def load(self):
        return None
    def save(self, _state):
        raise RuntimeError
    def locked(self):
        from contextlib import nullcontext
        return nullcontext()


__all__ = ["DevIdentityBindingSseRecoveryCoordinator", "SseRecoveryError", "validate_recovery_lineage"]
