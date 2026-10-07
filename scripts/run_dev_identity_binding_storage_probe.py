"""One-shot synthetic proof of the retained DEV identity-binding storage path.

This runner does not create application resources, users, or an open endpoint.
It exercises the already accepted dedicated table and exact tenant-scoped SSM
paths with RAM-only synthetic JWTs and transports. A durable probe intent is
saved before key publication or any DynamoDB/tenant-parameter write. Ambiguous
work is never replayed. This is not hosted MCP or MAPIT acceptance.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_dev_identity_binding_bootstrap import (
    APP_STACK_NAME, REGION, RUNTIME_POLICY_NAME,
    DevIdentityBindingBootstrapCoordinator, _unique,
    IdentityBindingBootstrapError, _canonical, _digest,
)
from scripts.build_aws_dev_identity_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_ROLE_NAME, STACK_NAME, build_dev_identity_binding_bootstrap,
)
from scripts.dev_identity_binding_key_setup import publish_keys
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError, _bounded_command, load_authorization,
    validate_private_location, validate_source_and_ci, validate_authorization,
)
from scripts.run_aws_dev_identity_binding_bootstrap import (
    IdentityBindingBootstrapRunnerError, load_binding, validate_github_protections, _BINDING_FIELDS,
    _COORDINATOR_FIELDS, _build_clients as _build_base_clients,
)
from scripts.dev_identity_binding_runtime_evidence import verify_accepted_runtime
from mapit.aws_binding_keys import load_binding_keys
from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.aws_identity_binding_publisher import AwsIdentityBindingPublisher
from mapit.config import MapitConfig
from mapit.durable_tenants import (
    DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore,
)
from mapit.enrolled_provider import EnrolledCloudServicesProvider, EnrolledProviderError
from mapit.mapit_identity import MapitIdentityVerifier
from mapit.tenant_router import InvitedTenantAuthority

_STATE_FIELDS = frozenset({
    "schema", "operation", "account", "source", "run_id", "caller", "start", "end",
    "bootstrap_sha256", "tenant_keys_sha256", "bootstrap_stack_id", "phase", "intent", "flags",
})
_SYNTHETIC_CONFIG = MapitConfig(
    region="eu-west-1", user_pool_id="eu-west-1_SyntheticPool001",
    user_pool_client_id="SyntheticMapitClient001",
    identity_pool_id="eu-west-1:11111111-2222-4333-8444-555555555555",
    core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me",
    discovery_enabled=False, http_timeout=2.0,
)
_SUBJECTS = ("00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b2")
_INVITATION_KID = "storage-probe-invitation"
_MAPIT_KID = "storage-probe-mapit"
_EXPECTED_SERVICES = {
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
_CLIENT_KEYS = frozenset(_EXPECTED_SERVICES)
_ASSUMED_CLIENT_KEYS = frozenset({"sts", "dynamodb", "ssm"})
_PROBE_CALL_LIMIT = 160
_PROBE_STEP_SECONDS = 90.0
_CATEGORIES = frozenset({
    "step_invalid", "authorization_invalid", "binding_invalid", "authorization_mismatch",
    "source_ci_failed", "protection_failed", "private_state_invalid", "journal_invalid",
    "clients_invalid", "assume_role_unverified", "bootstrap_receipt_invalid",
    "bootstrap_readback_unverified", "runtime_closed_unverified", "preflight_conflict",
    "preflight_verified", "probe_intent_saved", "key_publication_unverified",
    "storage_exercise_unverified", "storage_exercise_verified", "readback_unverified",
    "readback_verified", "probe_consumed", "window_invalid", "window_expired",
    "operator_internal_error",
})


class StorageProbeError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _bootstrap_receipt(state: Any, binding: Mapping[str, Any]) -> tuple[str, str]:
    """Validate the immutable historical receipt without loading it as authority."""
    try:
        expected_template = build_dev_identity_binding_bootstrap(
            account_id=binding["account_id"], operator_user_arn=binding["operator_user_arn"],
            tenant_keys=binding["tenant_keys"], ssm_key_arn=binding["ssm_key_arn"],
        )
        template_sha = hashlib.sha256(_canonical(expected_template)).hexdigest()
        required = {
            "schema", "kind", "account", "source_sha", "run_id", "template_sha256",
            "binding_sha256", "expected_caller_arn", "authorized_from_epoch",
            "authorized_until_epoch", "last_observed_epoch", "preflight", "intent",
            "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt",
        }
        if type(state) is not dict or set(state) != required:
            raise ValueError
        source = state["source_sha"]
        run_id = state["run_id"]
        coordinator_binding = {
            key: binding[key]
            for key in _COORDINATOR_FIELDS
            if key != "tenant_keys"
        }
        token = "dev-identity-bindings-" + hashlib.sha256(
            f"{binding['account_id']}:{source}:{run_id}".encode("ascii")
        ).hexdigest()
        intent = state["intent"]
        start, end = state["authorized_from_epoch"], state["authorized_until_epoch"]
        if (type(state["schema"]) is not int or state["schema"] != 1 or state["kind"] != "dev-identity-binding-bootstrap"
            or state["account"] != binding["account_id"] or state["expected_caller_arn"] != binding["operator_user_arn"]
            or type(source) is not str or re.fullmatch(r"[0-9a-f]{40}", source) is None
            or type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0
            or any(type(value) is not int or isinstance(value, bool) for value in (start, end, state["last_observed_epoch"]))
            or start <= 0 or not start <= state["last_observed_epoch"] < end or end <= start or end - start > 3600
            or state["template_sha256"] != template_sha
            or state["binding_sha256"] != _digest(coordinator_binding)
            or state["preflight"] is not True or state["acknowledged"] is not True or state["readback"] is not True
            or type(intent) is not dict or set(intent) != {"token", "stack_name"}
            or intent != {"token": token, "stack_name": STACK_NAME}
            or type(state["acknowledged_stack_id"]) is not str
            or state["readback_receipt"] != {"stack_id": state["acknowledged_stack_id"], "template_sha256": template_sha}):
            raise ValueError
        match = re.fullmatch(
            rf"arn:aws:cloudformation:{REGION}:{binding['account_id']}:stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}",
            state["acknowledged_stack_id"],
        )
        if match is None:
            raise ValueError
        return template_sha, state["acknowledged_stack_id"]
    except Exception:
        raise StorageProbeError("bootstrap_receipt_invalid") from None


def _verify_client_set(clients: Mapping[str, Any]) -> None:
    _verify_clients(clients, _CLIENT_KEYS)


def _verify_assumed_client_set(clients: Mapping[str, Any]) -> None:
    _verify_clients(clients, _ASSUMED_CLIENT_KEYS)


def _verify_clients(clients: Mapping[str, Any], expected_keys: frozenset[str]) -> None:
    if not isinstance(clients, Mapping) or set(clients) != expected_keys:
        raise StorageProbeError("clients_invalid")
    try:
        for name, client in clients.items():
            meta, config = client.meta, client.meta.config
            service, region, endpoint = _EXPECTED_SERVICES[name]
            if (meta.service_model.service_name != service or meta.region_name != region or meta.endpoint_url != endpoint
                or not isinstance(config.retries, Mapping) or type(config.retries.get("total_max_attempts")) is not int
                or config.retries["total_max_attempts"] != 1
                or any(type(x) not in (int, float) or not math.isfinite(x) or not 0 < x <= 3
                       for x in (config.connect_timeout, config.read_timeout))):
                raise ValueError
    except Exception:
        raise StorageProbeError("clients_invalid") from None


def _assume_clients(base_clients: Mapping[str, Any], auth: Mapping[str, Any], binding: Mapping[str, Any],
                    explicit_client_factory: Callable[[Mapping[str, str]], Mapping[str, Any]],
                    wall_clock: Callable[[], float], calls: list[int],
                    monotonic: Callable[[], float], mono_start: float) -> dict[str, Any]:
    try:
        sts = base_clients["sts"]
        who = sts.get_caller_identity()
        caller = who.get("Arn")
        account = binding["account_id"]
        if (not _http200(who) or who.get("Account") != account or caller != auth["expected_caller_arn"]
            or caller != binding["operator_user_arn"]):
            raise ValueError
        role_arn = f"arn:aws:iam::{account}:role/{OPERATOR_ROLE_NAME}"
        result = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"storage-probe-{auth['run_id']}", DurationSeconds=900)
        if not _http200(result):
            raise ValueError
        creds = result.get("Credentials")
        if not isinstance(creds, Mapping) or set(creds) != {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}:
            raise ValueError
        if any(type(creds.get(k)) is not str or not creds[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
            raise ValueError
        expiration = creds.get("Expiration")
        if not isinstance(expiration, datetime) or expiration.tzinfo is None or expiration.timestamp() <= wall_clock() + 120:
            raise ValueError
        # The explicit-credential factory must be bracketed by the already
        # active step guard; construction may be slow even though it is local.
        base_clients["sts"]._guard()
        explicit = explicit_client_factory({k: creds[k] for k in ("AccessKeyId", "SecretAccessKey", "SessionToken")})
        _verify_assumed_client_set(explicit)
        assumed_clients = _window_bound_clients(
            explicit, auth, wall_clock, calls=calls, monotonic=monotonic, mono_start=mono_start,
        )
        base_clients["sts"]._guard()
        assumed = assumed_clients["sts"].get_caller_identity()
        arn = assumed.get("Arn") if isinstance(assumed, Mapping) else None
        if (not _http200(assumed) or assumed.get("Account") != account or type(arn) is not str
            or re.fullmatch(rf"arn:aws:sts::{account}:assumed-role/{re.escape(OPERATOR_ROLE_NAME)}/storage-probe-[1-9][0-9]{{0,17}}", arn) is None):
            raise ValueError
        return assumed_clients
    except StorageProbeError:
        raise
    except Exception:
        raise StorageProbeError("assume_role_unverified") from None


def _http200(response: Any) -> bool:
    return (isinstance(response, Mapping) and isinstance(response.get("ResponseMetadata"), Mapping)
            and type(response["ResponseMetadata"].get("HTTPStatusCode")) is int
            and response["ResponseMetadata"]["HTTPStatusCode"] == 200)


class _WindowBoundClient:
    """Guard every assumed-role request with the immutable operator window."""
    def __init__(self, client: Any, guard: Callable[[], None], calls: list[int]):
        self._client, self._guard, self._calls = client, guard, calls

    def __getattr__(self, name: str):
        value = getattr(self._client, name)
        if name == "meta" or not callable(value):
            return value
        def call(*args, **kwargs):
            self._guard()
            self._calls[0] += 1
            try:
                return value(*args, **kwargs)
            finally:
                self._guard(check_budget=False)
        return call


def _window_bound_clients(clients: Mapping[str, Any], auth: Mapping[str, Any],
                          wall_clock: Callable[[], float], *, calls: list[int] | None = None,
                          monotonic: Callable[[], float] = time.monotonic,
                          mono_start: float | None = None) -> dict[str, Any]:
    last = [float(auth["start"])]
    calls = calls if calls is not None else [0]
    try:
        started = monotonic() if mono_start is None else mono_start
        if type(started) not in (int, float) or isinstance(started, bool) or not math.isfinite(started):
            raise ValueError
    except Exception:
        raise StorageProbeError("window_invalid") from None
    last_mono = [float(started)]
    def guard(*, check_budget: bool = True):
        try:
            now = wall_clock()
            current_mono = monotonic()
            if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
                or now < last[0] or type(current_mono) not in (int, float) or isinstance(current_mono, bool)
                or not math.isfinite(current_mono) or current_mono < last_mono[0]
                or current_mono - started >= _PROBE_STEP_SECONDS):
                raise ValueError
            if not auth["start"] <= now < auth["end"]:
                raise StorageProbeError("window_expired")
            if check_budget and calls[0] >= _PROBE_CALL_LIMIT:
                raise StorageProbeError("clients_invalid")
            last[0] = float(now)
            last_mono[0] = float(current_mono)
        except StorageProbeError:
            raise
        except Exception:
            raise StorageProbeError("window_invalid") from None
    guard()
    return {key: _WindowBoundClient(client, guard, calls) for key, client in clients.items()}


class _SyntheticContext:
    def __init__(self, authority, grants, snapshots, guard, connection, config, verifier, refresh_tokens,
                 mapit_tokens, wall_clock):
        self.authority, self.grants, self.snapshots, self.guard = authority, grants, snapshots, guard
        self.connection, self.config, self.verifier = connection, config, verifier
        self.refresh_tokens, self.mapit_tokens = refresh_tokens, mapit_tokens
        self.access_key_to_index = {}
        self._wall_clock = wall_clock

    def __repr__(self):
        return "SyntheticStorageContext(<redacted>)"

    def auth_transport(self, _url, headers, payload):
        target = headers.get("X-Amz-Target", "")
        if target.endswith("InitiateAuth"):
            refresh = payload.get("AuthParameters", {}).get("REFRESH_TOKEN")
            token = self.mapit_tokens[refresh]
            return {"AuthenticationResult": {"IdToken": token, "AccessToken": "synthetic-access", "ExpiresIn": 1800}}
        if target.endswith("GetId"):
            id_token = next(iter(payload.get("Logins", {}).values()))
            index = self.mapit_tokens_inverse[id_token]
            return {"IdentityId": f"eu-west-1:11111111-2222-4333-8444-55555555555{index}"}
        if target.endswith("GetCredentialsForIdentity"):
            id_token = next(iter(payload.get("Logins", {}).values()))
            index = self.mapit_tokens_inverse[id_token]
            key_id = f"SYNTHETICACCESSKEY{index}"
            self.access_key_to_index[key_id] = index
            return {"Credentials": {"AccessKeyId": key_id, "SecretKey": "synthetic-secret",
                "SessionToken": "synthetic-session", "Expiration": datetime.fromtimestamp(self._wall_clock() + 1200, timezone.utc)}}
        raise ValueError

    @property
    def mapit_tokens_inverse(self):
        return {value: index for index, value in enumerate(self.mapit_tokens.values())}

    def mapit_transport(self, method, url, headers):
        if method != "GET":
            raise ValueError
        match = re.search(r"Credential=([^/]+)/", headers.get("Authorization", ""))
        if match is None or match.group(1) not in self.access_key_to_index:
            raise ValueError
        index = self.access_key_to_index[match.group(1)]
        if url.endswith("/v1/account-summary"):
            status = "synthetic-tenant-a" if index == 0 else "synthetic-tenant-b"
            return json.dumps({"vehicles": [{"id": "synthetic-vehicle", "device": {"state": {"status": status}}}]}).encode()
        return json.dumps({"data": [{"id": "synthetic-route", "startedAt": "2026-01-10T00:00:00Z",
                                      "distance": 10 + 7 * index}]}).encode()


def _synthetic_identity_context(tenant_keys: tuple[str, str], key_material: Any, *, wall_clock: Callable[[], float]):
    """Create two valid invitation grants and MAPIT ID tokens in RAM only."""
    import jwt
    import sqlite3
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    now = int(wall_clock())
    verifier_now = int(time.time())
    invite_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mapit_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def public(private):
        return private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    policies = {tenant_keys[i]: CognitoDevPolicy("eu-west-1_SyntheticPool001", "a1b2c3d4e5",
                 "SyntheticInviteClient", _SUBJECTS[i]) for i in range(2)}
    authority = InvitedTenantAuthority(policies, {_INVITATION_KID: public(invite_private)}, environment="dev")
    grants, refresh_tokens = [], []
    invitation_expiry = verifier_now + 1800
    for i, key in enumerate(tenant_keys):
        policy = policies[key]
        access = jwt.encode({"iss": policy.issuer_url, "aud": policy.audience, "sub": _SUBJECTS[i],
            "client_id": policy.client_id, "token_use": "access", "iat": verifier_now - 1,
            "exp": invitation_expiry, "scope": policy.required_scope}, invite_private,
            algorithm="RS256", headers={"kid": _INVITATION_KID, "typ": "JWT"})
        grants.append(asyncio.run(authority.authenticate(access)))
        refresh_tokens.append("synthetic-refresh-" + str(i) + "-" + hashlib.sha256(access.encode()).hexdigest()[:24])
    conn = sqlite3.connect(":memory:")
    store = SQLiteTenantStore.initialize(conn)
    for grant in grants:
        store.cas(grant.key, None, DurableTenantRecord(grant.key, "active", 1))
    guard = DurableTenantGuard(authority, store)
    snapshots = [guard.capture(grant) for grant in grants]
    config = _SYNTHETIC_CONFIG
    verifier = MapitIdentityVerifier(config, {_MAPIT_KID: public(mapit_private),}, key_material.identity_proof_hmac_key,
        clock=lambda: datetime.fromtimestamp(wall_clock(), timezone.utc))
    mapit_expiry = now + 1800
    mapit_tokens = {
        refresh_tokens[i]: jwt.encode({"iss": verifier.issuer, "aud": config.user_pool_client_id,
            "sub": _SUBJECTS[i], "token_use": "id", "iat": now - 1, "exp": mapit_expiry},
            mapit_private, algorithm="RS256", headers={"kid": _MAPIT_KID, "typ": "JWT"})
        for i in range(2)
    }
    return _SyntheticContext(authority, grants, snapshots, guard, conn, config, verifier,
                             refresh_tokens, mapit_tokens, wall_clock)


def _account_verifier(sts_client: Any, expected_role_arn: str, target_client: Any):
    used = False
    def verify(client, account_id):
        nonlocal used
        if used or client is not target_client or account_id != expected_role_arn.split(":")[4]:
            return False
        used = True
        try:
            response = sts_client.get_caller_identity()
            arn = response.get("Arn")
            return (_http200(response) and response.get("Account") == account_id
                    and type(arn) is str and re.fullmatch(
                        rf"arn:aws:sts::{account_id}:assumed-role/{re.escape(OPERATOR_ROLE_NAME)}/storage-probe-[1-9][0-9]{{0,17}}", arn) is not None)
        except Exception:
            return False
    return verify


def _receipt_state(auth: Mapping[str, Any], binding: Mapping[str, Any], bootstrap_sha: str,
                   stack_id: str, *, phase: str, intent: str | None, flags: Mapping[str, bool]) -> dict[str, Any]:
    return {
        "schema": 1, "operation": "dev_identity_binding_storage_probe",
        "account": binding["account_id"], "source": auth["source_sha"], "run_id": auth["run_id"],
        "caller": auth["expected_caller_arn"], "start": auth["start"], "end": auth["end"],
        "bootstrap_sha256": bootstrap_sha, "tenant_keys_sha256": hashlib.sha256(
            _canonical(list(binding["tenant_keys"]))
        ).hexdigest(), "bootstrap_stack_id": stack_id, "phase": phase,
        "intent": intent, "flags": dict(flags),
    }


def _validate_probe_state(state: Any, auth: Mapping[str, Any], binding: Mapping[str, Any], bootstrap_sha: str,
                          stack_id: str) -> dict[str, Any]:
    if (type(state) is not dict or set(state) != _STATE_FIELDS
        or state.get("schema") != 1 or state.get("operation") != "dev_identity_binding_storage_probe"
        or state.get("account") != binding["account_id"] or state.get("source") != auth["source_sha"]
        or state.get("run_id") != auth["run_id"] or state.get("caller") != auth["expected_caller_arn"]
        or state.get("start") != auth["start"] or state.get("end") != auth["end"]
        or state.get("bootstrap_sha256") != bootstrap_sha
        or state.get("tenant_keys_sha256") != hashlib.sha256(_canonical(list(binding["tenant_keys"]))).hexdigest()
        or state.get("bootstrap_stack_id") != stack_id
        or state.get("phase") not in {"preflight_verified", "intent_saved", "accepted", "readback_verified"}
        or type(state.get("intent")) not in (str, type(None))
        or not isinstance(state.get("flags"), dict)
        or any(type(value) is not bool for value in state["flags"].values())):
        raise StorageProbeError("journal_invalid")
    expected = {
        "preflight_verified": ({"preflight": True}, None),
        "intent_saved": ({"preflight": True, "intent_saved": True}, "storage_exercise"),
        "accepted": (_exercise_receipt_flags(), "storage_exercise"),
        "readback_verified": (_readback_receipt_flags(), "storage_exercise"),
    }[state["phase"]]
    if state["flags"] != expected[0] or state["intent"] != expected[1]:
        raise StorageProbeError("journal_invalid")
    return state


def _exercise_receipt_flags() -> dict[str, bool]:
    return {
        "preflight": True, "intent_saved": True, "storage_exercise": True,
        "tenant_a_enrolled": True, "tenant_b_enrolled": True,
        "tenant_results_isolated": True, "tenant_a_revoked": True,
        "tenant_b_remained_active": True,
    }


def _readback_receipt_flags() -> dict[str, bool]:
    return {**_exercise_receipt_flags(), "tenant_b_active": True,
            "tenant_parameter_versions_verified": True}


def _verify_accepted_bootstrap(clients: Mapping[str, Any], auth: Mapping[str, Any], binding: Mapping[str, Any],
                               accepted_state: Mapping[str, Any], *, wall_clock: Callable[[], float],
                               monotonic: Callable[[], float], parameter_state: str) -> tuple[str, str, int]:
    template_sha, stack_id = _bootstrap_receipt(dict(accepted_state), binding)
    # Reuse fixed application/table/IAM comparators while using the fresh probe
    # authorization window. Never call the old coordinator or mutate its journal.
    coordinator = DevIdentityBindingBootstrapCoordinator(
        clients, _MemoryJournal(), binding={key: binding[key] for key in (
            "account_id", "operator_user_arn", "tenant_keys", "accepted_runtime_journal_path",
            "app_stack_arn", "app_run_id", "api_id", "user_pool_id", "client_id",
            "template_sha256", "code_sha256", "handler_role_arn", "handler_trust_sha256",
            "handler_policies_sha256", "ssm_key_arn")},
        source_sha=auth["source_sha"], run_id=auth["run_id"], expected_caller_arn=auth["expected_caller_arn"],
        authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
        accepted_runtime_verifier=verify_accepted_runtime, wall_clock=wall_clock, monotonic=monotonic,
    )
    initial = monotonic()
    coordinator._started = coordinator._last_mono = float(initial)
    coordinator._last_epoch = int(wall_clock())
    coordinator._calls = coordinator._accepted_calls = 0
    try:
        identity = clients["sts"].get_caller_identity()
        if (not _http200(identity) or identity.get("Account") != binding["account_id"]
            or identity.get("Arn") != auth["expected_caller_arn"]):
            raise ValueError
        # Assumed role identity has already been checked by _assume_clients.
        stack_reply = coordinator._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        stacks = stack_reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise ValueError
        stack = stacks[0]
        if (stack.get("StackName") != STACK_NAME or stack.get("StackId") != stack_id
            or stack.get("StackStatus") != "CREATE_COMPLETE" or stack.get("EnableTerminationProtection") is not True
            or stack.get("RoleARN") not in (None, "")):
            raise ValueError
        old_run = accepted_state["run_id"]
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                         "Purpose": "mapit-identity-bindings", "OperatorRunId": str(old_run)}
        tags = stack.get("Tags")
        if (type(tags) is not list or len(tags) != len(expected_tags)
            or any(not isinstance(row, Mapping) or set(row) != {"Key", "Value"} for row in tags)
            or {row["Key"]: row["Value"] for row in tags} != expected_tags):
            raise ValueError
        template_reply = coordinator._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        actual = template_reply.get("TemplateBody")
        if isinstance(actual, str):
            actual = json.loads(actual, object_pairs_hook=_unique)
        if _canonical(actual) != coordinator.template_bytes:
            raise ValueError
        events = coordinator._call("cloudformation", "describe_stack_events", StackName=STACK_NAME).get("StackEvents")
        expected_token = accepted_state["intent"]["token"]
        if (type(events) is not list or not 1 <= len(events) <= 100
            or not any(isinstance(row, Mapping) and row.get("ClientRequestToken") == expected_token
                       and row.get("StackId") == stack_id and row.get("StackName") == STACK_NAME for row in events)):
            raise ValueError
        resources = coordinator._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME).get("StackResources")
        names = {"MapitIdentityBindings": "AWS::DynamoDB::Table", "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
                 "IdentityEnrollerRole": "AWS::IAM::Role", "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy"}
        if type(resources) is not list or len(resources) != 4:
            raise ValueError
        seen = set()
        for row in resources:
            if (not isinstance(row, Mapping) or row.get("StackId") != stack_id or row.get("StackName") != STACK_NAME
                or row.get("ResourceStatus") != "CREATE_COMPLETE" or row.get("ResourceType") != names.get(row.get("LogicalResourceId"))
                or row.get("LogicalResourceId") in seen or type(row.get("PhysicalResourceId")) is not str):
                raise ValueError
            seen.add(row["LogicalResourceId"])
        if seen != set(names):
            raise ValueError
        coordinator._verify_current_app(include_runtime_policy=True)
        coordinator._verify_iam(f"arn:aws:iam::{binding['account_id']}:policy/honda-mapit-mcp-dev-identity-enroller-boundary")
        coordinator._verify_ssm_key()
        # The original readback required all three SSM paths absent. On later
        # steps only the config key and two synthetic tenant paths are allowed.
        if parameter_state not in {"preflight", "exercise", "readback"}:
            raise ValueError
        if parameter_state == "preflight":
            if not _verify_table_empty(clients["dynamodb"], binding["account_id"], coordinator):
                raise ValueError
            coordinator._verify_parameters_absent()
        else:
            # The key setup intentionally creates the config item after the
            # bootstrap receipt. Recheck table controls/tags, then bind item
            # and tenant-parameter state to the exact step.
            _verify_table_controls(clients["dynamodb"], binding["account_id"], coordinator)
            item = coordinator._call("dynamodb", "get_item", TableName=f"arn:aws:dynamodb:eu-west-1:{binding['account_id']}:table/honda-mapit-mcp-dev-identity-bindings",
                Key={"key": {"S": "identity-bindings-v1"}}, ConsistentRead=True, ReturnConsumedCapacity="NONE")
            if parameter_state == "exercise" and set(item) - {"ResponseMetadata"}:
                raise ValueError
            if parameter_state == "readback" and not isinstance(item.get("Item"), Mapping):
                raise ValueError
            for tenant_key in binding["tenant_keys"]:
                path = f"/honda-mapit-mcp/dev/tenants/{tenant_key}/mapit-refresh-token"
                if parameter_state == "exercise":
                    coordinator._call_absent("ssm", "get_parameter", absence="parameter", Name=path, WithDecryption=False)
                else:
                    reply = coordinator._call("ssm", "get_parameter", Name=path + ":1", WithDecryption=False)
                    parameter = reply.get("Parameter") if isinstance(reply, Mapping) else None
                    if (not isinstance(parameter, Mapping) or parameter.get("Name") != path
                        or parameter.get("ARN") != f"arn:aws:ssm:eu-west-1:{binding['account_id']}:parameter{path}"
                        or parameter.get("Type") != "SecureString" or parameter.get("DataType") != "text"
                        or type(parameter.get("Version")) is not int or parameter["Version"] != 1
                        or parameter.get("Selector") != ":1" or "SourceResult" in parameter):
                        raise ValueError
            config = coordinator._call("ssm", "get_parameter", Name=CONFIG_PARAMETER + ":1", WithDecryption=False)
            parameter = config.get("Parameter") if isinstance(config, Mapping) else None
            if (not isinstance(parameter, Mapping) or parameter.get("Name") != CONFIG_PARAMETER
                or parameter.get("ARN") != f"arn:aws:ssm:eu-west-1:{binding['account_id']}:parameter{CONFIG_PARAMETER}"
                or parameter.get("Type") != "SecureString" or type(parameter.get("Version")) is not int
                or parameter["Version"] != 1 or parameter.get("Selector") != ":1"
                or parameter.get("DataType") != "text" or "SourceResult" in parameter):
                raise ValueError
        calls = coordinator._calls + coordinator._accepted_calls
        if calls > 48:
            raise ValueError
        return template_sha, stack_id, calls
    except Exception:
        raise StorageProbeError("bootstrap_readback_unverified") from None


class _MemoryJournal:
    def __init__(self):
        self.value = None
    def load(self):
        return self.value
    def save(self, value):
        self.value = value
    def locked(self):
        from contextlib import nullcontext
        return nullcontext()


def _verify_table_controls(client: Any, account: str, coordinator: DevIdentityBindingBootstrapCoordinator) -> None:
    table_arn = f"arn:aws:dynamodb:eu-west-1:{account}:table/honda-mapit-mcp-dev-identity-bindings"
    reply = coordinator._call("dynamodb", "describe_table", TableName="honda-mapit-mcp-dev-identity-bindings")
    table = reply.get("Table")
    if (not isinstance(table, Mapping) or table.get("TableArn") != table_arn
        or table.get("TableName") != "honda-mapit-mcp-dev-identity-bindings"
        or table.get("TableStatus") != "ACTIVE" or table.get("DeletionProtectionEnabled") is not True
        or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
        or table.get("OnDemandThroughput") != {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100}
        or table.get("KeySchema") != [{"AttributeName": "key", "KeyType": "HASH"}]
        or table.get("AttributeDefinitions") != [{"AttributeName": "key", "AttributeType": "S"}]
        or table.get("GlobalSecondaryIndexes") not in (None, [])
        or table.get("LocalSecondaryIndexes") not in (None, [])):
        raise ValueError
    tags = coordinator._call("dynamodb", "list_tags_of_resource", ResourceArn=table_arn).get("Tags")
    required = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "mapit-identity-bindings"}
    if (type(tags) is not list or any(not isinstance(row, Mapping) for row in tags)
        or len({row.get("Key") for row in tags}) != len(tags)
        or any(not any(row.get("Key") == key and row.get("Value") == value for row in tags) for key, value in required.items())):
        raise ValueError


def _verify_table_empty(client: Any, account: str, coordinator: DevIdentityBindingBootstrapCoordinator) -> bool:
    try:
        _verify_table_controls(client, account, coordinator)
        table_arn = f"arn:aws:dynamodb:eu-west-1:{account}:table/honda-mapit-mcp-dev-identity-bindings"
        item = coordinator._call("dynamodb", "get_item", TableName=table_arn,
            Key={"key": {"S": "identity-bindings-v1"}}, ConsistentRead=True, ReturnConsumedCapacity="NONE")
        if set(item) - {"ResponseMetadata"}:
            raise ValueError
        return True
    except Exception:
        return False


def _http_parameter_absent(client: Any, path: str) -> bool:
    try:
        response = client.get_parameter(Name=path, WithDecryption=False)
    except Exception as exc:
        error, meta = getattr(exc, "response", {}), getattr(exc, "response", {}).get("ResponseMetadata", {})
        return (isinstance(error, Mapping) and isinstance(error.get("Error"), Mapping)
                and error["Error"].get("Code") == "ParameterNotFound"
                and isinstance(meta, Mapping) and type(meta.get("HTTPStatusCode")) is int
                and meta["HTTPStatusCode"] == 400)
    return False


def _parameter_metadata(client: Any, account: str, key: str) -> bool:
    path = f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
    try:
        response = client.get_parameter(Name=path + ":1", WithDecryption=False)
        parameter = response.get("Parameter") if isinstance(response, Mapping) else None
        return (_http200(response) and isinstance(parameter, Mapping)
                and parameter.get("Name") == path
                and parameter.get("ARN") == f"arn:aws:ssm:eu-west-1:{account}:parameter{path}"
                and parameter.get("Type") == "SecureString" and parameter.get("DataType") == "text"
                and type(parameter.get("Version")) is int and parameter["Version"] == 1
                and parameter.get("Selector") == ":1" and "SourceResult" not in parameter)
    except Exception:
        return False


def _load_context(auth: Mapping[str, Any], binding: Mapping[str, Any], accepted_state: Mapping[str, Any],
                  parameter_state: str,
                  *, acl_checker: Callable[[Path], bool] | None,
                  source_ci_validator: Callable[[Mapping[str, Any]], None],
                  protection_validator: Callable[[Mapping[str, Any]], None],
                  client_factory: Callable[[], Mapping[str, Any]],
                  explicit_client_factory: Callable[[Mapping[str, str]], Mapping[str, Any]],
                  wall_clock: Callable[[], float], monotonic: Callable[[], float]):
    bootstrap_sha, stack_id = _bootstrap_receipt(accepted_state, binding)
    try:
        source_ci_validator(auth)
    except Exception:
        raise StorageProbeError("source_ci_failed") from None
    try:
        protection_validator(binding)
    except Exception:
        raise StorageProbeError("protection_failed") from None
    try:
        # Check the immutable wall-clock authorization before any SDK client
        # construction or network request, then share one call budget across
        # base and assumed-role clients.
        now = wall_clock()
        mono_start = monotonic()
        if (type(now) not in (int, float) or not math.isfinite(now)
            or type(mono_start) not in (int, float) or not math.isfinite(mono_start)
            or not auth["start"] <= now < auth["end"]):
            raise StorageProbeError("window_expired")
        calls = [0]
        base = client_factory()
        current_mono = monotonic()
        if (type(current_mono) not in (int, float) or isinstance(current_mono, bool)
            or not math.isfinite(current_mono) or current_mono < mono_start
            or current_mono - mono_start >= _PROBE_STEP_SECONDS):
            raise StorageProbeError("window_invalid")
        _verify_client_set(base)
        base = _window_bound_clients(base, auth, wall_clock, calls=calls,
                                     monotonic=monotonic, mono_start=mono_start)
    except StorageProbeError:
        raise
    except Exception:
        raise StorageProbeError("clients_invalid") from None
    _verify_accepted_bootstrap(base, auth, binding, accepted_state,
        wall_clock=wall_clock, monotonic=monotonic,
        parameter_state=parameter_state)
    try:
        assumed = _assume_clients(base, auth, binding, explicit_client_factory, wall_clock, calls,
                                  monotonic, mono_start)
    except StorageProbeError:
        raise
    return bootstrap_sha, stack_id, base, assumed


def _load_key_journal_state(journal: Any, auth: Mapping[str, Any], binding: Mapping[str, Any], bootstrap_sha: str) -> None:
    expected_fields = {"schema", "operation", "account", "source", "run_id", "bootstrap_sha256",
                       "parameter_path", "start", "end", "phase"}
    try:
        state = journal.load()
        if (type(state) is not dict or set(state) != expected_fields
            or type(state.get("schema")) is not int or state["schema"] != 1
            or state.get("operation") != "dev_identity_binding_key_publication"
            or state.get("account") != binding["account_id"]
            or state.get("source") != auth["source_sha"] or state.get("run_id") != auth["run_id"]
            or state.get("start") != auth["start"] or state.get("end") != auth["end"]
            or state.get("bootstrap_sha256") != bootstrap_sha
            or state.get("parameter_path") != CONFIG_PARAMETER or state.get("phase") != "accepted"
            or type(state.get("source")) is not str or re.fullmatch(r"[0-9a-f]{40}", state["source"]) is None
            or type(state.get("run_id")) is not int or isinstance(state.get("run_id"), bool) or state["run_id"] <= 0
            or type(state.get("start")) is not int or isinstance(state.get("start"), bool)
            or type(state.get("end")) is not int or isinstance(state.get("end"), bool)
            or not 0 < state["end"] - state["start"] <= 3600):
            raise ValueError
    except Exception:
        raise StorageProbeError("journal_invalid") from None


def _load_keys(clients: Mapping[str, Any], binding: Mapping[str, Any], config: MapitConfig,
               *, monotonic: Callable[[], float]) -> Any:
    account = binding["account_id"]
    ssm = clients["ssm"]
    verifier = _account_verifier(
        clients["sts"], f"arn:aws:iam::{account}:role/{OPERATOR_ROLE_NAME}", ssm,
    )
    try:
        return load_binding_keys(
            ssm, account_id=account, config=config, account_verifier=verifier,
            deadline=monotonic() + 13.0, monotonic=monotonic,
        )
    except Exception:
        raise StorageProbeError("key_publication_unverified") from None


def _check_probe_parameters_absent(clients: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    for key in binding["tenant_keys"]:
        path = f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
        if not _http_parameter_absent(clients["ssm"], path):
            raise StorageProbeError("preflight_conflict")


def _readback_storage(clients: Mapping[str, Any], binding: Mapping[str, Any], key_material: Any,
                      *, wall_clock: Callable[[], float], monotonic: Callable[[], float]) -> dict[str, bool]:
    context = _synthetic_identity_context(binding["tenant_keys"], key_material, wall_clock=wall_clock)
    try:
        registry = _make_registry(clients, binding, context, key_material, monotonic=monotonic, writer=False)
        statuses = []
        for grant, snapshot in zip(context.grants, context.snapshots, strict=True):
            try:
                registry.get_binding(grant, snapshot)
            except Exception as exc:
                category = getattr(exc, "category", None)
                statuses.append("revoked" if category == "identity_binding_revoked" else "invalid")
            else:
                statuses.append("active")
        if statuses != ["revoked", "active"]:
            raise ValueError
        for key in binding["tenant_keys"]:
            if not _parameter_metadata(clients["ssm"], binding["account_id"], key):
                raise ValueError
        return {"tenant_a_revoked": True, "tenant_b_active": True,
                "tenant_parameter_versions_verified": True}
    except StorageProbeError:
        raise
    except Exception:
        raise StorageProbeError("readback_unverified") from None
    finally:
        context.connection.close()


def run_storage_probe_step(
    authorization: Mapping[str, Any],
    binding: Mapping[str, Any],
    accepted_bootstrap_state: Mapping[str, Any],
    probe_journal: Any,
    key_journal: Any,
    step: str,
    *,
    source_ci_validator: Callable[[Mapping[str, Any]], None],
    protection_validator: Callable[[Mapping[str, Any]], None],
    client_factory: Callable[[], Mapping[str, Any]],
    explicit_client_factory: Callable[[Mapping[str, str]], Mapping[str, Any]],
    wall_clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run one fresh-authority storage probe step using injected clients only.

    The caller must construct the journals in verified private directories and
    invoke fresh source/protection validators. This function never creates SDK
    clients, prints private values, or retries a storage write.
    """
    if type(step) is not str or step not in {"preflight", "exercise", "readback"}:
        return {"step": "unknown", "ok": False, "category": "step_invalid", "flags": {}}
    try:
        auth = validate_authorization(dict(authorization))
        if (type(binding) is not dict or set(binding) != _BINDING_FIELDS
            or binding.get("account_id") != auth["account"]
            or binding.get("operator_user_arn") != auth["expected_caller_arn"]):
            raise StorageProbeError("authorization_mismatch")
        bootstrap_sha, stack_id = _bootstrap_receipt(accepted_bootstrap_state, binding)
        lock = getattr(probe_journal, "locked", None)
        context_manager = lock() if callable(lock) else None
        if context_manager is None:
            raise StorageProbeError("journal_invalid")
        with context_manager:
            current = probe_journal.load()
            if current is not None:
                current = _validate_probe_state(current, auth, binding, bootstrap_sha, stack_id)
            if step == "preflight" and current is not None:
                raise StorageProbeError("probe_consumed")
            if step == "exercise" and (current is None or current["phase"] != "preflight_verified"):
                raise StorageProbeError("preflight_conflict")
            if step == "readback" and (current is None or current["phase"] not in {"accepted", "readback_verified"}):
                raise StorageProbeError("readback_unverified")

            try:
                source_ci_validator(auth)
            except Exception:
                raise StorageProbeError("source_ci_failed") from None
            try:
                protection_validator(binding)
            except Exception:
                raise StorageProbeError("protection_failed") from None
            existing_key_state = key_journal.load() if step in {"exercise", "readback"} else None
            if step == "readback" and existing_key_state is None:
                raise StorageProbeError("journal_invalid")
            verify_stage = ("preflight" if step == "preflight" or (step == "exercise" and existing_key_state is None)
                            else step)
            bootstrap_sha, stack_id, base_clients, assumed_clients = _load_context(
                auth, binding, accepted_bootstrap_state, verify_stage,
                acl_checker=None, source_ci_validator=lambda _: None,
                protection_validator=lambda _: None, client_factory=client_factory,
                explicit_client_factory=explicit_client_factory, wall_clock=wall_clock,
                monotonic=monotonic,
            )
            if step == "preflight":
                new_state = _receipt_state(auth, binding, bootstrap_sha, stack_id,
                    phase="preflight_verified", intent=None, flags={"preflight": True})
                probe_journal.save(new_state)
                return {"step": step, "ok": True, "category": "preflight_verified", "flags": new_state["flags"]}

            if step == "exercise":
                if existing_key_state is not None:
                    _load_key_journal_state(key_journal, auth, binding, bootstrap_sha)
                # A persisted intent permanently consumes this attempt before
                # key publication, DynamoDB writes, or tenant-parameter writes.
                intent_state = _receipt_state(auth, binding, bootstrap_sha, stack_id,
                    phase="intent_saved", intent="storage_exercise",
                    flags={"preflight": True, "intent_saved": True})
                probe_journal.save(intent_state)
                if existing_key_state is None:
                    published = publish_keys(
                        {key: assumed_clients[key] for key in ("sts", "ssm")},
                        key_journal, account_id=binding["account_id"],
                        config=_SYNTHETIC_CONFIG, source_sha=auth["source_sha"],
                        run_id=auth["run_id"], bootstrap_sha256=bootstrap_sha,
                        start=auth["start"], end=auth["end"], clock=wall_clock, monotonic=monotonic,
                    )
                    if published != {"ok": True, "category": "protected_key_handoff_verified"}:
                        raise StorageProbeError("key_publication_unverified")
                else:
                    _check_probe_parameters_absent(assumed_clients, binding)
                key_material = _load_keys(assumed_clients, binding, _SYNTHETIC_CONFIG, monotonic=monotonic)
                flags = _exercise(assumed_clients, binding, key_material,
                                  wall_clock=wall_clock, monotonic=monotonic)
                if (type(flags) is not dict or set(flags) != {
                    "tenant_a_enrolled", "tenant_b_enrolled", "tenant_results_isolated",
                    "tenant_a_revoked", "tenant_b_remained_active",
                } or any(value is not True for value in flags.values())):
                    raise StorageProbeError("storage_exercise_unverified")
                accepted = _receipt_state(auth, binding, bootstrap_sha, stack_id,
                    phase="accepted", intent="storage_exercise",
                    flags={**_exercise_receipt_flags()})
                probe_journal.save(accepted)
                return {"step": step, "ok": True, "category": "storage_exercise_verified", "flags": flags}

            _load_key_journal_state(key_journal, auth, binding, bootstrap_sha)
            key_material = _load_keys(assumed_clients, binding, _SYNTHETIC_CONFIG, monotonic=monotonic)
            flags = _readback_storage(assumed_clients, binding, key_material,
                                      wall_clock=wall_clock, monotonic=monotonic)
            if (type(flags) is not dict or set(flags) != {
                "tenant_a_revoked", "tenant_b_active", "tenant_parameter_versions_verified",
            } or any(value is not True for value in flags.values())):
                raise StorageProbeError("readback_unverified")
            readback = _receipt_state(auth, binding, bootstrap_sha, stack_id,
                phase="readback_verified", intent="storage_exercise",
                flags={**_readback_receipt_flags()})
            probe_journal.save(readback)
            return {"step": step, "ok": True, "category": "readback_verified", "flags": flags}
    except StorageProbeError as exc:
        return {"step": step, "ok": False, "category": exc.category, "flags": {}}
    except (IdentityBindingBootstrapRunnerError, RetainedDevRunnerError, RehearsalError):
        return {"step": step, "ok": False, "category": "private_state_invalid", "flags": {}}
    except Exception:
        return {"step": step, "ok": False, "category": "operator_internal_error", "flags": {}}


def _build_assumed_clients(credentials: Mapping[str, str]) -> dict[str, Any]:
    """Construct only explicit-credential clients for the fixed assumed role."""
    if (not isinstance(credentials, Mapping) or set(credentials) != {
        "AccessKeyId", "SecretAccessKey", "SessionToken",
    } or any(type(credentials.get(key)) is not str or not credentials[key]
             for key in ("AccessKeyId", "SecretAccessKey", "SessionToken"))):
        raise StorageProbeError("clients_invalid")
    try:
        import boto3
        from botocore.config import Config
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=REGION,
        )
        config = Config(connect_timeout=2, read_timeout=3,
                        retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        return {
            "sts": session.client("sts", region_name=REGION,
                endpoint_url=f"https://sts.{REGION}.amazonaws.com", config=config, verify=True),
            "dynamodb": session.client("dynamodb", region_name=REGION,
                endpoint_url=f"https://dynamodb.{REGION}.amazonaws.com", config=config, verify=True),
            "ssm": session.client("ssm", region_name=REGION,
                endpoint_url=f"https://ssm.{REGION}.amazonaws.com", config=config, verify=True),
        }
    except Exception:
        raise StorageProbeError("clients_invalid") from None


def _print_result(result: Mapping[str, Any]) -> None:
    raw_step = result.get("step")
    raw_category = result.get("category")
    raw_flags = result.get("flags")
    flags = raw_flags if type(raw_flags) is dict else {}
    safe = {
        "step": raw_step if type(raw_step) is str and raw_step in {"preflight", "exercise", "readback", "unknown"} else "unknown",
        "ok": result.get("ok") is True,
        "category": raw_category if type(raw_category) is str and raw_category in _CATEGORIES else "operator_internal_error",
        "flags": {key: value for key, value in flags.items()
                  if type(key) is str
                  if key in {"preflight", "intent_saved", "storage_exercise", "tenant_a_enrolled",
                             "tenant_b_enrolled", "tenant_results_isolated", "tenant_a_revoked",
                             "tenant_b_remained_active", "tenant_b_active", "tenant_parameter_versions_verified"}
                  and type(value) is bool},
    }
    print(json.dumps(safe, separators=(",", ":")))


def _ensure_distinct_state_directories(*directories: Path) -> None:
    try:
        normalized = [os.path.normcase(str(Path(item).resolve(strict=True))) for item in directories]
        if len(normalized) != len(set(normalized)):
            raise ValueError
    except Exception:
        raise StorageProbeError("private_state_invalid") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="One-shot synthetic DEV identity-binding storage proof")
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--bootstrap-state-dir", required=True, type=Path)
    parser.add_argument("--probe-state-dir", required=True, type=Path)
    parser.add_argument("--key-state-dir", required=True, type=Path)
    parser.add_argument("--step", choices=("preflight", "exercise", "readback"), required=True)
    args = parser.parse_args(argv)
    try:
        auth_path = validate_private_location(args.authorization)
        binding_path = validate_private_location(args.binding)
        bootstrap_dir = validate_private_location(args.bootstrap_state_dir)
        probe_dir = validate_private_location(args.probe_state_dir)
        state_dirs = [bootstrap_dir, probe_dir]
        if args.step != "preflight":
            key_dir = validate_private_location(args.key_state_dir)
            state_dirs.append(key_dir)
        _ensure_distinct_state_directories(*state_dirs)
        auth = load_authorization(auth_path)
        binding = load_binding(binding_path)
        accepted = FileJournal(bootstrap_dir).load()
        probe_journal = FileJournal(probe_dir)
        if args.step == "preflight":
            key_journal: Any = _EmptyJournal()
        else:
            key_journal = FileJournal(key_dir)
        result = run_storage_probe_step(
            auth, binding, accepted, probe_journal, key_journal, args.step,
            source_ci_validator=validate_source_and_ci,
            protection_validator=validate_github_protections,
            client_factory=_build_base_clients,
            explicit_client_factory=_build_assumed_clients,
        )
    except (StorageProbeError, IdentityBindingBootstrapRunnerError, RetainedDevRunnerError,
            RehearsalError):
        result = {"step": args.step, "ok": False, "category": "private_state_invalid", "flags": {}}
    except Exception:
        result = {"step": args.step, "ok": False, "category": "operator_internal_error", "flags": {}}
    _print_result(result)
    return 0 if result.get("ok") is True else 1


class _EmptyJournal:
    def load(self):
        return None


def _make_registry(clients: Mapping[str, Any], binding: Mapping[str, Any], context: _SyntheticContext,
                   key_material: Any, *, monotonic: Callable[[], float], writer: bool) -> DynamoDBIdentityBindingRegistry:
    account = binding["account_id"]
    ddb = clients["dynamodb"]
    account_check = (_account_verifier(
        clients["sts"], f"arn:aws:iam::{account}:role/{OPERATOR_ROLE_NAME}", ddb,
    ) if writer else None)
    return DynamoDBIdentityBindingRegistry(
        ddb, ddb if writer else None,
        table_arn=f"arn:aws:dynamodb:eu-west-1:{account}:table/honda-mapit-mcp-dev-identity-bindings",
        account_id=account, authority=context.authority, durable_guard=context.guard,
        environment="dev", config=context.config, verifier=context.verifier,
        binding_key=key_material.binding_mac_key, auth_transport=context.auth_transport,
        clock=lambda: datetime.fromtimestamp(context._wall_clock(), timezone.utc),
        deadline=monotonic() + 13.0, account_verifier=account_check,
        monotonic=monotonic,
    )


def _new_publish_adapter(clients: Mapping[str, Any], binding: Mapping[str, Any], context: _SyntheticContext,
                         grant: Any, snapshot: Any, *, monotonic: Callable[[], float]) -> AwsIdentityBindingPublisher:
    account = binding["account_id"]
    ssm = clients["ssm"]
    account_check = _account_verifier(
        clients["sts"], f"arn:aws:iam::{account}:role/{OPERATOR_ROLE_NAME}", ssm,
    )
    return AwsIdentityBindingPublisher(
        ssm, authority=context.authority, grant=grant, durable_guard=context.guard,
        snapshot=snapshot, environment="dev", account_id=account,
        account_verifier=account_check, deadline=monotonic() + 13.0, monotonic=monotonic,
    )


def _exercise(clients: Mapping[str, Any], binding: Mapping[str, Any], key_material: Any,
              *, wall_clock: Callable[[], float], monotonic: Callable[[], float]) -> dict[str, bool]:
    context = _synthetic_identity_context(binding["tenant_keys"], key_material, wall_clock=wall_clock)
    grants, snapshots = context.grants, context.snapshots
    try:
        # Constructors are new for each owner and operation so the backend's
        # one-shot write/account-verification fences cannot be reused.
        registries = [
            _make_registry(clients, binding, context, key_material, monotonic=monotonic, writer=True)
            for _ in grants
        ]
        for index in range(2):
            publisher = _new_publish_adapter(
                clients, binding, context, grants[index], snapshots[index], monotonic=monotonic,
            )
            registries[index].enroll(
                grants[index], snapshots[index], context.refresh_tokens[index], publisher=publisher,
            )

        services = [
            EnrolledCloudServicesProvider(
                registries[index], authority=context.authority, grant=grants[index],
                durable_guard=context.guard, snapshot=snapshots[index], ssm_client=clients["ssm"],
                account_id=binding["account_id"], auth_transport=context.auth_transport,
                mapit_transport=context.mapit_transport, deadline=monotonic() + 13.0,
                monotonic=monotonic,
            ).get()
            for index in range(2)
        ]
        statuses = [service.get_vehicle_status().status for service in services]
        distances = [service.get_distance("2026-01-01", "2026-02-01").distance for service in services]
        if statuses != ["synthetic-tenant-a", "synthetic-tenant-b"] or distances != [10, 17]:
            raise ValueError

        revoker = _make_registry(clients, binding, context, key_material, monotonic=monotonic, writer=True)
        revoker.revoke(grants[0], snapshots[0])
        try:
            services[0].get_vehicle_status()
        except EnrolledProviderError:
            revoked_denied = True
        else:
            revoked_denied = False
        if not revoked_denied or services[1].get_vehicle_status().status != "synthetic-tenant-b":
            raise ValueError
        return {
            "tenant_a_enrolled": True, "tenant_b_enrolled": True,
            "tenant_results_isolated": True, "tenant_a_revoked": True,
            "tenant_b_remained_active": True,
        }
    except StorageProbeError:
        raise
    except Exception:
        raise StorageProbeError("storage_exercise_unverified") from None
    finally:
        context.connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
