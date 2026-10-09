"""One-shot owner DEV invitation preparation; no login or MAPIT session access.

This operator creates exactly one authorization row for the owner key already
authorized by the real-MAPIT bootstrap. It never opens the API, resets users,
publishes keys, reads MAPIT data, or claims owner login acceptance.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
from pathlib import Path
import re
import time
import uuid
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any, Callable

from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantRecord
from scripts.dev_mapit_runtime_evidence import make_mapit_runtime_evidence_verifier
from scripts.dev_mapit_bootstrap_coordinator import _valid_runtime_evidence
from scripts.dev_owner_login_context import parse_accepted_owner_login_context, verify_current_context
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_identity_binding_bootstrap import REGION
from scripts.run_aws_dev_owner_oauth_bootstrap import _load_binding as _load_owner_binding, validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization, validate_authorization, validate_private_location, validate_source_and_ci,
)
from scripts.run_dev_mapit_binding_key_setup import (
    _ENDPOINTS as _MAPIT_ENDPOINTS, _load_accepted_bootstrap, _validate_clients,
    _verify_current_bootstrap,
)
from scripts.run_dev_owner_assisted_login import load_trusted_owner_policy

KIND = "dev-owner-invitation-authority"
SCHEMA = 1
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_AUTH_TABLE = "honda-mapit-mcp-dev-tenants"
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
_CREDENTIAL_ENV_MARKERS = (
    "access_key", "secret_key", "session_token", "security_token", "profile",
    "credential", "config", "web_identity", "role_arn", "role_session", "container_credential",
    "endpoint", "ca_bundle",
)
_FIELDS = frozenset({
    "schema", "kind", "account_id", "operator_user_arn", "source_sha", "ci_run_id",
    "run_id", "authorized_from_epoch", "authorized_until_epoch", "github_owner_id",
    "github_repository_id", "owner_context_sha256", "owner_oauth_stack_id",
    "owner_oauth_client_id", "mapit_bootstrap_authority_sha256",
    "mapit_bootstrap_receipt_sha256", "runtime_evidence_sha256", "owner_tenant_key",
    "state_directory",
})
_MAX_AUTH_BYTES = 16 * 1024
_MAX_CALLS = 160
_STEP_SECONDS = 75.0


def _default_clients() -> dict[str, Any]:
    """Resolve credentials once, then give every client the same frozen tuple."""
    if any((name.casefold() == "boto_config"
            or (name.casefold().startswith("aws_") and any(marker in name.casefold()
                for marker in _CREDENTIAL_ENV_MARKERS))) for name in os.environ):
        raise OwnerInvitationError("client_setup_failed")
    credentials_logger = logging.getLogger("botocore.credentials")
    previous_log_level = credentials_logger.level
    credentials_logger.setLevel(logging.CRITICAL)
    try:
        import boto3
        from botocore.config import Config
        session = boto3.Session(region_name=REGION)
        credentials = session.get_credentials()
        if credentials is None:
            raise ValueError
        frozen = credentials.get_frozen_credentials()
        access_key = getattr(frozen, "access_key", None)
        secret_key = getattr(frozen, "secret_key", None)
        session_token = getattr(frozen, "token", None)
        if (type(access_key) is not str or not access_key
                or type(secret_key) is not str or not secret_key
                or (session_token is not None and type(session_token) is not str)):
            raise ValueError
        common = Config(connect_timeout=2, read_timeout=3,
            retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        clients = {}
        for name, (service, region, endpoint) in _ENDPOINTS.items():
            clients[name] = session.client(
                service, region_name=region, endpoint_url=endpoint, config=common, verify=True,
                aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                aws_session_token=session_token,
            )
        return clients
    except OwnerInvitationError:
        raise
    except Exception:
        raise OwnerInvitationError("client_setup_failed") from None
    finally:
        credentials_logger.setLevel(previous_log_level)


class OwnerInvitationError(ValueError):
    """Fixed safe failure category; never contains provider data."""

    CATEGORIES = frozenset({
        "authorization_invalid", "source_ci_failed", "github_protection_failed",
        "accepted_receipt_invalid", "private_location_invalid", "client_setup_failed",
        "current_state_unverified", "invitation_conflict", "write_outcome_unknown",
        "journal_consumed", "invitation_unverified",
    })

    def __init__(self, category="invitation_unverified"):
        self.category = category if type(category) is str and category in self.CATEGORIES else "invitation_unverified"
        super().__init__(self.category)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sdk_ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping)
            and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _read_json(path: Path, *, acl_checker=None) -> dict[str, Any]:
    resolved = validate_private_location(Path(path), acl_checker=acl_checker)
    size = resolved.stat().st_size
    if type(size) is not int or not 0 < size <= _MAX_AUTH_BYTES:
        raise ValueError
    raw = resolved.read_bytes()
    if len(raw) != size or len(raw) > _MAX_AUTH_BYTES:
        raise ValueError
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(value) is not dict:
        raise ValueError
    return value


def _validate_authority_metadata(value: Any) -> dict[str, Any]:
    """Pure metadata checks; does not establish file or state-path provenance."""
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError
    account = value.get("account_id")
    operator = value.get("operator_user_arn")
    start, end = value.get("authorized_from_epoch"), value.get("authorized_until_epoch")
    if (type(value.get("schema")) is not int or value["schema"] != SCHEMA
            or value.get("kind") != KIND
            or type(account) is not str or _ACCOUNT.fullmatch(account) is None
            or type(operator) is not str
            or re.fullmatch(rf"arn:aws:iam::{account}:user/[A-Za-z0-9+=,.@_/-]+", operator) is None
            or type(value.get("source_sha")) is not str or _SHA40.fullmatch(value["source_sha"]) is None
            or value["source_sha"] == "0" * 40
            or any(type(value.get(k)) is not int or isinstance(value.get(k), bool) or value[k] <= 0
                   for k in ("ci_run_id", "run_id", "github_owner_id", "github_repository_id"))
            or type(start) is not int or isinstance(start, bool) or type(end) is not int or isinstance(end, bool)
            or start <= 0 or end <= start or end - start > 600
            or any(type(value.get(k)) is not str or _SHA256.fullmatch(value[k]) is None for k in (
                "owner_context_sha256", "mapit_bootstrap_authority_sha256",
                "mapit_bootstrap_receipt_sha256", "runtime_evidence_sha256"))
            or type(value.get("owner_oauth_stack_id")) is not str
            or re.fullmatch(rf"arn:aws:cloudformation:eu-west-1:{account}:stack/[A-Za-z0-9-]+/[0-9a-f-]{{36}}",
                            value["owner_oauth_stack_id"]) is None
            or type(value.get("owner_oauth_client_id")) is not str
            or re.fullmatch(r"[A-Za-z0-9]{8,128}", value["owner_oauth_client_id"]) is None
            or type(value.get("owner_tenant_key")) is not str or _KEY.fullmatch(value["owner_tenant_key"]) is None
            or type(value.get("state_directory")) is not str):
        raise ValueError
    return dict(value)


def _validate_authority(value: Any, *, state_dir: Path) -> dict[str, Any]:
    value = _validate_authority_metadata(value)
    if Path(value["state_directory"]).resolve() != Path(state_dir).resolve():
        raise ValueError
    return value


def _exclusive_write(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink() or not payload or len(payload) > _MAX_AUTH_BYTES:
        raise ValueError
    # If creation/flush/fsync fails, retain any partial file. Its existence
    # fences this authorization path; recovery requires a fresh private root.
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _require_fresh_state_dir(path: Path, *, acl_checker=None) -> Path:
    resolved = validate_private_location(Path(path), acl_checker=acl_checker)
    if not resolved.is_dir() or any((resolved / name).exists() or (resolved / name).is_symlink()
            for name in ("rehearsal-state.json", "rehearsal-state.lock", "rehearsal-state.next")):
        raise ValueError
    return resolved


def _parser_only_clients():
    """Metadata-only client shapes required by the accepted journal parser."""
    clients = {}
    for name, (service, region, endpoint) in _MAPIT_ENDPOINTS.items():
        config = SimpleNamespace(retries={"total_max_attempts": 1}, signature_version="v4",
                                 proxies={}, connect_timeout=2, read_timeout=3)
        meta = SimpleNamespace(service_model=SimpleNamespace(service_name=service),
                               region_name=region, endpoint_url=endpoint, config=config)
        clients[name] = SimpleNamespace(
            meta=meta, _endpoint=SimpleNamespace(http_session=SimpleNamespace(_verify=True)))
    return clients


def prepare_private_authorization(
    authorization_path: Path,
    state_dir: Path,
    *,
    source_sha: str,
    ci_run_id: int,
    owner_release_receipt: Path,
    owner_oauth_authorization_path: Path,
    owner_oauth_binding_path: Path,
    owner_oauth_state_dir: Path,
    mapit_bootstrap_authority_path: Path,
    mapit_bootstrap_state_dir: Path,
    synthetic_state_dir: Path,
    acl_checker=None,
    source_validator=validate_source_and_ci,
    protection_reader=validate_github_protections,
    wall_clock=time.time,
    run_id_factory=lambda: uuid.uuid4().hex,
) -> dict[str, Any]:
    """Prepare one private authority after fresh source/protection checks.

    Accepted old journals are loaded by their parser-only APIs. No historical
    operation is resumed, and all required evidence is re-read by the runner.
    """
    try:
        if (type(source_sha) is not str or _SHA40.fullmatch(source_sha) is None or source_sha == "0" * 40
                or type(ci_run_id) is not int or isinstance(ci_run_id, bool) or ci_run_id <= 0):
            raise ValueError
        owner_auth_path = validate_private_location(Path(owner_oauth_authorization_path), acl_checker=acl_checker)
        owner_auth = load_authorization(owner_auth_path)
        owner_binding = _load_owner_binding(Path(owner_oauth_binding_path), acl_checker=acl_checker)
        owner_state_dir = validate_private_location(Path(owner_oauth_state_dir), acl_checker=acl_checker)
        owner_state = FileJournal(owner_state_dir).load()
        owner_policy = load_trusted_owner_policy(Path(owner_release_receipt),
            expected_account=owner_auth["account"], acl_checker=acl_checker)
        owner_context = parse_accepted_owner_login_context(owner_auth, owner_binding, owner_state,
            trusted_owner_policy=owner_policy)
        mapit_authority, _, _, mapit_state, _plan, receipt_sha = _load_accepted_bootstrap(
            Path(mapit_bootstrap_authority_path), Path(mapit_bootstrap_state_dir), _parser_only_clients(),
            acl_checker=acl_checker)
        if (mapit_authority.account_id != owner_context.account
                or mapit_authority.expected_caller_arn != owner_context.operator
                or len(mapit_authority._tenant_keys) != 1):
            raise ValueError
        # Current clean source gate uses the new source/CI, never the consumed
        # historical source envelope.
        now = wall_clock()
        if type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now):
            raise ValueError
        run_uuid = run_id_factory()
        if type(run_uuid) is not str or re.fullmatch(r"[0-9a-f]{32}", run_uuid) is None:
            raise ValueError
        run_id = int(run_uuid[:15], 16) or 1
        start, end = int(now), int(now) + 600
        source_auth = {**owner_auth, "source_sha": source_sha, "ci_run_id": ci_run_id,
                       "run_id": run_id, "start": start, "end": end}
        validate_authorization(source_auth)
        try:
            source_validator(source_auth)
        except Exception:
            raise OwnerInvitationError("source_ci_failed") from None
        try:
            protections = protection_reader(expected_owner_id=owner_context.github_owner_id,
                              expected_repository_id=owner_context.github_repository_id)
        except Exception:
            raise OwnerInvitationError("github_protection_failed") from None
        if protections != (owner_context.github_owner_id, owner_context.github_repository_id):
            raise OwnerInvitationError("github_protection_failed")
        state_path = _require_fresh_state_dir(Path(state_dir), acl_checker=acl_checker)
        target_parent = validate_private_location(Path(authorization_path).parent, acl_checker=acl_checker)
        synthetic_state_path = validate_private_location(Path(synthetic_state_dir), acl_checker=acl_checker)
        if not synthetic_state_path.is_dir():
            raise ValueError
        protected_dirs = (owner_state_dir.resolve(), Path(mapit_bootstrap_state_dir).resolve(),
                          synthetic_state_path.resolve())
        if (not state_path.is_dir() or not target_parent.is_dir()
                or any(state_path.resolve() == p or state_path.resolve() in p.parents
                       or p in state_path.resolve().parents for p in protected_dirs)):
            raise ValueError
        if any(target_parent == p or p in target_parent.parents for p in protected_dirs):
            raise ValueError
        binding = {
            "schema": SCHEMA, "kind": KIND, "account_id": owner_context.account,
            "operator_user_arn": owner_context.operator, "source_sha": source_sha,
            "ci_run_id": ci_run_id, "run_id": run_id,
            "authorized_from_epoch": start, "authorized_until_epoch": end,
            "github_owner_id": owner_context.github_owner_id,
            "github_repository_id": owner_context.github_repository_id,
            "owner_context_sha256": owner_context.context_digest,
            "owner_oauth_stack_id": owner_context.stack_id,
            "owner_oauth_client_id": owner_context.policy.client_id,
            "mapit_bootstrap_authority_sha256": mapit_authority._binding_sha256,
            "mapit_bootstrap_receipt_sha256": receipt_sha,
            "runtime_evidence_sha256": mapit_authority.runtime_evidence_sha256,
            "owner_tenant_key": mapit_authority._tenant_keys[0],
            "state_directory": str(state_path.resolve()),
        }
        _validate_authority(binding, state_dir=state_path)
        _exclusive_write(target_parent / Path(authorization_path).name, _canonical(binding))
        return {"ok": True, "category": "invitation_authority_prepared", "run_id": binding["run_id"]}
    except Exception:
        return {"ok": False, "category": "invitation_authority_unverified"}


class _GuardedClients:
    """Shared one-session SDK budget and immutable time fence."""
    _SERVICES = frozenset({
        "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito", "apigatewayv2", "lambda", "kms",
    })

    def __init__(self, clients, *, owner_key, account_id, start, end,
                 wall_clock, monotonic, max_calls=_MAX_CALLS, seconds=_STEP_SECONDS):
        if not isinstance(clients, Mapping) or set(clients) != self._SERVICES:
            raise ValueError
        self.raw = clients
        self.owner_key = owner_key
        self.account_id = account_id
        self.start, self.end = start, end
        self.wall, self.mono = wall_clock, monotonic
        self.max_calls = max_calls
        self.calls = 0
        self.armed = False
        self.write_dispatch_started = False
        self.last_wall = float(start)
        self.last_mono = monotonic()
        self.deadline = self.last_mono + seconds

    def wrap(self):
        owner = self
        class Proxy:
            def __init__(self, service, client):
                self._service, self._client = service, client

            def __getattr__(self, method):
                if method in {"meta", "_endpoint"}:
                    return getattr(self._client, method)
                target = getattr(self._client, method, None)
                allowed = method.startswith(("get_", "describe_", "list_"))
                if self._service == "sts" and method == "get_caller_identity":
                    allowed = True
                if self._service == "dynamodb" and method == "put_item":
                    allowed = True
                if not callable(target) or not allowed:
                    raise ValueError
                def invoke(**kwargs):
                    before_m, before_w = owner.mono(), owner.wall()
                    if (type(before_m) not in (int, float) or isinstance(before_m, bool)
                            or type(before_w) not in (int, float) or isinstance(before_w, bool)
                            or not math.isfinite(before_m) or not math.isfinite(before_w)
                            or before_m < owner.last_mono or before_m >= owner.deadline
                            or before_w < owner.last_wall or not owner.start <= before_w < owner.end
                            or owner.calls >= owner.max_calls):
                        raise ValueError
                    if method == "get_item":
                        allowed_reads = {
                            (f"arn:aws:dynamodb:eu-west-1:{owner.account_id}:table/{_AUTH_TABLE}", owner.owner_key),
                            (f"arn:aws:dynamodb:eu-west-1:{owner.account_id}:table/honda-mapit-mcp-dev-mapit-identity-bindings",
                             "identity-bindings-v1"),
                        }
                        requested_key = kwargs.get("Key")
                        key_text = (requested_key.get("key", {}).get("S")
                                    if isinstance(requested_key, Mapping)
                                    and isinstance(requested_key.get("key"), Mapping) else None)
                        if (set(kwargs) != {"TableName", "Key", "ConsistentRead", "ReturnConsumedCapacity"}
                                or type(kwargs.get("TableName")) is not str or type(key_text) is not str
                                or (kwargs["TableName"], key_text) not in allowed_reads
                                or requested_key != {"key": {"S": key_text}}
                                or kwargs.get("ConsistentRead") is not True
                                or kwargs.get("ReturnConsumedCapacity") != "NONE"):
                            raise ValueError
                    if method == "put_item":
                        item = kwargs.get("Item")
                        if (not owner.armed or owner.write_dispatch_started or set(kwargs) != {
                                "TableName", "Item", "ConditionExpression", "ExpressionAttributeNames",
                                "ReturnValues", "ReturnConsumedCapacity"}
                                or kwargs.get("TableName") !=
                                f"arn:aws:dynamodb:eu-west-1:{owner.account_id}:table/{_AUTH_TABLE}"
                                or not isinstance(item, Mapping) or set(item) != {"key", "status", "revision"}
                                or item.get("key") != {"S": owner.owner_key}
                                or item.get("status") != {"S": "active"} or item.get("revision") != {"N": "1"}
                                or kwargs.get("ConditionExpression") != "attribute_not_exists(#key)"
                                or kwargs.get("ExpressionAttributeNames") != {"#key": "key"}
                                or kwargs.get("ReturnValues") != "NONE"
                                or kwargs.get("ReturnConsumedCapacity") != "NONE"):
                            raise ValueError
                    owner.last_wall, owner.last_mono = float(before_w), float(before_m)
                    owner.calls += 1
                    if method == "put_item":
                        owner.write_dispatch_started = True
                    result = target(**kwargs)
                    after_m, after_w = owner.mono(), owner.wall()
                    if (type(after_m) not in (int, float) or isinstance(after_m, bool)
                            or type(after_w) not in (int, float) or isinstance(after_w, bool)
                            or not math.isfinite(after_m) or not math.isfinite(after_w)
                            or after_m < before_m or after_m >= owner.deadline or after_w < before_w
                            or not owner.start <= after_w < owner.end):
                        raise ValueError
                    owner.last_wall, owner.last_mono = float(after_w), float(after_m)
                    return result
                return invoke
        return {name: Proxy(name, client) for name, client in self.raw.items()}


def run_authorized_invitation(
    authorization_path: Path,
    owner_release_receipt: Path,
    owner_oauth_authorization_path: Path,
    owner_oauth_binding_path: Path,
    owner_oauth_state_dir: Path,
    mapit_bootstrap_authority_path: Path,
    mapit_bootstrap_state_dir: Path,
    runtime_evidence_path: Path,
    synthetic_binding_path: Path,
    synthetic_authorization_path: Path,
    synthetic_state_dir: Path,
    state_dir: Path,
    *,
    acl_checker=None,
    client_factory: Callable[[], Mapping[str, Any]] = _default_clients,
    source_validator=validate_source_and_ci,
    protection_reader=validate_github_protections,
    runtime_verifier_factory=make_mapit_runtime_evidence_verifier,
    journal_factory=FileJournal,
    wall_clock=time.time,
    monotonic=time.monotonic,
) -> dict[str, Any]:
    """Read current owner/bootstrap/runtime state and create one owner row."""
    guard = None
    stage = "authority"
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        binding = _validate_authority(_read_json(auth_path, acl_checker=acl_checker), state_dir=Path(state_dir))
        private_state = _require_fresh_state_dir(Path(state_dir), acl_checker=acl_checker)
        if (not private_state.is_dir() or str(private_state.resolve()) != binding["state_directory"]
                ):
            raise OwnerInvitationError("journal_consumed")
        journal = journal_factory(private_state)
        # A consumed intent is checked before current-state reads so an
        # ambiguous prior CAS cannot be mistaken for a fresh conflict.
        if journal.load() is not None:
            raise OwnerInvitationError("journal_consumed")
        source_auth = {
            "account": binding["account_id"], "expected_caller_arn": binding["operator_user_arn"],
            "source_sha": binding["source_sha"], "run_id": binding["run_id"],
            "start": binding["authorized_from_epoch"], "end": binding["authorized_until_epoch"],
            "ci_run_id": binding["ci_run_id"],
        }
        validate_authorization(source_auth)
        stage = "source"
        try:
            source_validator(source_auth)
        except Exception:
            raise OwnerInvitationError("source_ci_failed") from None
        stage = "owner_context"
        owner_policy = load_trusted_owner_policy(Path(owner_release_receipt),
            expected_account=binding["account_id"], acl_checker=acl_checker)
        owner_auth_path = validate_private_location(Path(owner_oauth_authorization_path), acl_checker=acl_checker)
        owner_auth = load_authorization(owner_auth_path)
        owner_binding = _load_owner_binding(Path(owner_oauth_binding_path), acl_checker=acl_checker)
        owner_state_path = validate_private_location(Path(owner_oauth_state_dir), acl_checker=acl_checker)
        owner_state = FileJournal(owner_state_path).load()
        owner_context = parse_accepted_owner_login_context(owner_auth, owner_binding, owner_state,
            trusted_owner_policy=owner_policy)
        mapit_authority, _, _, mapit_state, mapit_plan, receipt_sha = _load_accepted_bootstrap(
            Path(mapit_bootstrap_authority_path), Path(mapit_bootstrap_state_dir),
            _parser_only_clients(), acl_checker=acl_checker)
        if (owner_context.account != binding["account_id"] or owner_context.operator != binding["operator_user_arn"]
                or owner_context.context_digest != binding["owner_context_sha256"]
                or owner_context.stack_id != binding["owner_oauth_stack_id"]
                or owner_context.policy.client_id != binding["owner_oauth_client_id"]
                or owner_context.github_owner_id != binding["github_owner_id"]
                or owner_context.github_repository_id != binding["github_repository_id"]
                or mapit_authority._binding_sha256 != binding["mapit_bootstrap_authority_sha256"]
                or receipt_sha != binding["mapit_bootstrap_receipt_sha256"]
                or mapit_authority.runtime_evidence_sha256 != binding["runtime_evidence_sha256"]
                or mapit_authority._tenant_keys != (binding["owner_tenant_key"],)):
            raise OwnerInvitationError("accepted_receipt_invalid")
        stage = "protections"
        historical_dirs = (owner_state_path.resolve(), Path(mapit_bootstrap_state_dir).resolve(),
                           Path(synthetic_state_dir).resolve())
        fresh_state = private_state.resolve()
        if any(fresh_state == p or fresh_state in p.parents or p in fresh_state.parents
               for p in historical_dirs):
            raise OwnerInvitationError("journal_consumed")
        try:
            protections = protection_reader(expected_owner_id=binding["github_owner_id"],
                expected_repository_id=binding["github_repository_id"])
        except Exception:
            raise OwnerInvitationError("github_protection_failed") from None
        if protections != (binding["github_owner_id"], binding["github_repository_id"]):
            raise OwnerInvitationError("github_protection_failed")
        stage = "clients"
        try:
            raw_clients = client_factory()
        except Exception:
            raise OwnerInvitationError("client_setup_failed") from None
        _validate_clients(raw_clients)
        guard = _GuardedClients(raw_clients, owner_key=binding["owner_tenant_key"],
            account_id=binding["account_id"], start=binding["authorized_from_epoch"],
            end=binding["authorized_until_epoch"], wall_clock=wall_clock, monotonic=monotonic)
        clients = guard.wrap()
        stage = "owner_readback"
        owner_sdk = OwnerOAuthSdkBindings(clients, account_id=binding["account_id"],
            operator_user_arn=binding["operator_user_arn"],
            until_epoch=binding["authorized_until_epoch"], wall_clock=wall_clock,
            monotonic=monotonic, max_calls=96)
        if not verify_current_context(owner_context, owner_sdk):
            raise OwnerInvitationError("current_state_unverified")
        stage = "bootstrap_readback"
        start_mono = monotonic()
        _verify_current_bootstrap(clients, mapit_authority, mapit_state, mapit_plan, receipt_sha,
            [0], start_mono, start_mono + 50, monotonic)
        verifier = runtime_verifier_factory(
            evidence_path=Path(runtime_evidence_path), synthetic_binding_path=Path(synthetic_binding_path),
            synthetic_authorization_path=Path(synthetic_authorization_path),
            synthetic_state_dir=Path(synthetic_state_dir), acl_checker=acl_checker)
        stage = "runtime_readback"
        proof = verifier(clients, mapit_authority, mapit_plan.template, phase="readback")
        if not _valid_runtime_evidence(proof, mapit_authority, "readback"):
            raise OwnerInvitationError("current_state_unverified")
        identity = clients["sts"].get_caller_identity()
        if (not _sdk_ok(identity) or identity.get("Account") != binding["account_id"]
                or identity.get("Arn") != binding["operator_user_arn"]):
            raise OwnerInvitationError("current_state_unverified")
        table_arn = f"arn:aws:dynamodb:eu-west-1:{binding['account_id']}:table/{_AUTH_TABLE}"
        stage = "row_preflight"
        store = DynamoDBTenantStore(clients["dynamodb"], table_arn=table_arn,
            allowed_keys=(binding["owner_tenant_key"],), writer=clients["dynamodb"])
        if store.get(binding["owner_tenant_key"]) is not None:
            raise OwnerInvitationError("invitation_conflict")
        with journal.locked():
            if journal.load() is not None:
                raise OwnerInvitationError("journal_consumed")
            # Source/protections are refreshed after all preflight reads and
            # before a new durable intent can authorize a write.
            try:
                source_validator(source_auth)
            except Exception:
                raise OwnerInvitationError("source_ci_failed") from None
            try:
                fresh_protections = protection_reader(expected_owner_id=binding["github_owner_id"],
                    expected_repository_id=binding["github_repository_id"])
            except Exception:
                raise OwnerInvitationError("github_protection_failed") from None
            if fresh_protections != (binding["github_owner_id"], binding["github_repository_id"]):
                raise OwnerInvitationError("github_protection_failed")
            identity = clients["sts"].get_caller_identity()
            now = wall_clock()
            if (not _sdk_ok(identity) or identity.get("Account") != binding["account_id"]
                    or identity.get("Arn") != binding["operator_user_arn"]
                    or type(now) not in (int, float) or isinstance(now, bool)
                    or not math.isfinite(now)
                    or not binding["authorized_from_epoch"] <= now < binding["authorized_until_epoch"]):
                raise OwnerInvitationError("current_state_unverified")
            intent = {
                "schema": 1, "kind": KIND, "phase": "intent_saved",
                "authority_sha256": _digest(binding),
                "owner_context_sha256": binding["owner_context_sha256"],
                "bootstrap_authority_sha256": binding["mapit_bootstrap_authority_sha256"],
                "bootstrap_receipt_sha256": binding["mapit_bootstrap_receipt_sha256"],
                "runtime_evidence_sha256": binding["runtime_evidence_sha256"],
                "source_sha": binding["source_sha"], "run_id": binding["run_id"],
                "authorized_from_epoch": binding["authorized_from_epoch"],
                "authorized_until_epoch": binding["authorized_until_epoch"],
                "owner_key": binding["owner_tenant_key"], "table_arn": table_arn,
                "write_dispatched": False,
            }
            stage = "intent"
            journal.save(intent)
            guard.armed = True
            stage = "closed_controls"
            # Recheck the safety-critical closed controls and strong absence
            # after durable intent; full owner/bootstrap/runtime inventories
            # were just verified in the same bounded SDK phase above.
            stage = "closed_api_recheck"
            api = clients["apigatewayv2"].get_api(ApiId=owner_context.policy.api_id)
            if (not _sdk_ok(api) or api.get("ApiId") != owner_context.policy.api_id
                    or api.get("DisableExecuteApiEndpoint") is not True):
                raise OwnerInvitationError("current_state_unverified")
            stage = "closed_lambda_recheck"
            reserve = clients["lambda"].get_function_concurrency(
                FunctionName="honda-mapit-mcp-dev-retained-handler")
            if (not _sdk_ok(reserve)
                    or type(reserve.get("ReservedConcurrentExecutions")) is not int
                    or reserve["ReservedConcurrentExecutions"] != 0):
                raise OwnerInvitationError("current_state_unverified")
            stage = "absence_recheck"
            if store.get(binding["owner_tenant_key"]) is not None:
                raise OwnerInvitationError("invitation_conflict")
            stage = "identity_recheck"
            identity = clients["sts"].get_caller_identity()
            now = wall_clock()
            if (not _sdk_ok(identity) or identity.get("Account") != binding["account_id"]
                    or identity.get("Arn") != binding["operator_user_arn"]
                    or type(now) not in (int, float) or isinstance(now, bool)
                    or not math.isfinite(now)
                    or not binding["authorized_from_epoch"] <= now < binding["authorized_until_epoch"]):
                raise OwnerInvitationError("current_state_unverified")
            try:
                stage = "cas"
                acknowledged = store.cas(binding["owner_tenant_key"], None,
                    DurableTenantRecord(binding["owner_tenant_key"], "active", 1))
            except Exception:
                intent["phase"] = "write_outcome_unknown"
                intent["write_dispatched"] = guard.write_dispatch_started
                journal.save(intent)
                raise OwnerInvitationError("write_outcome_unknown") from None
            intent["write_dispatched"] = True
            if acknowledged is not True:
                intent["phase"] = "invitation_conflict"
                journal.save(intent)
                raise OwnerInvitationError("invitation_conflict")
            intent["phase"] = "write_acknowledged"
            journal.save(intent)
            if store.get(binding["owner_tenant_key"]) != DurableTenantRecord(
                    binding["owner_tenant_key"], "active", 1):
                intent["phase"] = "readback_unverified"
                journal.save(intent)
                raise OwnerInvitationError("write_outcome_unknown")
            intent["phase"] = "invitation_accepted"
            intent["readback_verified"] = True
            journal.save(intent)
        return {"ok": True, "category": "owner_invitation_accepted", "calls": guard.calls}
    except OwnerInvitationError as exc:
        return {"ok": False, "category": exc.category, "stage": stage, "calls": getattr(guard, "calls", 0)}
    except Exception:
        return {"ok": False, "category": "invitation_unverified", "stage": stage, "calls": getattr(guard, "calls", 0)}


__all__ = ["OwnerInvitationError", "prepare_private_authorization", "run_authorized_invitation"]
