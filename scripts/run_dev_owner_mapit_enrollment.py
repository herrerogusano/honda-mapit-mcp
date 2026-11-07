"""Fresh one-shot owner MAPIT enrollment while the DEV API remains closed.

This operator never replays the accepted delivery or its authority. It needs a
new private authority and current integrated source evidence. The MCP bearer
is authenticated and discarded inside the OAuth consumer; only its sealed
grant survives. Human consent uses a private native dialog. The saved MAPIT
refresh session is read only from native Credential Manager, never command
arguments, environment variables, chat or DOM.
No endpoint opening or business query is implemented here.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time
from urllib.request import Request

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from mapit.aws_binding_keys import load_binding_keys
from mapit.aws_dev_runtime import parse_cognito_jwks
from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.aws_enrollment_clients import create_enrollment_clients
from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.aws_identity_binding_publisher import AwsIdentityBindingPublisher
from mapit.config import MapitConfig
from mapit.durable_tenants import DurableTenantGuard
from mapit.http_transport import open_direct, read_bounded
from mapit.mapit_identity import MapitIdentityVerifier
from mapit.tenant_router import InvitedTenantAuthority
from mapit.session import WindowsKeyringRefreshTokenStore
from scripts.dev_owner_assisted_login import DevOwnerAssistedLogin
from scripts.dev_owner_enrolled_accepted_inputs import load_accepted_owner_delivery
from scripts.dev_owner_mapit_private_baseline import AcceptedPrivateBaseline
from scripts.dev_owner_enrolled_delivery_sdk import build_explicit_delivery_clients, _is_registered_client_bundle
from scripts.dev_owner_enrolled_login_lineage import validate_owner_enrolled_login_lineage
from scripts.dev_owner_enrolled_observation import validate_observation_window
from scripts.dev_owner_enrolled_private_inputs import _snapshot, _read_snapshot_now, _canonical
from scripts.dev_owner_enrolled_runtime_readback import make_owner_enrolled_accepted_observer
from scripts.run_dev_owner_assisted_login import fetch_owner_public_jwks
from scripts.run_dev_owner_enrolled_delivery import (
    _PRIVATE_INPUT_FIELDS, _source_and_protection_checks, _source_check_result, _protection_check_result,
    _require_disjoint_root,
)
from scripts.run_aws_dev_owner_oauth_bootstrap import validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import validate_source_and_ci

_AUTHORITY_FIELDS = frozenset({"schema", "kind", "operation_id", "account_id", "operator_arn",
    "source_sha", "ci_run_id", "github_owner_id", "github_repository_id", "authorized_from_epoch",
    "authorized_until_epoch", "runtime_evidence_sha256", "owner_tenant_key", "max_sdk_calls", "state_directory"})
_LOCK = threading.Lock()
_ATTEMPTED_ROOTS: set[str] = set()


class OwnerMapitEnrollmentError(ValueError):
    def __init__(self):
        super().__init__("owner_mapit_enrollment_unverified")


class OwnerMapitSessionMissingError(ValueError):
    def __init__(self):
        super().__init__("owner_mapit_session_missing")


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def _epoch(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise OwnerMapitEnrollmentError()
    return float(value)


def validate_enrollment_authority(value, *, evidence, source_sha, ci_run_id, now, authority_root):
    """Exact new operation contract; expired historical receipts grant no writes."""
    try:
        historical = evidence.authority
        if (type(value) is not dict or set(value) != _AUTHORITY_FIELDS
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["kind"] != "owner-mapit-enrollment-dev"
            or type(value["operation_id"]) is not str or re.fullmatch(r"[0-9a-f]{32}", value["operation_id"]) is None
            or type(value["state_directory"]) is not str
            or not Path(value["state_directory"]).is_absolute()
            or str(Path(value["state_directory"]).resolve()).casefold() != value["state_directory"].casefold()
            or value["state_directory"].casefold() != str(Path(authority_root).resolve()).casefold()
            or value["account_id"] != historical["account_id"]
            or value["operator_arn"] != historical["operator_arn"]
            or value["github_owner_id"] != historical["github_owner_id"]
            or type(value["github_owner_id"]) is not int
            or value["github_repository_id"] != historical["github_repository_id"]
            or type(value["github_repository_id"]) is not int
            or type(value["source_sha"]) is not str or re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]) is None
            or value["source_sha"] != source_sha or type(value["ci_run_id"]) is not int
            or value["ci_run_id"] <= 0 or value["ci_run_id"] != ci_run_id
            or value["runtime_evidence_sha256"] != evidence.update_state["receipt"]["runtime_evidence_sha256"]
            or value["owner_tenant_key"] != historical["owner_tenant_key"]
            or type(value["authorized_from_epoch"]) is not int or type(value["authorized_until_epoch"]) is not int
            or not 0 < value["authorized_until_epoch"] - value["authorized_from_epoch"] <= 1200
            or not value["authorized_from_epoch"] <= _epoch(now) < value["authorized_until_epoch"]
            or type(value["max_sdk_calls"]) is not int or not 1 <= value["max_sdk_calls"] <= 192):
            raise ValueError
        return dict(value)
    except Exception:
        raise OwnerMapitEnrollmentError() from None


class _Operation:
    """Immutable private admission plus aggregate one-attempt dispatch fences."""
    def __init__(self, *, root, evidence, source_sha, ci_run_id, acl_checker, clock, monotonic,
                 private_baseline=None):
        self.evidence, self.clock, self.monotonic = evidence, clock, monotonic
        self.acl_checker = acl_checker
        path, raw, self.fingerprint = _snapshot(Path(root) / "authorization.json", maximum=8192, acl_checker=acl_checker)
        if private_baseline is not None and (type(private_baseline) is not AcceptedPrivateBaseline
            or private_baseline.evidence is not evidence or private_baseline.is_registered_native() is not True):
            raise OwnerMapitEnrollmentError()
        self.private_baseline = private_baseline
        if private_baseline is not None:
            private_baseline.add(path, maximum=8192, expected_fingerprint=self.fingerprint)
        self.root = path.parent
        authority_sample = _epoch(clock())
        self.authority = validate_enrollment_authority(_json(raw), evidence=evidence,
            source_sha=source_sha, ci_run_id=ci_run_id, now=authority_sample, authority_root=path.parent)
        self._projection = _canonical(self.authority)
        self._last_wall = authority_sample
        self._last_mono = _epoch(monotonic())
        self._mono_until = self._last_mono + self.authority["authorized_until_epoch"] - self._last_wall
        self.calls = 0
        self.ddb_writes = 0
        self.ssm_writes = 0
        self.auth_calls = 0
        self._gate_wall = None
        self._gate_mono = None
        self._intent = False
        self._failed_dispatch = False
        self._write_lock = threading.Lock()
        self._dispatch_lock = threading.Lock()
        self._durable_fingerprints = []
        key = str(self.root).casefold()
        with _LOCK:
            if key in _ATTEMPTED_ROOTS:
                raise OwnerMapitEnrollmentError()
            _ATTEMPTED_ROOTS.add(key)
        self.check()
        self._persist("attempt.json", {"schema": 1, "kind": "owner-mapit-enrollment-attempt",
            "operation_id": self.authority["operation_id"], "authority_sha256": hashlib.sha256(raw).hexdigest()})

    def __repr__(self):
        return "OwnerMapitEnrollmentOperation(<redacted>)"

    def check(self, *, fresh_gates=False, deadline=None):
        wall, mono = _epoch(self.clock()), _epoch(self.monotonic())
        if (wall < self._last_wall or mono < self._last_mono
            or not self.authority["authorized_from_epoch"] <= wall < self.authority["authorized_until_epoch"]
            or mono >= self._mono_until
            or deadline is not None and mono >= deadline
            or _canonical(self.authority) != self._projection
            or (self.private_baseline.check() is not True if self.private_baseline is not None else
                (_read_snapshot_now(self.fingerprint, maximum=8192, acl_checker=self.acl_checker) != self.fingerprint
                 or any(_read_snapshot_now(fp, maximum=8192, acl_checker=self.acl_checker) != fp
                     for fp in self._durable_fingerprints)
                 or self.evidence.assert_unchanged() is not True))
            or fresh_gates and (self._gate_wall is None or self._gate_mono is None
                or not 0 <= wall - self._gate_wall < 30 or not 0 <= mono - self._gate_mono < 30)):
            raise OwnerMapitEnrollmentError()
        # Native file/ACL hashing is bounded but consumes real time. Samples
        # from before it cannot authorize a dispatch after an exclusive cutoff.
        after_wall, after_mono = _epoch(self.clock()), _epoch(self.monotonic())
        if (after_wall < wall or after_mono < mono
            or not self.authority["authorized_from_epoch"] <= after_wall < self.authority["authorized_until_epoch"]
            or after_mono >= self._mono_until
            or deadline is not None and after_mono >= deadline
            or fresh_gates and (not 0 <= after_wall - self._gate_wall < 30
                or not 0 <= after_mono - self._gate_mono < 30)):
            raise OwnerMapitEnrollmentError()
        self._last_wall, self._last_mono = after_wall, after_mono
        return after_wall, after_mono

    def gates_verified(self):
        self._gate_wall, self._gate_mono = self.check()

    def _persist(self, filename, value):
        # Create-only, flushed and fsynced; partial files remain terminal fences.
        raw = _canonical(value)
        with (self.root / filename).open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _, stored, fingerprint = _snapshot(self.root / filename, maximum=8192, acl_checker=self.acl_checker)
        if stored != raw:
            raise OwnerMapitEnrollmentError()
        self._durable_fingerprints.append(fingerprint)
        if self.private_baseline is not None:
            self.private_baseline.add(self.root / filename, maximum=8192, expected_fingerprint=fingerprint)
        self.check()

    def intent(self):
        with self._write_lock:
            if self._intent:
                raise OwnerMapitEnrollmentError()
            self.check(fresh_gates=True)
            self._persist("intent.json", {"schema": 1, "kind": "owner-mapit-enrollment-intent",
                "operation_id": self.authority["operation_id"], "ddb_cas_limit": 3, "ssm_create_limit": 1})
            self._intent = True

    def dispatch(self, client, method, request, *, deadline, write=None):
        # Reentrant/concurrent calls fail closed. Counts are spent before SDK dispatch.
        if not self._dispatch_lock.acquire(blocking=False):
            raise OwnerMapitEnrollmentError()
        try:
            self.check(fresh_gates=write is not None, deadline=deadline)
            if self._failed_dispatch or self.calls >= self.authority["max_sdk_calls"]:
                raise OwnerMapitEnrollmentError()
            if write == "ddb":
                if not self._intent or self.ddb_writes >= 3:
                    raise OwnerMapitEnrollmentError()
                self.ddb_writes += 1
            elif write == "ssm":
                if not self._intent or self.ssm_writes >= 1:
                    raise OwnerMapitEnrollmentError()
                self.ssm_writes += 1
            self.calls += 1
            result = getattr(client, method)(**request)
            self.check(deadline=deadline)
            return result
        except Exception:
            self._failed_dispatch = True
            raise
        finally:
            self._dispatch_lock.release()


class _BoundClient:
    """Only fixed identity, exact strong table reads and create-only publication."""
    def __init__(self, raw, operation, *, deadline, table=None, row_key=None, ssm_path=None,
                 identity_only=False, writable=False):
        self.meta = raw.meta
        self._raw, self._op, self._deadline = raw, operation, deadline
        self._table, self._row = table, row_key
        self._ssm_path, self._identity_only, self._writable = ssm_path, identity_only, writable

    def __repr__(self):
        return "OwnerMapitEnrollmentClient(<redacted>)"

    def get_caller_identity(self, **request):
        if not self._identity_only or request:
            raise OwnerMapitEnrollmentError()
        return self._op.dispatch(self._raw, "get_caller_identity", request, deadline=self._deadline)

    def get_item(self, **request):
        if request != {"TableName": self._table, "Key": {"key": {"S": self._row}},
            "ConsistentRead": True, "ReturnConsumedCapacity": "NONE"}:
            raise OwnerMapitEnrollmentError()
        return self._op.dispatch(self._raw, "get_item", request, deadline=self._deadline)

    def put_item(self, **request):
        step = self._op.ddb_writes
        expected_condition = "attribute_not_exists(#pk)" if step == 0 else "#revision = :revision"
        expected_names = {"#pk": "key"} if step == 0 else {"#revision": "revision"}
        item = request.get("Item", {})
        if (not self._writable or self._row != "identity-bindings-v1" or request.get("TableName") != self._table
            or item.get("key") != {"S": self._row} or step not in {0, 1, 2}
            or item.get("revision") != {"N": str(step + 1)}
            or request.get("ConditionExpression") != expected_condition
            or request.get("ExpressionAttributeNames") != expected_names
            or ("ExpressionAttributeValues" in request if step == 0 else
                request.get("ExpressionAttributeValues") != {":revision": {"N": str(step)}})
            or request.get("ReturnValues") != "NONE" or request.get("ReturnConsumedCapacity") != "NONE"):
            raise OwnerMapitEnrollmentError()
        document = _json(item.get("payload", {}).get("S", ""))
        owner = self._op.authority["owner_tenant_key"]
        rows = document.get("records") if type(document) is dict else None
        if (set(document) != {"schema", "records"} or type(document["schema"]) is not int or document["schema"] != 1
            or type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
            or rows[0].get("tenant_key") != owner or rows[0].get("environment") != "dev"
            or type(rows[0].get("revision")) is not int or rows[0]["revision"] != step + 1
            or rows[0].get("status") != ("active" if step == 2 else "pending")
            or rows[0].get("secret_path") != "/honda-mapit-mcp/dev/tenants/" + owner + "/mapit-refresh-token"
            or type(rows[0].get("secret_version")) is not int or rows[0]["secret_version"] != 1):
            raise OwnerMapitEnrollmentError()
        return self._op.dispatch(self._raw, "put_item", request, deadline=self._deadline, write="ddb")

    def get_parameter(self, **request):
        if request != {"Name": self._ssm_path + ":1", "WithDecryption": True}:
            raise OwnerMapitEnrollmentError()
        return self._op.dispatch(self._raw, "get_parameter", request, deadline=self._deadline)

    def put_parameter(self, **request):
        if (not self._writable or request.get("Name") != self._ssm_path
            or set(request) != {"Name", "Value", "Type", "Tier", "KeyId", "DataType", "Overwrite"}
            or request["Type"] != "SecureString" or request["Tier"] != "Standard"
            or request["KeyId"] != "alias/aws/ssm" or request["DataType"] != "text"
            or request["Overwrite"] is not False):
            raise OwnerMapitEnrollmentError()
        return self._op.dispatch(self._raw, "put_parameter", request, deadline=self._deadline, write="ssm")


@dataclass(frozen=True, repr=False)
class _PrivateSubmission:
    refresh_token: str = field(repr=False)
    consent: bool

    def __repr__(self):
        return "PrivateMapitSubmission(<redacted>)"


def _collect_saved_session(*, consent_request, deadline, monotonic,
                          store_factory=WindowsKeyringRefreshTokenStore):
    last = _epoch(monotonic())
    def check():
        nonlocal last
        now = _epoch(monotonic())
        if now < last or now >= deadline:
            raise OwnerMapitEnrollmentError()
        last = now
    check()
    if consent_request() is not True:
        raise OwnerMapitEnrollmentError()
    check()
    store = store_factory()
    token = store.load_readonly()
    check()
    if (type(token) is not str or not token or len(token.encode("utf-8")) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in token)):
        raise OwnerMapitSessionMissingError()
    return _PrivateSubmission(token, True)


def collect_private_mapit_session(*, deadline, monotonic=time.monotonic):
    """Human consent followed by an immutable read of the existing saved session."""
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    last = _epoch(monotonic())
    def live():
        nonlocal last
        now = _epoch(monotonic())
        if now < last or now >= deadline:
            root.destroy()
            raise OwnerMapitEnrollmentError()
        last = now
    def watch():
        try:
            live()
            root.after(100, watch)
        except Exception:
            pass
    root.after(100, watch)
    try:
        live()
        return _collect_saved_session(consent_request=lambda: messagebox.askyesno("Honda MAPIT MCP - DEV",
            "¿Autorizas leer tu sesión MAPIT guardada en el Gestor de credenciales de Windows "
            "y vincularla, cifrada, en DEV? La sesión local se conserva. "
            "La API permanece cerrada. No se consultarán tus recorridos en este paso.", parent=root),
            deadline=deadline, monotonic=monotonic)
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def _assume_enroller(bundle, operation, *, deadline, grant_expires_at):
    authority = operation.authority
    response = operation.dispatch(bundle.clients["sts"], "get_caller_identity", {}, deadline=deadline)
    if (response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
        or type(response.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
        or response.get("Account") != authority["account_id"] or response.get("Arn") != authority["operator_arn"]):
        raise OwnerMapitEnrollmentError()
    role = "arn:aws:iam::" + authority["account_id"] + ":role/honda-mapit-mcp-dev-mapit-enroller"
    session = "owner-mapit-" + authority["operation_id"]
    response = operation.dispatch(bundle.clients["sts"], "assume_role", {
        "RoleArn": role, "RoleSessionName": session, "DurationSeconds": 900}, deadline=deadline)
    credentials = response.get("Credentials", {})
    user = response.get("AssumedRoleUser", {})
    if (response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
        or type(response.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
        or user.get("Arn") != "arn:aws:sts::" + authority["account_id"] + ":assumed-role/honda-mapit-mcp-dev-mapit-enroller/" + session
        or any(type(credentials.get(name)) is not str or not credentials[name]
            for name in ("AccessKeyId", "SecretAccessKey", "SessionToken"))
        or not isinstance(credentials.get("Expiration"), datetime)
        or credentials["Expiration"].tzinfo is None
        or type(grant_expires_at) is not int
        or credentials["Expiration"].timestamp() <= min(authority["authorized_until_epoch"], grant_expires_at)):
        raise OwnerMapitEnrollmentError()
    return {"access_key": credentials["AccessKeyId"], "secret_key": credentials["SecretAccessKey"],
        "session_token": credentials["SessionToken"]}, role


def _role_pair(credentials, role, operation, deadline, *, include_dynamodb=False):
    # Each pair owns independent one-use identity verification. Loading the
    # configuration never consumes the subsequent publication verifier.
    pair = create_enrollment_clients(**credentials, deadline=deadline, direct_only=True,
        expected_role_arn=role, include_dynamodb=include_dynamodb, monotonic=operation.monotonic)
    return pair


def _bounded_mapit_transport(operation, deadline, config):
    allowed = {"https://cognito-idp." + config.region + ".amazonaws.com/",
        "https://cognito-identity." + config.region + ".amazonaws.com/"}
    allowed_targets = {"AWSCognitoIdentityProviderService.InitiateAuth", "AWSCognitoIdentityService.GetId",
        "AWSCognitoIdentityService.GetCredentialsForIdentity"}
    used = set()
    def transport(url, headers, payload):
        operation.check(deadline=deadline)
        target = headers.get("X-Amz-Target")
        if url not in allowed or target not in allowed_targets or target in used:
            raise OwnerMapitEnrollmentError()
        used.add(target)
        request = Request(url, data=_canonical(payload), headers=dict(headers), method="POST")
        _, now = operation.check(fresh_gates=True, deadline=deadline)
        remaining = deadline - now
        if remaining <= 0 or operation.auth_calls >= 3:
            raise OwnerMapitEnrollmentError()
        operation.auth_calls += 1
        with open_direct(request, timeout=min(2, remaining)) as response:
            if response.status != 200:
                raise OwnerMapitEnrollmentError()
            raw = read_bounded(response, 256 * 1024,
                on_chunk=lambda _: operation.check(deadline=deadline))
        operation.check(deadline=deadline)
        parsed = _json(raw)
        if type(parsed) is not dict:
            raise OwnerMapitEnrollmentError()
        return parsed
    return transport


def _count_post_read(operation):
    operation.check()
    if operation._failed_dispatch or operation.calls >= operation.authority["max_sdk_calls"]:
        raise OwnerMapitEnrollmentError()
    operation.calls += 1


def _preflight_login(evidence, bundle, private_paths, operation, source_validator,
                     protection_reader, acl_checker, jwks_fetcher, channel_factory, ready_callback):
    historical = evidence.authority
    authority = operation.authority
    def gates():
        operation.check()
        _source_and_protection_checks(authority["source_sha"], authority["ci_run_id"],
            source_validator=source_validator, protection_reader=protection_reader,
            owner_id=authority["github_owner_id"], repository_id=authority["github_repository_id"])
        operation.gates_verified()
    gates()
    now = operation.clock()
    start = math.floor(now) - 1
    until = min(start + 600, authority["authorized_until_epoch"])
    window = {"schema": 1, "kind": "owner-enrolled-readonly-observation",
        "account_id": historical["account_id"], "operator_arn": historical["operator_arn"],
        "source_sha": authority["source_sha"], "ci_run_id": authority["ci_run_id"],
        "authorized_from_epoch": start, "authorized_until_epoch": until,
        "github_owner_id": historical["github_owner_id"], "github_repository_id": historical["github_repository_id"]}
    context = evidence.private_inputs.manifest_inputs["context"]
    observer = make_owner_enrolled_accepted_observer(client_bundle=bundle, authority=historical,
        accepted=evidence.accepted, prior_template=evidence.private_inputs.prior_template,
        manifest_raw=evidence.manifest_raw, invitation_jwks=evidence.invitation_jwks,
        mapit_jwks=evidence.mapit_jwks, archive_bytes=evidence.archive_bytes,
        archive_size=len(evidence.archive_bytes), owner_oauth_context=context,
        **{name: Path(private_paths[name]) for name in ("mapit_bootstrap_authority_path", "mapit_bootstrap_state_dir",
            "mapit_publication_state_dir", "mapit_evidence_path", "synthetic_binding_path",
            "synthetic_authorization_path", "synthetic_state_dir")},
        accepted_observation_capsule=evidence.capsule, observation_window=window,
        accepted_update_state=evidence.update_state,
        accepted_runtime_evidence_sha256=evidence.update_state["receipt"]["runtime_evidence_sha256"],
        observation_source_check=lambda v: _source_check_result(v, source_validator),
        observation_protection_check=lambda v: _protection_check_result(v, protection_reader,
            historical["github_owner_id"], historical["github_repository_id"]),
        before_sdk_read=lambda: _count_post_read(operation),
        acl_checker=acl_checker, clock=operation.clock, monotonic=operation.monotonic)
    readback = observer("accepted", evidence.binding)
    if operation.calls >= authority["max_sdk_calls"]:
        raise OwnerMapitEnrollmentError()
    runtime, identity = observer.owner_login_projections(readback)
    lineage = validate_owner_enrolled_login_lineage(original_context=context, delivery_authority=historical,
        accepted_receipts=evidence.accepted, accepted_update_state=evidence.update_state,
        current_runtime_readback=runtime, owner_identity_readback=identity)
    keys = parse_cognito_jwks(jwks_fetcher(lineage.policy))
    if keys != parse_cognito_jwks(evidence.invitation_jwks):
        raise OwnerMapitEnrollmentError()
    invited = InvitedTenantAuthority({authority["owner_tenant_key"]: lineage.policy}, keys, environment="dev")
    # Original authorization table is always read with the base operator client,
    # never the namespace-only enroller role. It has no writer capability.
    table = "arn:aws:dynamodb:eu-west-1:" + authority["account_id"] + ":table/honda-mapit-mcp-dev-tenants"
    base_reader = _BoundClient(bundle.clients["dynamodb"], operation, deadline=operation._mono_until,
        table=table, row_key=authority["owner_tenant_key"])
    store = DynamoDBTenantStore(base_reader, table_arn=table, allowed_keys=(authority["owner_tenant_key"],))
    guard = DurableTenantGuard(invited, store)
    seen = []
    def consume(token):
        if seen:
            raise OwnerMapitEnrollmentError()
        operation.check()
        gates()
        validate_observation_window(window, account_id=historical["account_id"],
            operator_arn=historical["operator_arn"], github_owner_id=historical["github_owner_id"],
            github_repository_id=historical["github_repository_id"], now=operation.clock())
        grant = asyncio.run(invited.authenticate(token))
        snapshot = guard.capture(grant)
        operation.check()
        seen.append((grant, snapshot))
        # The token is neither returned nor stored; only the sealed grant lives.
    gates()
    operation.check()
    channel = channel_factory(lineage.policy, keys, consume, consumer_seconds=90,
        absolute_until_epoch=until, wall_clock=operation.clock, monotonic=operation.monotonic)
    if channel.serve(ready_callback=ready_callback) != "verified" or len(seen) != 1:
        raise OwnerMapitEnrollmentError()
    return invited, guard, seen[0], gates


def run_owner_mapit_enrollment(*, authority_root, delivery_root, private_paths, source_sha, ci_run_id,
        acl_checker=None, source_validator=validate_source_and_ci,
        protection_reader=validate_github_protections, jwks_fetcher=fetch_owner_public_jwks,
        channel_factory=DevOwnerAssistedLogin, private_collector=collect_private_mapit_session,
        ready_callback=None, clock=time.time, monotonic=time.monotonic):
    """Owning live composition. Injection seams collect synthetic test data only.

    No replacement accepted loader, observer, bundle or mutation coordinator is
    accepted by this entrypoint. The post-verifier has its separate owning path.
    """
    operation = None
    phase = "source"
    try:
        # Source first; historical authorities are parsed, not executed.
        _source_and_protection_checks(source_sha, ci_run_id,
            source_validator=source_validator, protection_reader=protection_reader)
        phase = "private_inputs"
        evidence = load_accepted_owner_delivery(delivery_root=delivery_root,
            private_paths=private_paths, acl_checker=acl_checker)
        _require_disjoint_root(authority_root, [delivery_root, *private_paths.values()])
        operation = _Operation(root=authority_root, evidence=evidence, source_sha=source_sha,
            ci_run_id=ci_run_id, acl_checker=acl_checker, clock=clock, monotonic=monotonic,
            private_baseline=AcceptedPrivateBaseline(evidence))
        bundle = build_explicit_delivery_clients()
        if not _is_registered_client_bundle(bundle):
            raise OwnerMapitEnrollmentError()
        phase = "login"
        invited, guard, (grant, snapshot), gates = _preflight_login(evidence, bundle, private_paths,
            operation, source_validator, protection_reader, acl_checker, jwks_fetcher, channel_factory, ready_callback)
        gates()
        phase = "keys"
        _, now = operation.check()
        key_deadline = min(now + 14, operation._mono_until, now + grant.expires_at - clock())
        credentials, role = _assume_enroller(bundle, operation, deadline=key_deadline,
            grant_expires_at=grant.expires_at)
        config = MapitConfig(**evidence.private_inputs.manifest_inputs["public_config"])
        key_pair = _role_pair(credentials, role, operation, key_deadline)
        # Account verifiers retain their raw client identity; their direct STS
        # calls are counted explicitly before invoking the one-use verifier.
        def verified(raw, verifier):
            def verify(client, account):
                operation.check(deadline=key_deadline)
                if operation.calls >= operation.authority["max_sdk_calls"] or client is not raw:
                    return False
                operation.calls += 1
                ok = verifier(raw, account)
                operation.check(deadline=key_deadline)
                return ok
            return verify
        key_reader = _BoundClient(key_pair.ssm, operation, deadline=key_deadline,
            ssm_path="/honda-mapit-mcp/dev/mapit-identity-binding-config")
        key_verify = verified(key_pair.ssm, key_pair.account_verifier)
        material = load_binding_keys(key_reader, account_id=operation.authority["account_id"], config=config,
            account_verifier=lambda client, account: client is key_reader and key_verify(key_pair.ssm, account),
            deadline=key_deadline, monotonic=monotonic, namespace="mapit", environment="dev")
        verifier = MapitIdentityVerifier(config, parse_cognito_jwks(evidence.mapit_jwks),
            material.identity_proof_hmac_key, clock=lambda: datetime.fromtimestamp(clock(), timezone.utc))
        operation.check()
        local_deadline = min(operation._mono_until, monotonic() + grant.expires_at - clock())
        phase = "consent"
        submission = private_collector(deadline=local_deadline, monotonic=monotonic)
        if type(submission) is not _PrivateSubmission or submission.consent is not True:
            raise OwnerMapitEnrollmentError()
        invited.validate(grant)
        guard.check(grant, snapshot)
        gates()
        operation.intent()
        _, now = operation.check(fresh_gates=True)
        deadline = min(now + 14, local_deadline)
        phase = "enrollment"
        clients = _role_pair(credentials, role, operation, deadline, include_dynamodb=True)
        account = operation.authority["account_id"]
        table = "arn:aws:dynamodb:eu-west-1:" + account + ":table/honda-mapit-mcp-dev-mapit-identity-bindings"
        ddb = _BoundClient(clients.dynamodb, operation, deadline=deadline, table=table,
            row_key="identity-bindings-v1", writable=True)
        path = "/honda-mapit-mcp/dev/tenants/" + grant.key + "/mapit-refresh-token"
        ssm = _BoundClient(clients.ssm, operation, deadline=deadline, ssm_path=path, writable=True)
        def account_verify(wrapper, raw, verify):
            def check(client, expected):
                operation.check(fresh_gates=True, deadline=deadline)
                if client is not wrapper or operation.calls >= operation.authority["max_sdk_calls"]:
                    return False
                operation.calls += 1
                result = verify(raw, expected)
                operation.check(fresh_gates=True, deadline=deadline)
                return result
            return check
        transport = _bounded_mapit_transport(operation, deadline, config)
        registry = DynamoDBIdentityBindingRegistry(ddb, ddb, table_arn=table, account_id=account,
            authority=invited, durable_guard=guard, environment="dev", namespace="mapit",
            config=config, verifier=verifier, binding_key=material.binding_mac_key,
            auth_transport=transport, clock=lambda: datetime.fromtimestamp(clock(), timezone.utc),
            deadline=deadline, monotonic=monotonic,
            account_verifier=account_verify(ddb, clients.dynamodb, clients.dynamodb_account_verifier))
        publisher = AwsIdentityBindingPublisher(ssm, authority=invited, grant=grant,
            durable_guard=guard, snapshot=snapshot, environment="dev", account_id=account,
            account_verifier=account_verify(ssm, clients.ssm, clients.account_verifier),
            deadline=deadline, monotonic=monotonic)
        binding = registry.enroll(grant, snapshot, submission.refresh_token, publisher=publisher)
        del submission
        if operation.ddb_writes != 3 or operation.ssm_writes != 1:
            raise OwnerMapitEnrollmentError()
        # The accepted PRE observer cannot accept a nonempty binding namespace.
        # A new POST verifier gets fresh read-only registry clocks, never a
        # refreshed writable coordinator or a replayed authority.
        gates()
        phase = "readback"
        from scripts.dev_owner_mapit_enrollment_readback import verify_owner_mapit_enrollment
        def readonly_registry_factory(*, deadline):
            read = _BoundClient(bundle.clients["dynamodb"], operation, deadline=deadline,
                table=table, row_key="identity-bindings-v1")
            return DynamoDBIdentityBindingRegistry(read, None, table_arn=table, account_id=account,
                authority=invited, durable_guard=guard, environment="dev", namespace="mapit",
                config=config, verifier=verifier, binding_key=material.binding_mac_key,
                auth_transport=lambda *args: (_ for _ in ()).throw(OwnerMapitEnrollmentError()),
                clock=lambda: datetime.fromtimestamp(clock(), timezone.utc), deadline=deadline, monotonic=monotonic)
        receipt = verify_owner_mapit_enrollment(operation_id=operation.authority["operation_id"], grant=grant,
            snapshot=snapshot, binding=binding, registry=registry, authority=operation.authority,
            client_bundle=bundle, delivery_evidence=evidence, readonly_registry_factory=readonly_registry_factory,
            deadline=min(operation._mono_until, monotonic() + 120, local_deadline), monotonic=monotonic,
            before_sdk_call=lambda: _count_post_read(operation), clock=clock,
            private_baseline=operation.private_baseline)
        expected = {"schema": 1, "kind": "owner-mapit-enrollment-closed-readback",
            "operation_id": operation.authority["operation_id"], "owner_key": grant.key,
            "secret_version": 1, "binding_revision": 3, "closed": True, "reservation": 0}
        if (type(receipt) is not dict or receipt != expected
            or any(type(receipt[name]) is not int for name in ("schema", "secret_version", "binding_revision", "reservation"))
            or type(receipt["closed"]) is not bool):
            raise OwnerMapitEnrollmentError()
        operation.check()
        operation._persist("result.json", receipt)
        return {"ok": True, "category": "owner_mapit_enrollment_verified", "calls": operation.calls,
            "ddb_writes": 3, "ssm_writes": 1, "auth_calls": operation.auth_calls, "phase": "readback"}
    except Exception as exc:
        return {"ok": False, "category": "owner_mapit_session_missing" if type(exc) is OwnerMapitSessionMissingError
                else "owner_mapit_enrollment_unverified",
            "calls": operation.calls if operation is not None else 0,
            "ddb_writes": operation.ddb_writes if operation is not None else 0,
            "ssm_writes": operation.ssm_writes if operation is not None else 0,
            "auth_calls": operation.auth_calls if operation is not None else 0, "phase": phase}


def main(argv=None):
    parser = argparse.ArgumentParser(description="One fresh private owner MAPIT enrollment; DEV stays closed.")
    parser.add_argument("--authority-root", type=Path, required=True)
    parser.add_argument("--delivery-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", type=int, required=True)
    for name in sorted(_PRIVATE_INPUT_FIELDS):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args(argv)
    def ready(_url):
        print('{"category":"owner_login_ready","url":"http://127.0.0.1:8787/"}', flush=True)
    result = run_owner_mapit_enrollment(authority_root=args.authority_root, delivery_root=args.delivery_root,
        private_paths={name: getattr(args, name) for name in _PRIVATE_INPUT_FIELDS},
        source_sha=args.source_sha, ci_run_id=args.ci_run_id, ready_callback=ready)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
