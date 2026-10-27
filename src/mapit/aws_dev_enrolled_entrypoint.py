"""Opt-in DEV enrolled MAPIT handler; unavailable outside a pinned test window.

Private manifests contain public configuration/verification keys only. Runtime
credentials are supplied explicitly from Lambda's environment, never a default
SDK chain. This module neither invites users nor publishes/updates secrets.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
import math
import os
from pathlib import Path
import re
import threading
import time

from .aws_binding_keys import load_binding_keys
from .aws_enrollment_clients import create_enrollment_clients
from .aws_dev_multiuser_entrypoint import _WindowContext, _unavailable
from .cloud_transport import CloudDirectTransport
from .dev_enrolled_manifest import (MANIFEST_FILENAME, INVITATION_JWKS_FILENAME, MAPIT_JWKS_FILENAME,
    MAX_MANIFEST_BYTES, MAX_JWKS_BYTES, parse_enrolled_dev_manifest)
from .dev_enrolled_runtime import DevEnrolledReadResources, compose_enrolled_dev_runtime

_LOCK = threading.Lock()
_BINDING = None
_LAST_WALL = None


def _read(name, ceiling):
    with Path(__file__).with_name(name).open("rb") as stream:
        value = stream.read(ceiling + 1)
    if len(value) > ceiling:
        raise ValueError("artifact_invalid")
    return value


def _clients(deadline):
    names = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    values = tuple(os.environ.get(name) for name in names)
    if any(type(value) is not str or not value for value in values):
        raise ValueError("runtime_unavailable")
    return create_enrollment_clients(access_key=values[0], secret_key=values[1], session_token=values[2],
        deadline=deadline, include_dynamodb=True)


def _require_budget(deadline, seconds):
    sampled = time.monotonic()
    if (type(sampled) not in (int, float) or not math.isfinite(sampled)
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or deadline - sampled <= seconds):
        raise ValueError("runtime_unavailable")


class _AuthorizationReader:
    def __init__(self, account, deadline):
        self._account = account
        self._deadline = deadline
        self._client = None

    def get_item(self, **request):
        # The invited router invokes this only after signed-token verification.
        # This reader belongs to one invocation, not a warm global cache. Reuse
        # its bounded wire client rather than constructing three SDK clients for
        # every reauthorization read; the router retains the original deadline.
        if self._client is None:
            # Each bounded SDK call permits two seconds for connect and read.
            # Both STS and GetItem must fit before the invocation's reserve.
            _require_budget(self._deadline, 8)
            clients = _clients(self._deadline)
            _require_budget(self._deadline, 8)
            verifier = clients.dynamodb_account_verifier
            if not callable(verifier) or verifier(clients.dynamodb, self._account) is not True:
                raise ValueError("runtime_unavailable")
            self._client = clients.dynamodb
        _require_budget(self._deadline, 4)
        result = self._client.get_item(**request)
        _require_budget(self._deadline, 0)
        return result


class _BoundedReadClient:
    def __init__(self, client, deadline):
        self._client, self._deadline = client, deadline
        self.meta = client.meta

    def _read(self, method, request):
        _require_budget(self._deadline, 4)
        result = getattr(self._client, method)(**request)
        _require_budget(self._deadline, 0)
        return result

    def get_parameter(self, **request):
        return self._read("get_parameter", request)

    def get_item(self, **request):
        return self._read("get_item", request)


def _resources_loader(manifest, account):
    def load(*, deadline):
        clients = _clients(deadline)
        _require_budget(deadline, 4)
        verifier = clients.dynamodb_account_verifier
        if not callable(verifier) or verifier(clients.dynamodb, account) is not True:
            raise ValueError("runtime_unavailable")
        # Latest version must still be the accepted create-only version. The
        # independently validated decrypt loader subsequently selects exactly :1.
        _require_budget(deadline, 4)
        latest = clients.ssm.get_parameter(Name=manifest.key_parameter_path, WithDecryption=False)
        parameter = latest.get("Parameter", {})
        modified = parameter.get("LastModifiedDate")
        if (type(latest.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or latest["ResponseMetadata"]["HTTPStatusCode"] != 200
                or parameter.get("Name") != manifest.key_parameter_path
                or parameter.get("ARN") != f"arn:aws:ssm:eu-west-1:{account}:parameter{manifest.key_parameter_path}"
                or parameter.get("Type") != "SecureString" or parameter.get("DataType") != "text"
                or type(parameter.get("Version")) is not int or parameter["Version"] != 1
                or not isinstance(modified, datetime) or modified.tzinfo is None
                or not manifest.key_publication_start_epoch <= modified.timestamp() < manifest.key_publication_end_epoch
                or any(key in latest for key in ("NextToken", "NextMarker", "Marker"))):
            raise ValueError("runtime_unavailable")
        # The key loader verifies STS then decrypts once using the exact pair.
        _require_budget(deadline, 8)
        material = load_binding_keys(clients.ssm, account_id=account, config=manifest.config,
            namespace="mapit", account_verifier=clients.account_verifier, deadline=deadline)
        _require_budget(deadline, 0)
        return DevEnrolledReadResources(_BoundedReadClient(clients.dynamodb, deadline),
            _BoundedReadClient(clients.ssm, deadline), material)
    return load


def _handler(event, context):
    global _BINDING, _LAST_WALL
    if (os.environ.get("MAPIT_MCP_ENV") != "dev" or os.environ.get("AWS_REGION") != "eu-west-1"
            or os.environ.get("MAPIT_DEV_ENROLLED_MODE") != "mapit-enrolled"):
        return _unavailable()
    names = ("MAPIT_DEV_ENROLLED_MANIFEST_SHA256", "MAPIT_DEV_EXPECTED_ACCOUNT_ID",
        "MAPIT_DEV_EXECUTION_START_EPOCH", "MAPIT_DEV_EXECUTION_END_EPOCH", "MAPIT_SOURCE_SHA256",
        "MAPIT_COGNITO_JWKS_SHA256", "MAPIT_IDENTITY_JWKS_SHA256", "MAPIT_OBSERVED_API_ID",
        "MAPIT_COGNITO_USER_POOL_ID", "MAPIT_COGNITO_CLIENT_ID")
    binding = tuple(os.environ.get(name) for name in names)
    if any(type(value) is not str for value in binding):
        return _unavailable()
    digest, account, start_text, end_text, source, invite_hash, mapit_hash, api, pool, client = binding
    if any(re.fullmatch(r"[1-9][0-9]{0,11}", value) is None for value in (start_text, end_text)):
        return _unavailable()
    start, end, now = int(start_text), int(end_text), time.time()
    if (not 0 < end - start <= 300 or type(now) not in (int, float) or not math.isfinite(now)
            or not start <= now < end or (_LAST_WALL is not None and now < _LAST_WALL)
            or (_BINDING is not None and binding != _BINDING)):
        return _unavailable()
    _LAST_WALL = now
    bounded = _WindowContext(context, start, end, now)
    invocation_deadline = time.monotonic() + min(14, bounded.get_remaining_time_in_millis() / 1000 - 1)
    raw = _read(MANIFEST_FILENAME, MAX_MANIFEST_BYTES)
    invitation = _read(INVITATION_JWKS_FILENAME, MAX_JWKS_BYTES)
    mapit = _read(MAPIT_JWKS_FILENAME, MAX_JWKS_BYTES)
    manifest = parse_enrolled_dev_manifest(raw, invitation, mapit, expected_digest=digest, account_id=account)
    policy = next(iter(manifest.policies.values()))
    if (manifest.source_sha != source or hashlib.sha256(invitation).hexdigest() != invite_hash
            or hashlib.sha256(mapit).hexdigest() != mapit_hash
            or policy.api_id != api or policy.user_pool_id != pool or policy.client_id != client):
        return _unavailable()
    def transports(*, deadline):
        transport = CloudDirectTransport(manifest.config, deadline=deadline)
        return transport.cognito_json, transport.mapit_request
    runtime = compose_enrolled_dev_runtime(raw, invitation, mapit, manifest_digest=digest,
        account_id=account, authorization_reader=_AuthorizationReader(account, invocation_deadline),
        resources_loader=_resources_loader(manifest, account), transports_factory=transports)
    _BINDING = binding
    result = runtime.handler(event, bounded)
    final = time.time()
    if (type(final) not in (int, float) or not math.isfinite(final) or final < now
            or final >= end or bounded.get_remaining_time_in_millis() <= 0):
        return _unavailable()
    _LAST_WALL = final
    return result


def handler(event, context):
    if not _LOCK.acquire(blocking=False):
        return _unavailable()
    try:
        try:
            return _handler(event, context)
        except Exception:
            return _unavailable()
    finally:
        _LOCK.release()


__all__ = ["handler"]
