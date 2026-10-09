"""Explicit-SDK write adapters for the owner-enrolled DEV delivery core.

This module owns only frozen client construction and the one-shot S3/CFN write
adapters. It does not perform the coordinator's full live readback, prepare
private authority, run source/protection checks, or make delivery live-ready.
The coordinator must persist its separate artifact/update intents before
calling these methods. Any ambiguous result is sticky for this adapter object;
there is no write retry or idempotent replay path.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import re
import threading
import time
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, Callable
from urllib.parse import urlsplit
from weakref import WeakKeyDictionary

from scripts.dev_owner_enrolled_delivery import _validate_authority
from scripts.dev_owner_enrolled_login_lineage import (
    CredentialSnapshot,
    credential_snapshot_from_explicit_credentials,
)

REGION = "eu-west-1"
_CLIENT_ENDPOINTS = {
    "sts": ("sts", REGION, f"https://sts.{REGION}.amazonaws.com"),
    "cloudformation": ("cloudformation", REGION, f"https://cloudformation.{REGION}.amazonaws.com"),
    "s3": ("s3", REGION, f"https://s3.{REGION}.amazonaws.com"),
    "iam": ("iam", "us-east-1", "https://iam.amazonaws.com"),
    "dynamodb": ("dynamodb", REGION, f"https://dynamodb.{REGION}.amazonaws.com"),
    "ssm": ("ssm", REGION, f"https://ssm.{REGION}.amazonaws.com"),
    "cognito": ("cognito-idp", REGION, f"https://cognito-idp.{REGION}.amazonaws.com"),
    "apigatewayv2": ("apigatewayv2", REGION, f"https://apigateway.{REGION}.amazonaws.com"),
    "lambda": ("lambda", REGION, f"https://lambda.{REGION}.amazonaws.com"),
    "kms": ("kms", REGION, f"https://kms.{REGION}.amazonaws.com"),
}
_REQUIRED_CLIENTS = frozenset(_CLIENT_ENDPOINTS)
_HANDLER_NAME = "honda-mapit-mcp-dev-retained-handler"
_MAX_CALLS = 48
_MAX_STEP_SECONDS = 30.0
_MAX_BODY_BYTES = 50 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_UUID32 = re.compile(r"[0-9a-f]{32}\Z")
_CREDENTIAL_ENV_MARKERS = (
    "access_key", "secret_key", "session_token", "security_token", "profile",
    "credential", "config", "web_identity", "role_arn", "role_session",
    "container_credential", "endpoint", "ca_bundle",
)
_CLIENT_BUNDLE_REGISTRY = WeakKeyDictionary()
_CLIENT_BUNDLE_REGISTRY_LOCK = threading.Lock()


class OwnerEnrolledDeliverySdkError(ValueError):
    """Safe fixed category; provider responses and credentials are never echoed."""

    _CATEGORIES = frozenset({
        "client_setup_failed", "binding_invalid", "window_closed", "call_budget_exhausted",
        "identity_unverified", "closed_state_unverified", "artifact_write_unknown",
        "artifact_readback_unverified", "update_write_unknown",
    })

    def __init__(self, category: str):
        safe = category if type(category) is str and category in self._CATEGORIES else "client_setup_failed"
        self.category = safe
        super().__init__(safe)


def _fail(category: str) -> None:
    raise OwnerEnrolledDeliverySdkError(category)


def _status(response: Any) -> bool:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except Exception:
        _fail("binding_invalid")


def _reject_ambient_credential_configuration(environ: Mapping[str, str]) -> None:
    try:
        if any((name.casefold() == "boto_config"
                or (name.casefold().startswith("aws_") and any(
                    marker in name.casefold() for marker in _CREDENTIAL_ENV_MARKERS)))
               for name in environ):
            _fail("client_setup_failed")
    except OwnerEnrolledDeliverySdkError:
        raise
    except Exception:
        _fail("client_setup_failed")


def _validate_clients(clients: Any) -> Mapping[str, Any]:
    if not isinstance(clients, Mapping) or set(clients) != _REQUIRED_CLIENTS:
        _fail("client_setup_failed")
    for name, (service, region, endpoint) in _CLIENT_ENDPOINTS.items():
        client = clients[name]
        try:
            meta = client.meta
            config = meta.config
            retries = config.retries
            verify = client._endpoint.http_session._verify
            if (meta.service_model.service_name != service or meta.region_name != region
                    or meta.endpoint_url != endpoint or verify is not True
                    or config.signature_version != "v4" or config.proxies != {}
                    or type(config.connect_timeout) not in (int, float) or isinstance(config.connect_timeout, bool)
                    or not math.isfinite(config.connect_timeout) or not 0 < config.connect_timeout <= 2
                    or type(config.read_timeout) not in (int, float) or isinstance(config.read_timeout, bool)
                    or not math.isfinite(config.read_timeout) or not 0 < config.read_timeout <= 3
                    or type(retries) is not dict or type(retries.get("total_max_attempts")) is not int
                    or retries.get("total_max_attempts") != 1
                    or retries.get("mode") != "standard"):
                _fail("client_setup_failed")
        except OwnerEnrolledDeliverySdkError:
            raise
        except Exception:
            _fail("client_setup_failed")
    return clients


def build_explicit_delivery_clients(*, session_factory: Callable[..., Any] | None = None,
                                    environ: Mapping[str, str] | None = None):
    """Create pinned TLS clients from one frozen credential tuple.

    ``session_factory``/``environ`` are test seams. Default credentials are
    resolved once, frozen, and passed explicitly to every client; no client
    may fall back to a separate ambient provider chain. The returned opaque
    bundle keeps the client identities and credential snapshot inseparable.
    """
    _reject_ambient_credential_configuration(os.environ if environ is None else environ)
    logger = logging.getLogger("botocore.credentials")
    previous = logger.level
    logger.setLevel(logging.CRITICAL)
    try:
        import boto3
        from botocore.config import Config
        factory = boto3.Session if session_factory is None else session_factory
        session = factory(region_name=REGION)
        provider = session.get_credentials()
        if provider is None:
            _fail("client_setup_failed")
        frozen = provider.get_frozen_credentials()
        access_key = getattr(frozen, "access_key", None)
        secret_key = getattr(frozen, "secret_key", None)
        token = getattr(frozen, "token", None)
        if (type(access_key) is not str or not access_key
                or type(secret_key) is not str or not secret_key
                or token is not None and type(token) is not str):
            _fail("client_setup_failed")
        common = Config(connect_timeout=2, read_timeout=3,
            retries={"mode": "standard", "total_max_attempts": 1}, proxies={}, signature_version="v4")
        clients = {}
        for name, (service, region, endpoint) in _CLIENT_ENDPOINTS.items():
            clients[name] = session.client(service, region_name=region, endpoint_url=endpoint,
                config=common, verify=True, aws_access_key_id=access_key,
                aws_secret_access_key=secret_key, aws_session_token=token)
        clients = _validate_clients(clients)
        snapshot = credential_snapshot_from_explicit_credentials(frozen)
        bundle = DeliveryClientBundle(clients, snapshot)
        _register_client_bundle(bundle)
        return bundle
    except OwnerEnrolledDeliverySdkError:
        raise
    except Exception:
        _fail("client_setup_failed")
    finally:
        logger.setLevel(previous)


class DeliveryClientBundle:
    """Opaque immutable association between one explicit client set and its credentials."""

    __slots__ = ("_clients", "_credential_snapshot", "__weakref__")

    def __init__(self, clients: Any, credential_snapshot: Any):
        validated = _validate_clients(clients)
        if type(credential_snapshot) is not CredentialSnapshot:
            raise TypeError("credential snapshot is invalid")
        object.__setattr__(self, "_clients", MappingProxyType(dict(validated)))
        object.__setattr__(self, "_credential_snapshot", credential_snapshot)

    def __setattr__(self, _name: str, _value: Any) -> None:
        raise AttributeError("delivery client bundle is immutable")

    @property
    def clients(self):
        return self._clients

    @property
    def credential_snapshot(self):
        return self._credential_snapshot

    def __repr__(self) -> str:
        return "DeliveryClientBundle(<redacted>)"


def _bundle_identity(bundle: DeliveryClientBundle):
    return (tuple((name, bundle.clients[name]) for name in sorted(_REQUIRED_CLIENTS)),
            bundle.credential_snapshot)


def _register_client_bundle(bundle: DeliveryClientBundle) -> None:
    """Register only bundles assembled directly by the explicit SDK factory."""
    if type(bundle) is not DeliveryClientBundle:
        _fail("client_setup_failed")
    with _CLIENT_BUNDLE_REGISTRY_LOCK:
        _CLIENT_BUNDLE_REGISTRY[bundle] = _bundle_identity(bundle)


def _is_registered_client_bundle(bundle: Any) -> bool:
    if type(bundle) is not DeliveryClientBundle:
        return False
    try:
        current = _bundle_identity(bundle)
        with _CLIENT_BUNDLE_REGISTRY_LOCK:
            registered = _CLIENT_BUNDLE_REGISTRY.get(bundle)
        if registered is None:
            return False
        registered_clients, registered_snapshot = registered
        current_clients, current_snapshot = current
        return (current_snapshot is registered_snapshot
                and len(current_clients) == len(registered_clients)
                and all(name == registered_name and client is registered_client
                        for (name, client), (registered_name, registered_client)
                        in zip(current_clients, registered_clients)))
    except Exception:
        return False


class OwnerEnrolledDeliverySdk:
    """Single-session S3 publisher and closed CFN updater.

    `authority` must be the exact already-validated delivery authority. The
    coordinator still owns durable intent and target construction. This class
    independently fences one artifact PutObject and one UpdateStack, performs
    fresh STS and API/Lambda-closed checks immediately before and after each
    write, and never retries an ambiguous result.
    """

    def __init__(self, *, client_bundle: DeliveryClientBundle,
                 authority: dict[str, Any], target_template_sha256: str,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        try:
            if not _is_registered_client_bundle(client_bundle):
                raise ValueError
            self.clients = client_bundle.clients
            _validate_clients(self.clients)
            self.client_bundle = client_bundle
            self.credential_snapshot = client_bundle.credential_snapshot
            self.authority = MappingProxyType(_validate_authority(authority))
            if type(target_template_sha256) is not str or _SHA256.fullmatch(target_template_sha256) is None:
                raise ValueError
            self.target_template_sha256 = target_template_sha256
            if not callable(clock) or not callable(monotonic):
                raise ValueError
            self.clock, self.monotonic = clock, monotonic
            now_wall, now_mono = self._read_clocks()
            if not self.authority["authorized_from_epoch"] <= now_wall < self.authority["authorized_until_epoch"]:
                raise ValueError
            self._started_mono = self._last_mono = now_mono
            self._last_wall = now_wall
            self._invalidated = False
            self.calls = 0
            self._publish_attempted = False
            self._update_attempted = False
            self._write_lock = threading.Lock()
        except OwnerEnrolledDeliverySdkError:
            raise
        except Exception:
            _fail("binding_invalid")

    def __repr__(self) -> str:
        return "OwnerEnrolledDeliverySdk(<redacted>)"

    def _read_clocks(self) -> tuple[float, float]:
        try:
            wall, mono = self.clock(), self.monotonic()
            if (type(wall) not in (int, float) or isinstance(wall, bool)
                    or type(mono) not in (int, float) or isinstance(mono, bool)
                    or not math.isfinite(wall) or not math.isfinite(mono)):
                raise ValueError
            return float(wall), float(mono)
        except Exception:
            _fail("window_closed")

    def _guard(self) -> None:
        if self._invalidated:
            _fail("window_closed")
        try:
            wall, mono = self._read_clocks()
            if (wall < self._last_wall or mono < self._last_mono
                    or not self.authority["authorized_from_epoch"] <= wall < self.authority["authorized_until_epoch"]
                    or mono - self._started_mono >= _MAX_STEP_SECONDS):
                self._invalidated = True
                _fail("window_closed")
        except OwnerEnrolledDeliverySdkError:
            self._invalidated = True
            raise
        self._last_wall, self._last_mono = wall, mono

    def _call(self, service: str, method: str, **kwargs):
        self._guard()
        if self.calls >= _MAX_CALLS:
            _fail("call_budget_exhausted")
        self.calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            if method == "update_stack":
                _fail("update_write_unknown")
            if method == "put_object":
                _fail("artifact_write_unknown")
            if method == "head_object":
                _fail("artifact_readback_unverified")
            if method == "get_caller_identity":
                _fail("identity_unverified")
            _fail("closed_state_unverified")
        self._guard()
        if not _status(result):
            if method == "update_stack":
                _fail("update_write_unknown")
            if method == "put_object":
                _fail("artifact_write_unknown")
            if method == "head_object":
                _fail("artifact_readback_unverified")
            if method == "get_caller_identity":
                _fail("identity_unverified")
            _fail("closed_state_unverified")
        return result

    def _verify_identity(self) -> None:
        response = self._call("sts", "get_caller_identity")
        if (response.get("Account") != self.authority["account_id"]
                or response.get("Arn") != self.authority["operator_arn"]):
            _fail("identity_unverified")

    def _api_id(self) -> str:
        try:
            parsed = urlsplit(self.authority["owner_resource_uri"])
            prefix = f".execute-api.{REGION}.amazonaws.com"
            if (parsed.scheme != "https" or parsed.path != "/mcp" or parsed.query or parsed.fragment
                    or not parsed.netloc.endswith(prefix)):
                raise ValueError
            api_id = parsed.netloc[:-len(prefix)]
            if re.fullmatch(r"[a-z0-9]{10}", api_id) is None:
                raise ValueError
            return api_id
        except Exception:
            _fail("binding_invalid")

    def _verify_closed(self) -> None:
        api_id = self._api_id()
        api = self._call("apigatewayv2", "get_api", ApiId=api_id)
        reserved = self._call("lambda", "get_function_concurrency", FunctionName=_HANDLER_NAME)
        if (api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
                or type(reserved.get("ReservedConcurrentExecutions")) is not int
                or reserved["ReservedConcurrentExecutions"] != 0):
            _fail("closed_state_unverified")

    def _before_write(self) -> None:
        self._guard()
        self._verify_identity()
        self._verify_closed()
        self._guard()

    def _after_write(self) -> None:
        self._guard()
        self._verify_identity()
        self._verify_closed()
        self._guard()

    def _claim_write(self, which: str) -> None:
        with self._write_lock:
            field = "_publish_attempted" if which == "publish" else "_update_attempted"
            if getattr(self, field):
                _fail("artifact_write_unknown" if which == "publish" else "update_write_unknown")
            setattr(self, field, True)

    def publish_once(self, binding: dict[str, Any], archive: bytes) -> dict[str, Any]:
        """Perform one conditional S3 write and exact HEAD verification."""
        try:
            if (type(binding) is not dict or binding.get("authority") != self.authority
                    or type(archive) is not bytes or not 0 < len(archive) <= _MAX_BODY_BYTES):
                _fail("binding_invalid")
            digest = hashlib.sha256(archive).hexdigest()
            if _SHA256.fullmatch(digest) is None:
                _fail("binding_invalid")
            bucket = self.authority["artifact_bucket"]
            key = f"runtime/{digest}.zip"
            checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
            self._before_write()
            self._claim_write("publish")
            put = self._call("s3", "put_object", Bucket=bucket, Key=key, Body=archive,
                IfNoneMatch="*", ExpectedBucketOwner=self.authority["account_id"],
                ServerSideEncryption="AES256", ChecksumSHA256=checksum, ContentType="application/zip")
            if not _status(put):
                _fail("artifact_write_unknown")
            head = self._call("s3", "head_object", Bucket=bucket, Key=key,
                ChecksumMode="ENABLED", ExpectedBucketOwner=self.authority["account_id"])
            if (type(head.get("ContentLength")) is not int or head["ContentLength"] != len(archive)
                    or head.get("ChecksumSHA256") != checksum
                    or head.get("ServerSideEncryption") != "AES256"
                    or head.get("ContentType") != "application/zip"):
                _fail("artifact_readback_unverified")
            self._after_write()
            return {
                "status": "verified", "bucket": bucket, "key": key, "sha256": digest,
                "size_bytes": len(archive), "expected_bucket_owner": self.authority["account_id"],
                "server_side_encryption": "AES256", "if_none_match": "*",
                "put_http_status": 200, "head_http_status": 200,
                "head_checksum_sha256": checksum, "head_content_length": len(archive),
                "head_server_side_encryption": "AES256",
            }
        except OwnerEnrolledDeliverySdkError:
            raise
        except Exception:
            _fail("artifact_write_unknown")

    def update_once(self, stack_id: str, target: dict[str, Any], token: str, role_arn: str) -> dict[str, Any]:
        """Perform exactly one UpdateStack for the pinned accepted target."""
        try:
            authority = self.authority
            if (stack_id != authority["stack_id"]
                    or token != f"owner-enrolled-{authority['run_id']}"
                    or role_arn != authority["service_role_arn"]
                    or type(target) is not dict):
                _fail("binding_invalid")
            target_body = _canonical(target)
            target_sha = hashlib.sha256(target_body).hexdigest()
            # The delivery callback binding is supplied by the coordinator and
            # must pin this exact target before this method can be invoked.
            if target_sha != self.target_template_sha256:
                _fail("binding_invalid")
            self._before_write()
            self._claim_write("update")
            reply = self._call("cloudformation", "update_stack", StackName=stack_id,
                TemplateBody=target_body.decode("ascii"), RoleARN=role_arn,
                Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=token)
            if reply.get("StackId") != stack_id:
                _fail("update_write_unknown")
            self._after_write()
            return {"status": "acknowledged", "http_status": 200, "stack_id": stack_id,
                    "client_request_token": token, "target_template_sha256": target_sha}
        except OwnerEnrolledDeliverySdkError:
            raise
        except Exception:
            _fail("update_write_unknown")


__all__ = [
    "DeliveryClientBundle", "OwnerEnrolledDeliverySdk", "OwnerEnrolledDeliverySdkError",
    "build_explicit_delivery_clients",
]
