"""Explicit synthetic multi-user DEV entrypoint, closed outside a fixed window.

Only authorization metadata is read from DynamoDB, lazily after authentication.
No MAPIT session, SSM, password, local credential store or business network
provider exists in this runtime. Its private bundle pins exactly two users.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import time
import threading
from typing import Any

from .aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from .aws_durable_tenants import DynamoDBTenantStore
from .invited_lambda import create_invited_dev_lambda_runtime
from .remote_http import SyntheticServicesProvider
from .services import DistanceResult, Position, RouteDetail, RouteList, RouteSummary, VehicleStatus

MANIFEST_FILENAME = "dev-multiuser.manifest.json"
JWKS_FILENAME = "dev-multiuser.jwks.json"
MAX_MANIFEST_BYTES = 12 * 1024
MAX_JWKS_BYTES = 32 * 1024
REGION = "eu-west-1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_CACHED = None
_BINDING = None
_LAST_WALL = None
_INVOCATION_LOCK = threading.Lock()


def _unavailable():
    return {"statusCode": 503, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": '{"error":"service_unavailable"}', "isBase64Encoded": False}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("manifest_invalid")
        result[key] = value
    return result


def parse_manifest(raw: bytes, *, expected_digest: str, account_id: str) -> dict[str, Any]:
    """Validate only a private manifest; this function constructs no client."""
    try:
        if (type(raw) is not bytes or not 0 < len(raw) <= MAX_MANIFEST_BYTES
            or type(expected_digest) is not str or _DIGEST.fullmatch(expected_digest) is None
            or type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
            or account_id == "000000000000"
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_digest)):
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        fields = {"schema", "builder", "environment", "synthetic", "source_sha", "api_id",
                  "user_pool_id", "client_id", "jwks_sha256", "table_arn", "tenants"}
        if (type(value) is not dict or set(value) != fields
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["builder"] != "build_retained_dev_multiuser_archive"
            or value["environment"] != "dev" or value["synthetic"] is not True
            or type(value["source_sha"]) is not str or re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]) is None
            or value["source_sha"] == "0" * 40
            or type(value["jwks_sha256"]) is not str or _DIGEST.fullmatch(value["jwks_sha256"]) is None
            or value["table_arn"] != f"arn:aws:dynamodb:{REGION}:{account_id}:table/honda-mapit-mcp-dev-tenants"
            or type(value["tenants"]) is not list or len(value["tenants"]) != 2):
            raise ValueError
        policies = {}
        subjects, labels = set(), set()
        for tenant in value["tenants"]:
            if (type(tenant) is not dict or set(tenant) != {"key", "subject", "label"}
                or type(tenant["key"]) is not str or _KEY.fullmatch(tenant["key"]) is None
                or tenant["key"] in policies or type(tenant["label"]) is not str
                or tenant["label"] not in {"synthetic-A", "synthetic-B"}
                or tenant["label"] in labels or tenant["subject"] in subjects):
                raise ValueError
            policies[tenant["key"]] = CognitoDevPolicy(
                value["user_pool_id"], value["api_id"], value["client_id"], tenant["subject"],
                request_deadline_seconds=14.0,
            )
            subjects.add(tenant["subject"])
            labels.add(tenant["label"])
        return value
    except Exception:
        raise ValueError("manifest_invalid") from None


class _TenantServices(SyntheticServicesProvider):
    def __init__(self, label: str):
        super().__init__()
        self._label = label
        self._route = label + "-route"
        self._km = 11.0 if label == "synthetic-A" else 22.0

    def get_vehicle_status(self):
        self._record()
        return VehicleStatus(status=self._label, position=Position())

    def get_distance(self, from_time, to_time):
        self._record()
        return DistanceResult(from_time=from_time, to_time=to_time, distance=self._km * 1000,
                              distance_km=self._km, route_count=1)

    def list_routes(self, from_time, to_time):
        self._record()
        return RouteList(from_time=from_time, to_time=to_time,
                         routes=[RouteSummary(route_id=self._route, started_at=from_time,
                                              distance=self._km * 1000, distance_km=self._km)],
                         matched_routes=1, returned_routes=1, truncated=False)

    def get_route_detail(self, route_id):
        if route_id != self._route:
            raise ValueError("synthetic_route_unauthorized")
        self._record()
        return RouteDetail(route_id=self._route, geojson={"type": "FeatureCollection", "features": []})


def compose_runtime(manifest_raw: bytes, jwks_raw: bytes, *, manifest_digest: str,
                    account_id: str, dynamodb_reader: Any):
    """Injected composition, also exercised offline with synthetic wire shapes."""
    value = parse_manifest(manifest_raw, expected_digest=manifest_digest, account_id=account_id)
    if (type(jwks_raw) is not bytes or len(jwks_raw) > MAX_JWKS_BYTES
        or hashlib.sha256(jwks_raw).hexdigest() != value["jwks_sha256"]):
        raise ValueError("artifact_invalid")
    public_keys = parse_cognito_jwks(jwks_raw)
    policies = {tenant["key"]: CognitoDevPolicy(value["user_pool_id"], value["api_id"],
                value["client_id"], tenant["subject"], request_deadline_seconds=14.0)
                for tenant in value["tenants"]}
    labels = {tenant["key"]: tenant["label"] for tenant in value["tenants"]}
    store = DynamoDBTenantStore(dynamodb_reader, table_arn=value["table_arn"], allowed_keys=tuple(policies))
    return create_invited_dev_lambda_runtime(next(iter(policies.values())), policies, public_keys,
        authorization_store=store, provider_factory=lambda key, deadline: _TenantServices(labels[key]))


def _make_client():
    credentials = {name: os.environ.get(name) for name in
                   ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")}
    if any(type(value) is not str or not value for value in credentials.values()):
        raise ValueError("runtime_unavailable")
    import boto3
    from botocore.config import Config
    return boto3.client("dynamodb", region_name=REGION,
        endpoint_url=f"https://dynamodb.{REGION}.amazonaws.com", verify=True,
        aws_access_key_id=credentials["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=credentials["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=credentials["AWS_SESSION_TOKEN"],
        config=Config(retries={"mode": "standard", "total_max_attempts": 1},
                      connect_timeout=1, read_timeout=1, proxies={}))


class _LazyReader:
    def __init__(self):
        self._client = None

    def get_item(self, **request):
        if self._client is None:
            self._client = _make_client()
        return self._client.get_item(**request)


def _bounded_read(name: str, ceiling: int) -> bytes:
    with Path(__file__).with_name(name).open("rb") as stream:
        raw = stream.read(ceiling + 1)
    if len(raw) > ceiling:
        raise ValueError("artifact_invalid")
    return raw


class _WindowContext:
    def __init__(self, original, start, end, initial_wall):
        self.started = time.monotonic()
        if type(self.started) not in (int, float) or not math.isfinite(self.started):
            raise ValueError("budget_invalid")
        self.remaining = original.get_remaining_time_in_millis()
        self.last_mono = self.started
        self.last_wall = initial_wall
        self.start, self.end = start, end
        if type(self.remaining) is not int or self.remaining <= 1000:
            raise ValueError("budget_invalid")

    def get_remaining_time_in_millis(self):
        mono, wall = time.monotonic(), time.time()
        if (type(mono) not in (int, float) or type(wall) not in (int, float)
            or not math.isfinite(mono) or not math.isfinite(wall)
            or mono < self.last_mono or wall < self.last_wall
            or wall < self.start or wall >= self.end):
            self.remaining = 0
            return 0
        self.last_mono, self.last_wall = mono, wall
        # The adapter keeps its one-second reserve; do not extend wall cutoff.
        elapsed_ms = math.ceil((mono - self.started) * 1000)
        window_ms = math.floor((self.end - wall) * 1000)
        return max(0, min(self.remaining - elapsed_ms, window_ms))


def _handler(event: Any, context: Any):
    global _CACHED, _BINDING, _LAST_WALL
    try:
        env = os.environ
        if (env.get("MAPIT_MCP_ENV") != "dev" or env.get("MAPIT_DEV_MULTIUSER_MODE") != "synthetic"
            or env.get("AWS_REGION") != REGION):
            return _unavailable()
        binding = tuple(env.get(name) for name in ("MAPIT_DEV_MULTIUSER_MANIFEST_SHA256",
            "MAPIT_DEV_EXPECTED_ACCOUNT_ID", "MAPIT_DEV_EXECUTION_START_EPOCH", "MAPIT_DEV_EXECUTION_END_EPOCH",
            "MAPIT_SOURCE_SHA256", "MAPIT_COGNITO_JWKS_SHA256", "MAPIT_COGNITO_USER_POOL_ID",
            "MAPIT_COGNITO_CLIENT_ID", "MAPIT_OBSERVED_API_ID"))
        digest, account, start_text, end_text, source, jwks_digest, pool, client, api = binding
        if any(type(value) is not str for value in binding):
            return _unavailable()
        if any(re.fullmatch(r"[1-9][0-9]{0,11}", value) is None for value in (start_text, end_text)):
            return _unavailable()
        start, end = int(start_text), int(end_text)
        now = time.time()
        if (not 0 < end - start <= 300 or type(now) not in (int, float) or not math.isfinite(now)
            or now < start or now >= end or (_LAST_WALL is not None and now < _LAST_WALL)
            or (_CACHED is not None and _BINDING is None)
            or (_BINDING is not None and binding != _BINDING)):
            return _unavailable()
        _LAST_WALL = now
        bounded_context = _WindowContext(context, start, end, now)
        if _CACHED is None:
            raw = _bounded_read(MANIFEST_FILENAME, MAX_MANIFEST_BYTES)
            jwks = _bounded_read(JWKS_FILENAME, MAX_JWKS_BYTES)
            manifest = parse_manifest(raw, expected_digest=digest, account_id=account)
            if any(manifest[key] != expected for key, expected in (
                ("source_sha", source), ("jwks_sha256", jwks_digest), ("user_pool_id", pool),
                ("client_id", client), ("api_id", api))):
                return _unavailable()
            _CACHED = compose_runtime(raw, jwks, manifest_digest=digest, account_id=account,
                                      dynamodb_reader=_LazyReader())
            _BINDING = binding
        result = _CACHED.handler(event, bounded_context)
        final = time.time()
        if (type(final) not in (int, float) or not math.isfinite(final)
            or final < now or final >= end or bounded_context.get_remaining_time_in_millis() <= 0):
            return _unavailable()
        _LAST_WALL = final
        return result
    except Exception:
        return _unavailable()


def handler(event: Any, context: Any):
    # AWS invokes one request per execution environment. Reject accidental
    # concurrent embedding rather than racing cached bindings or wall receipts.
    if not _INVOCATION_LOCK.acquire(blocking=False):
        return _unavailable()
    try:
        return _handler(event, context)
    finally:
        _INVOCATION_LOCK.release()


__all__ = ["handler", "compose_runtime", "parse_manifest"]
