"""Explicit DEV key handoff; secret values never belong in deployment artifacts."""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import hashlib
import math
import re
import secrets
import time
from typing import Any, Callable

from .config import MapitConfig
from .mapit_identity import json_bytes

PARAMETER_PATH = "/honda-mapit-mcp/dev/identity-binding-config"


class BindingKeysError(ValueError):
    def __init__(self):
        super().__init__("binding_keys_unverified")


@dataclass(frozen=True, repr=False)
class BindingKeyMaterial:
    binding_mac_key: bytes = field(repr=False)
    identity_proof_hmac_key: bytes = field(repr=False)

    def __repr__(self):
        return "BindingKeyMaterial(<redacted>)"


def _context(account_id: str) -> tuple[str, str]:
    if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
            or account_id == "000000000000"):
        raise BindingKeysError()
    return (f"arn:aws:dynamodb:eu-west-1:{account_id}:table/honda-mapit-mcp-dev-identity-bindings",
            f"arn:aws:ssm:eu-west-1:{account_id}:parameter{PARAMETER_PATH}")


def _encode(key: bytes) -> str:
    if type(key) is not bytes or len(key) != 32:
        raise BindingKeysError()
    return base64.urlsafe_b64encode(key).rstrip(b"=").decode("ascii")


def _config_digest(config: MapitConfig) -> str:
    if type(config) is not MapitConfig or config.email is not None or config.password is not None:
        raise BindingKeysError()
    fields = ("region", "user_pool_id", "user_pool_client_id", "identity_pool_id", "core_api_url",
              "geo_api_url", "frontend_url", "discovery_enabled", "http_timeout")
    try:
        values = {k: getattr(config, k) for k in fields}
        json.dumps(values, allow_nan=False)
        raw = json_bytes(values)
        if len(raw) > 2048:
            raise ValueError
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        raise BindingKeysError() from None


def encode_binding_keys(material: BindingKeyMaterial, *, account_id: str, config: MapitConfig) -> str:
    """Return a sensitive in-memory value for one create-only SecureString PUT."""
    table, _ = _context(account_id)
    if type(material) is not BindingKeyMaterial or material.binding_mac_key == material.identity_proof_hmac_key:
        raise BindingKeysError()
    return json.dumps({"schema": 1, "environment": "dev", "account_id": account_id,
        "table_arn": table, "parameter_path": PARAMETER_PATH,
        "mapit_config_sha256": _config_digest(config),
        "binding_mac_key": _encode(material.binding_mac_key),
        "identity_proof_hmac_key": _encode(material.identity_proof_hmac_key)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def generate_binding_keys() -> BindingKeyMaterial:
    return BindingKeyMaterial(secrets.token_bytes(32), secrets.token_bytes(32))


def decode_binding_keys(value: str, *, account_id: str, config: MapitConfig) -> BindingKeyMaterial:
    try:
        _context(account_id)
        if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= 2048:
            raise ValueError
        def unique(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError
                result[key] = item
            return result
        document = json.loads(value, object_pairs_hook=unique)
        if type(document) is not dict or type(document.get("schema")) is not int:
            raise ValueError
        def key(name):
            encoded = document[name]
            if type(encoded) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded) is None:
                raise ValueError
            result = base64.urlsafe_b64decode(encoded + "=")
            if _encode(result) != encoded:
                raise ValueError
            return result
        material = BindingKeyMaterial(key("binding_mac_key"), key("identity_proof_hmac_key"))
        if encode_binding_keys(material, account_id=account_id, config=config) != value:
            raise ValueError
        return material
    except Exception:
        raise BindingKeysError() from None


def load_binding_keys(client: Any, *, account_id: str, config: MapitConfig,
                      account_verifier: Callable[[Any, str], bool], deadline: float,
                      monotonic: Callable[[], float] = time.monotonic) -> BindingKeyMaterial:
    """One pinned decrypted read using explicit client/account authority, no retry."""
    try:
        _, arn = _context(account_id)
        last = monotonic()
        if (type(last) not in (int, float) or not math.isfinite(last)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 < deadline - last <= 14):
            raise ValueError
        def fresh():
            nonlocal last
            now = monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or now < last or now >= deadline:
                raise ValueError
            last = now
        meta = client.meta
        client_config = meta.config
        if (meta.service_model.service_name != "ssm" or meta.region_name != "eu-west-1"
                or meta.endpoint_url != "https://ssm.eu-west-1.amazonaws.com"
                or type(client_config.retries.get("total_max_attempts")) is not int
                or client_config.retries["total_max_attempts"] != 1
                or any(type(t) not in (int, float) or not math.isfinite(t) or not 0 < t <= 3
                       for t in (client_config.connect_timeout, client_config.read_timeout))):
            raise ValueError
        fresh()
        if account_verifier(client, account_id) is not True:
            raise ValueError
        fresh()
        response = client.get_parameter(Name=PARAMETER_PATH + ":1", WithDecryption=True)
        fresh()
        if (type(response) is not dict or type(response.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or response["ResponseMetadata"]["HTTPStatusCode"] != 200
                or any(k in response for k in ("NextToken", "NextMarker", "Marker"))):
            raise ValueError
        parameter = response["Parameter"]
        if (parameter.get("ARN") != arn or parameter.get("Name") != PARAMETER_PATH
                or parameter.get("Type") != "SecureString" or type(parameter.get("Version")) is not int
                or parameter["Version"] != 1 or parameter.get("Selector") != ":1"
                or parameter.get("DataType") != "text" or "SourceResult" in parameter):
            raise ValueError
        result = decode_binding_keys(parameter["Value"], account_id=account_id, config=config)
        fresh()
        return result
    except Exception:
        raise BindingKeysError() from None
