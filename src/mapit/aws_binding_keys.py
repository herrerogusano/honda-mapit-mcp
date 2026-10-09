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
MAPIT_PARAMETER_PATH = "/honda-mapit-mcp/dev/mapit-identity-binding-config"
_NAMESPACES = {"synthetic": ("honda-mapit-mcp-dev-identity-bindings", PARAMETER_PATH),
               "mapit": ("honda-mapit-mcp-dev-mapit-identity-bindings", MAPIT_PARAMETER_PATH)}


class BindingKeysError(ValueError):
    def __init__(self):
        super().__init__("binding_keys_unverified")


@dataclass(frozen=True, repr=False)
class BindingKeyMaterial:
    binding_mac_key: bytes = field(repr=False)
    identity_proof_hmac_key: bytes = field(repr=False)

    def __repr__(self):
        return "BindingKeyMaterial(<redacted>)"


def _context(account_id: str, namespace: str = "synthetic", environment: str = "dev") -> tuple[str, str, str]:
    if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
            or account_id == "000000000000" or type(namespace) is not str
            or namespace not in _NAMESPACES or type(environment) is not str or environment != "dev"):
        raise BindingKeysError()
    # This module's fixed table/path map is DEV-only; no production namespace
    # is represented here.
    table_name, parameter_path = _NAMESPACES[namespace]
    return (f"arn:aws:dynamodb:eu-west-1:{account_id}:table/{table_name}", parameter_path,
            f"arn:aws:ssm:eu-west-1:{account_id}:parameter{parameter_path}")


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


def encode_binding_keys(material: BindingKeyMaterial, *, account_id: str, config: MapitConfig,
                        namespace: str = "synthetic", environment: str = "dev") -> str:
    """Return a sensitive in-memory value for one create-only SecureString PUT."""
    if namespace == "mapit" and type(config) is not MapitConfig:
        raise BindingKeysError()
    table, path, _ = _context(account_id, namespace, environment)
    if type(material) is not BindingKeyMaterial or material.binding_mac_key == material.identity_proof_hmac_key:
        raise BindingKeysError()
    document = {"schema": 1 if namespace == "synthetic" else 2,
        "environment": "dev", "account_id": account_id, "table_arn": table,
        "parameter_path": path, "mapit_config_sha256": _config_digest(config),
        "binding_mac_key": _encode(material.binding_mac_key),
        "identity_proof_hmac_key": _encode(material.identity_proof_hmac_key)}
    if namespace != "synthetic":
        document["namespace"] = namespace
    return json.dumps(document,
        sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def generate_binding_keys() -> BindingKeyMaterial:
    return BindingKeyMaterial(secrets.token_bytes(32), secrets.token_bytes(32))


def decode_binding_keys(value: str, *, account_id: str, config: MapitConfig,
                        namespace: str = "synthetic", environment: str = "dev") -> BindingKeyMaterial:
    try:
        _, expected_path, _ = _context(account_id, namespace, environment)
        if namespace == "mapit" and type(config) is not MapitConfig:
            raise ValueError
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
        expected_fields = {"schema", "environment", "account_id", "table_arn", "parameter_path",
                           "mapit_config_sha256", "binding_mac_key", "identity_proof_hmac_key"}
        if namespace != "synthetic":
            expected_fields.add("namespace")
        if (type(document) is not dict or set(document) != expected_fields
                or type(document.get("schema")) is not int
                or document.get("schema") != (1 if namespace == "synthetic" else 2)
                or document.get("environment") != "dev"
                or document.get("account_id") != account_id
                or document.get("parameter_path") != expected_path
                or (namespace != "synthetic" and document.get("namespace") != namespace)):
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
        if encode_binding_keys(material, account_id=account_id, config=config,
                                namespace=namespace, environment=environment) != value:
            raise ValueError
        return material
    except Exception:
        raise BindingKeysError() from None


def load_binding_keys(client: Any, *, account_id: str, config: MapitConfig,
                      account_verifier: Callable[[Any, str], bool], deadline: float,
                      monotonic: Callable[[], float] = time.monotonic,
                      namespace: str = "synthetic", environment: str = "dev") -> BindingKeyMaterial:
    """One pinned decrypted read using explicit client/account authority, no retry."""
    try:
        _, parameter_path, arn = _context(account_id, namespace, environment)
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
        response = client.get_parameter(Name=parameter_path + ":1", WithDecryption=True)
        fresh()
        if (type(response) is not dict or type(response.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or response["ResponseMetadata"]["HTTPStatusCode"] != 200
                or any(k in response for k in ("NextToken", "NextMarker", "Marker"))):
            raise ValueError
        parameter = response["Parameter"]
        if (parameter.get("ARN") != arn or parameter.get("Name") != parameter_path
                or parameter.get("Type") != "SecureString" or type(parameter.get("Version")) is not int
                or parameter["Version"] != 1 or parameter.get("Selector") != ":1"
                or parameter.get("DataType") != "text" or "SourceResult" in parameter):
            raise ValueError
        result = decode_binding_keys(parameter["Value"], account_id=account_id, config=config,
                                     namespace=namespace, environment=environment)
        fresh()
        return result
    except Exception:
        raise BindingKeysError() from None
