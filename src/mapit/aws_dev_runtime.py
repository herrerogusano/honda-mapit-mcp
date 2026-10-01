"""Offline-only synthetic composition for a Cognito-bound eu-west-1 dev profile.

This module accepts a fixed public JWKS fixture. It never discovers keys over the
network and never constructs a MAPIT, local-session, credential-store or ledger
provider.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .lambda_adapter import _build_synthetic_lambda_handler
from .remote_http import (
    FixedRS256TokenVerifier,
    _build_synthetic_http_app,
)

_REGION = "eu-west-1"
_MAX_JWKS_BYTES = 32 * 1024
_MAX_JWKS_KEYS = 8
_MAX_RSA_BITS = 4096
_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})
_JWK_FIELDS = frozenset({"kty", "kid", "use", "alg", "n", "e"})
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,64}$")
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_OWNER_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class CognitoDevPolicy:
    """Canonical, dev-only identity and endpoint policy; URI claims are derived."""

    user_pool_id: str
    api_id: str
    client_id: str
    owner_subject: str
    max_request_body_bytes: int = 2 * 1024 * 1024
    max_response_body_bytes: int = 2 * 1024 * 1024
    max_token_bytes: int = 8192
    request_deadline_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not isinstance(self.user_pool_id, str) or not _POOL_ID.fullmatch(self.user_pool_id):
            raise ValueError("invalid development Cognito pool identifier")
        if not isinstance(self.api_id, str) or not _API_ID.fullmatch(self.api_id):
            raise ValueError("invalid development API identifier")
        if not isinstance(self.client_id, str) or not _CLIENT_ID.fullmatch(self.client_id):
            raise ValueError("invalid Cognito app client identifier")
        if not isinstance(self.owner_subject, str) or not _OWNER_UUID.fullmatch(self.owner_subject):
            raise ValueError("owner subject must be a canonical UUID")
        try:
            if str(uuid.UUID(self.owner_subject)) != self.owner_subject:
                raise ValueError("owner subject must be a canonical UUID")
        except (ValueError, AttributeError):
            raise ValueError("owner subject must be a canonical UUID") from None
        if type(self.max_request_body_bytes) is not int or self.max_request_body_bytes != 2 * 1024 * 1024:
            raise ValueError("development request limit must remain 2 MiB")
        if type(self.max_response_body_bytes) is not int or self.max_response_body_bytes != 2 * 1024 * 1024:
            raise ValueError("development response limit must remain 2 MiB")
        if type(self.max_token_bytes) is not int or self.max_token_bytes != 8192:
            raise ValueError("development token limit is fixed")
        deadline = self.request_deadline_seconds
        try:
            deadline_number = float(deadline)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("development request deadline is outside its bound") from None
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline_number)
            or not 0.01 <= deadline_number <= 15.0
        ):
            raise ValueError("development request deadline is outside its bound")

    @property
    def environment(self) -> str:
        return "dev"

    @property
    def issuer_url(self) -> str:
        return f"https://cognito-idp.{_REGION}.amazonaws.com/{self.user_pool_id}"

    @property
    def api_host(self) -> str:
        return f"{self.api_id}.execute-api.{_REGION}.amazonaws.com"

    @property
    def resource_url(self) -> str:
        return f"https://{self.api_host}/mcp"

    @property
    def audience(self) -> str:
        return self.resource_url

    @property
    def required_scope(self) -> str:
        return f"{self.resource_url}/use"

    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        return (self.api_host,)

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        return (f"https://{self.api_host}",)


def cognito_dev_policy(*, user_pool_id: str, api_id: str, client_id: str, owner_subject: str) -> CognitoDevPolicy:
    """Construct only the single-region, canonical dev policy."""
    return CognitoDevPolicy(
        user_pool_id=user_pool_id,
        api_id=api_id,
        client_id=client_id,
        owner_subject=owner_subject,
    )


def _reject_duplicate_json_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JWKS JSON member")
        result[name] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("invalid JWKS JSON constant")


def _decode_base64url_uint(value: Any, *, maximum_chars: int) -> int:
    if not isinstance(value, str) or not value or len(value) > maximum_chars or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid JWK integer encoding")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded + b"=" * ((4 - len(encoded) % 4) % 4), altchars=b"-_", validate=True)
    except (UnicodeError, binascii.Error, ValueError):
        raise ValueError("invalid JWK integer encoding") from None
    if not decoded or decoded[0] == 0 or base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
        raise ValueError("non-canonical JWK integer encoding")
    return int.from_bytes(decoded, "big")


def parse_cognito_jwks(document: bytes | str) -> Mapping[str, bytes]:
    """Validate a bounded fixed Cognito JWKS fixture and return immutable PEM keys."""
    if isinstance(document, bytes):
        if len(document) > _MAX_JWKS_BYTES:
            raise ValueError("JWKS fixture exceeds the size limit")
        try:
            raw = document.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("JWKS fixture must be UTF-8 JSON") from None
    elif isinstance(document, str):
        if len(document) > _MAX_JWKS_BYTES:
            raise ValueError("JWKS fixture exceeds the size limit")
        try:
            encoded_document = document.encode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("JWKS fixture must be UTF-8 JSON") from None
        if len(encoded_document) > _MAX_JWKS_BYTES:
            raise ValueError("JWKS fixture exceeds the size limit")
        raw = document
    else:
        raise ValueError("JWKS fixture must be bytes or text")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_members,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("JWKS fixture is invalid") from None
    if not isinstance(parsed, dict) or set(parsed) != {"keys"}:
        raise ValueError("JWKS fixture shape is invalid")
    entries = parsed["keys"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= _MAX_JWKS_KEYS:
        raise ValueError("JWKS key count is outside the allowed range")
    pem_keys: dict[str, bytes] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) - _JWK_FIELDS or set(entry) & _PRIVATE_JWK_FIELDS:
            raise ValueError("JWKS contains unsupported key fields")
        if set(entry) != _JWK_FIELDS:
            raise ValueError("JWKS key fields are incomplete")
        kid = entry["kid"]
        if not isinstance(kid, str) or not kid or len(kid) > 128 or "\r" in kid or "\n" in kid:
            raise ValueError("JWKS key identifier is invalid")
        if kid in pem_keys:
            raise ValueError("JWKS key identifiers must be unique")
        if entry["kty"] != "RSA" or entry["alg"] != "RS256" or entry["use"] != "sig":
            raise ValueError("JWKS key policy is unsupported")
        modulus = _decode_base64url_uint(entry["n"], maximum_chars=700)
        exponent = _decode_base64url_uint(entry["e"], maximum_chars=16)
        if modulus.bit_length() < 2048 or modulus.bit_length() > _MAX_RSA_BITS:
            raise ValueError("JWKS RSA key size is outside the allowed range")
        if exponent < 3 or exponent % 2 == 0 or exponent.bit_length() > 32:
            raise ValueError("JWKS RSA exponent is invalid")
        try:
            public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            pem_keys[kid] = public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except (TypeError, ValueError):
            raise ValueError("JWKS RSA public key is invalid") from None
    return MappingProxyType(pem_keys)


@dataclass(frozen=True)
class AwsDevSyntheticRuntime:
    """Already validated, local-only HTTP and Lambda compositions."""

    policy: CognitoDevPolicy
    public_keys: Mapping[str, bytes]
    http_app: Any
    lambda_handler: Any


def create_aws_dev_runtime(policy: CognitoDevPolicy, jwks_fixture: bytes | str) -> AwsDevSyntheticRuntime:
    """Create a fixed synthetic provider composition; there is no arbitrary provider seam."""
    if type(policy) is not CognitoDevPolicy:
        raise ValueError("a validated development Cognito policy is required")
    public_keys = parse_cognito_jwks(jwks_fixture)
    verifier = FixedRS256TokenVerifier(policy, public_keys)
    app = _build_synthetic_http_app(policy, verifier)

    def validate_keys(config: Any, keys: Mapping[str, bytes | str]) -> FixedRS256TokenVerifier:
        if config is not policy:
            raise ValueError("development policy identity changed")
        return FixedRS256TokenVerifier(config, keys)

    def build_app(config: Any, keys: Mapping[str, bytes | str]):
        if type(config) is not CognitoDevPolicy:
            raise ValueError("a validated development Cognito policy is required")
        return _build_synthetic_http_app(config, FixedRS256TokenVerifier(config, keys))

    handler = _build_synthetic_lambda_handler(
        policy,
        public_keys,
        key_validator=validate_keys,
        app_builder=build_app,
    )
    return AwsDevSyntheticRuntime(policy, public_keys, app, handler)


__all__ = [
    "AwsDevSyntheticRuntime",
    "CognitoDevPolicy",
    "cognito_dev_policy",
    "create_aws_dev_runtime",
    "parse_cognito_jwks",
]
