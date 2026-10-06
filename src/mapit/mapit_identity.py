"""Offline verification of the fixed Cognito identity used by opt-in MAPIT.

The verifier accepts only an injected, bounded RSA key set and HMAC seal key.
It never discovers keys, calls Cognito or treats a verified pool identity as
vehicle/account ownership.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import math
import re
from types import MappingProxyType
import uuid
from typing import Any, Callable, Mapping

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .config import MapitConfig

MAX_IDENTITY_TOKEN_BYTES = 8192
MAX_IDENTITY_CLAIMS_BYTES = 64 * 1024
MAX_IDENTITY_CLAIMS = 64
MAX_IDENTITY_HEADER_BYTES = 4096
MAX_IDENTITY_STRING_BYTES = 4096
_ALLOWED_HEADER_FIELDS = frozenset({"alg", "kid", "typ"})
_MAX_KEYS = 8
_REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]+\Z")
_POOL = re.compile(r"[a-z]{2}-[a-z]+-[0-9]+_[A-Za-z0-9]+\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")


class MapitIdentityError(ValueError):
    """Safe, stable failure category without token/claim/key material."""

    _ALLOWED = frozenset({
        "identity_configuration_invalid", "identity_token_invalid",
        "identity_proof_invalid", "identity_continuity_mismatch",
    })

    def __init__(self, category: str):
        self.category = category if category in self._ALLOWED else "identity_token_invalid"
        super().__init__(self.category)


def _utc_now(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError
        value = value.astimezone(timezone.utc)
        if not math.isfinite(value.timestamp()):
            raise ValueError
        return value
    except Exception:
        raise MapitIdentityError("identity_configuration_invalid") from None


def _bounded_text(value: Any, *, maximum: int = MAX_IDENTITY_STRING_BYTES) -> bool:
    return (
        type(value) is str and bool(value) and len(value.encode("utf-8", errors="ignore")) <= maximum
        and all(ord(char) >= 32 and char not in "\r\n" for char in value)
    )


@dataclass(frozen=True, repr=False)
class MapitIdentityProof:
    issuer: str
    subject_digest: bytes = field(repr=False)
    _seal: bytes = field(repr=False)
    _verifier: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "MapitIdentityProof(<redacted>)"


class MapitIdentityVerifier:
    """Verify a Cognito ID token against one fixed Mapit configuration."""

    def __init__(
        self,
        config: MapitConfig,
        public_keys: Mapping[str, bytes | str],
        hmac_key: bytes,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(config) is not MapitConfig:
            raise MapitIdentityError("identity_configuration_invalid")
        if (
            type(config.region) is not str or not _REGION.fullmatch(config.region)
            or type(config.user_pool_id) is not str or not _POOL.fullmatch(config.user_pool_id)
            or not config.user_pool_id.startswith(config.region + "_")
            or type(config.user_pool_client_id) is not str or not _CLIENT.fullmatch(config.user_pool_client_id)
        ):
            raise MapitIdentityError("identity_configuration_invalid")
        if not isinstance(public_keys, Mapping) or not 1 <= len(public_keys) <= _MAX_KEYS:
            raise MapitIdentityError("identity_configuration_invalid")
        if type(hmac_key) is not bytes or not 32 <= len(hmac_key) <= 128:
            raise MapitIdentityError("identity_configuration_invalid")
        parsed: dict[str, RSAPublicKey] = {}
        try:
            for kid, material in public_keys.items():
                if not _bounded_text(kid, maximum=128):
                    raise ValueError
                encoded = material.encode("ascii") if type(material) is str else material
                if type(encoded) is not bytes or not 1 <= len(encoded) <= 16 * 1024:
                    raise ValueError
                key = serialization.load_pem_public_key(encoded)
                if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                    raise ValueError
                if kid in parsed:
                    raise ValueError
                parsed[kid] = key
        except Exception:
            raise MapitIdentityError("identity_configuration_invalid") from None
        self.config = config
        self.issuer = f"https://cognito-idp.{config.region}.amazonaws.com/{config.user_pool_id}"
        self._keys = MappingProxyType(parsed)
        self._hmac_key = bytes(hmac_key)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._marker = object()

    def __repr__(self) -> str:
        return "MapitIdentityVerifier(<redacted>)"

    def _subject_digest(self, subject: str) -> bytes:
        return hmac.new(
            self._hmac_key,
            b"mapit-identity-sub-v1\0" + self.issuer.encode("utf-8") + b"\0" + subject.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _seal(self, issuer: str, digest: bytes) -> bytes:
        return hmac.new(self._hmac_key, b"mapit-identity-proof-v1\0" + issuer.encode("utf-8") + digest, hashlib.sha256).digest()

    def _proof(self, subject: str) -> MapitIdentityProof:
        digest = self._subject_digest(subject)
        return MapitIdentityProof(self.issuer, digest, self._seal(self.issuer, digest), self._marker)

    def verify(self, token: str) -> MapitIdentityProof:
        if (
            type(token) is not str or not token
            or len(token.encode("utf-8", errors="ignore")) > MAX_IDENTITY_TOKEN_BYTES
        ):
            raise MapitIdentityError("identity_token_invalid")
        try:
            parts = token.split(".")
            if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
                raise ValueError
            header = _strict_segment(parts[0], MAX_IDENTITY_HEADER_BYTES)
            strict_claims = _strict_segment(parts[1], MAX_IDENTITY_CLAIMS_BYTES)
            if not isinstance(header, dict) or set(header) - _ALLOWED_HEADER_FIELDS:
                raise ValueError
            if header.get("alg") != "RS256" or header.get("typ") not in {None, "JWT"}:
                raise ValueError
            kid = header.get("kid")
            if not _bounded_text(kid, maximum=128) or len(json_bytes(header)) > MAX_IDENTITY_HEADER_BYTES:
                raise ValueError
            key = self._keys.get(kid)
            if key is None:
                raise ValueError
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "verify_aud": False, "verify_iss": False, "verify_exp": False,
                    "verify_iat": False, "verify_nbf": False,
                    "require": ["iss", "aud", "sub", "token_use", "exp", "iat"],
                },
            )
            if not isinstance(strict_claims, dict) or not isinstance(claims, dict) or claims != strict_claims or len(claims) > MAX_IDENTITY_CLAIMS or len(json_bytes(claims)) > MAX_IDENTITY_CLAIMS_BYTES:
                raise ValueError
            if (
                claims.get("iss") != self.issuer
                or type(claims.get("aud")) is not str
                or claims.get("aud") != self.config.user_pool_client_id
                or claims.get("token_use") != "id"
            ):
                raise ValueError
            subject = claims.get("sub")
            if not _bounded_text(subject, maximum=128) or str(uuid.UUID(subject)) != subject:
                raise ValueError
            now = int(_utc_now(self._clock).timestamp())
            exp, issued, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
            if (
                type(exp) is not int or type(issued) is not int
                or not 0 <= exp <= 253402300799 or not 0 <= issued <= 253402300799
                or exp <= now or issued > now or exp <= issued
                or ("nbf" in claims and (type(nbf) is not int or not 0 <= nbf <= 253402300799 or nbf > now))
            ):
                raise ValueError
            return self._proof(subject)
        except MapitIdentityError:
            raise
        except Exception:
            raise MapitIdentityError("identity_token_invalid") from None

    verify_id_token = verify

    def validate_proof(self, proof: MapitIdentityProof) -> None:
        if (
            type(proof) is not MapitIdentityProof
            or proof._verifier is not self._marker
            or proof.issuer != self.issuer
            or type(proof.subject_digest) is not bytes or len(proof.subject_digest) != 32
            or type(proof._seal) is not bytes or len(proof._seal) != 32
            or not hmac.compare_digest(proof._seal, self._seal(proof.issuer, proof.subject_digest))
        ):
            raise MapitIdentityError("identity_proof_invalid")

    def ensure_continuity(self, expected: MapitIdentityProof, actual: MapitIdentityProof) -> None:
        self.validate_proof(expected)
        self.validate_proof(actual)
        if expected.issuer != actual.issuer or not hmac.compare_digest(expected.subject_digest, actual.subject_digest):
            raise MapitIdentityError("identity_continuity_mismatch")


def json_bytes(value: Any) -> bytes:
    """Bounded deterministic sizing helper; it returns no source material."""
    import json
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


__all__ = ["MapitIdentityError", "MapitIdentityProof", "MapitIdentityVerifier"]


def _reject_json_constant(value: str) -> Any:
    raise ValueError(value)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _strict_segment(segment: str, maximum: int) -> dict[str, Any]:
    if type(segment) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError
    raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    if len(raw) > maximum:
        raise ValueError
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_pairs,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise ValueError
    return value
