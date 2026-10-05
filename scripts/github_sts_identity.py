"""Injected, single-attempt GitHub OIDC to AWS identity proof core.

This module does not request runner tokens, construct SDK clients, look up
credentials, or make network calls. Callers must supply a single-attempt,
unsigned regional STS client for the web-identity exchange and a factory that
constructs the second STS client using only the returned explicit credentials.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import re
from typing import Any

from scripts.github_oidc_claims import OidcClaimError, validate_oidc_claims


REGION = "eu-west-1"
ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "sts.amazonaws.com"
ROLE_NAMES = {"dev": "honda-mapit-mcp-dev-cd", "prod": "honda-mapit-mcp-prod-cd"}
_ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/(honda-mapit-mcp-(?:dev|prod)-cd)\Z")
_MAX_SESSION_FIELD = 1_048_576


class StsProofError(ValueError):
    """Fixed-category proof failure; never contains token, credentials, or SDK text."""

    def __init__(self, category: str) -> None:
        allowed = {
            "invalid_input", "claims_mismatch", "sts_exchange_failed",
            "sts_response_invalid", "identity_mismatch", "credentials_invalid",
        }
        self.category = category if category in allowed else "sts_response_invalid"
        super().__init__(self.category)


@dataclass(frozen=True, slots=True)
class IdentityProof:
    status: str
    target: str
    source_sha: str
    account_verified: bool
    role_verified: bool

    def safe_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "target": self.target,
            "source_sha": self.source_sha,
            "account_verified": self.account_verified,
            "role_verified": self.role_verified,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _http_200(reply: Any) -> bool:
    if not isinstance(reply, Mapping):
        return False
    metadata = reply.get("ResponseMetadata")
    return (
        isinstance(metadata, Mapping)
        and type(metadata.get("HTTPStatusCode")) is int
        and metadata["HTTPStatusCode"] == 200
    )


def _same_digest(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def prove_github_sts_identity(
    token: str,
    *,
    target: str,
    source_sha: str,
    expected_account_id: str,
    expected_owner_id: str,
    expected_repository_id: str,
    role_arn: str,
    anonymous_sts: Any,
    explicit_sts_factory: Callable[..., Any],
    clock: Callable[[], datetime] = _utc_now,
) -> IdentityProof:
    """Make exactly one injected web-identity exchange and one explicit-credential identity read."""
    if (
        type(target) is not str
        or target not in ROLE_NAMES
        or type(source_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or type(expected_account_id) is not str
        or re.fullmatch(r"[0-9]{12}", expected_account_id) is None
        or type(expected_owner_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", expected_owner_id) is None
        or type(expected_repository_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", expected_repository_id) is None
        or type(role_arn) is not str
    ):
        raise StsProofError("invalid_input")
    match = _ROLE_ARN.fullmatch(role_arn)
    if (
        match is None
        or match.group(1) != expected_account_id
        or match.group(2) != ROLE_NAMES[target]
    ):
        raise StsProofError("invalid_input")
    account_id = match.group(1)
    try:
        claims = validate_oidc_claims(
            token,
            target=target,
            source_sha=source_sha,
            expected_owner_id=expected_owner_id,
            expected_repository_id=expected_repository_id,
        )
    except OidcClaimError:
        raise StsProofError("claims_mismatch") from None

    session_name = f"mapit-cd-{target}-{source_sha[:12]}"
    try:
        assume = anonymous_sts.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=token,
            DurationSeconds=900,
        )
    except Exception:
        raise StsProofError("sts_exchange_failed") from None
    if not _http_200(assume):
        raise StsProofError("sts_response_invalid")

    provider = assume.get("Provider")
    audience = assume.get("Audience")
    subject = assume.get("SubjectFromWebIdentityToken")
    assumed = assume.get("AssumedRoleUser")
    credentials = assume.get("Credentials")
    subject_digest = ""
    if type(subject) is str and len(subject) <= 1024:
        subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    if (
        provider != ISSUER
        or audience != AUDIENCE
        or not _same_digest(subject_digest, claims.subject_sha256)
        or not isinstance(assumed, Mapping)
        or not isinstance(credentials, Mapping)
    ):
        raise StsProofError("identity_mismatch")
    expected_arn = f"arn:aws:sts::{account_id}:assumed-role/{ROLE_NAMES[target]}/{session_name}"
    assumed_arn = assumed.get("Arn")
    assumed_id = assumed.get("AssumedRoleId")
    if (
        assumed_arn != expected_arn
        or type(assumed_id) is not str
        or len(assumed_id) > 256
        or not assumed_id.endswith(f":{session_name}")
    ):
        raise StsProofError("identity_mismatch")

    access_key = credentials.get("AccessKeyId")
    secret_key = credentials.get("SecretAccessKey")
    session_token = credentials.get("SessionToken")
    expiration = credentials.get("Expiration")
    if any(
        type(value) is not str or not value or len(value) > _MAX_SESSION_FIELD
        for value in (access_key, secret_key, session_token)
    ):
        raise StsProofError("credentials_invalid")
    try:
        if (
            not isinstance(expiration, datetime)
            or expiration.tzinfo is None
            or expiration.utcoffset() is None
        ):
            raise ValueError
        now = clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ValueError
        expiration_utc = expiration.astimezone(timezone.utc)
        now_utc = now.astimezone(timezone.utc)
    except Exception:
        raise StsProofError("credentials_invalid") from None
    if expiration_utc <= now_utc or (expiration_utc - now_utc).total_seconds() > 960:
        raise StsProofError("credentials_invalid")

    try:
        authenticated_sts = explicit_sts_factory(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=REGION,
        )
        caller = authenticated_sts.get_caller_identity()
    except Exception:
        raise StsProofError("sts_exchange_failed") from None
    if not _http_200(caller):
        raise StsProofError("sts_response_invalid")
    if (
        caller.get("Account") != account_id
        or caller.get("Arn") != expected_arn
        or caller.get("UserId") != assumed_id
    ):
        raise StsProofError("identity_mismatch")
    return IdentityProof(
        status="aws_identity_verified",
        target=target,
        source_sha=source_sha,
        account_verified=True,
        role_verified=True,
    )
