"""Bounded, identity-only OIDC proof for the retained development role.

The runner is deliberately separate from production CD.  It accepts one
exact ``develop`` checkout, requests one runner token, performs one unsigned
STS exchange, and performs one caller-identity read with only the returned
temporary credentials.  No credential is exported, written, or included in
the safe result.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any

from scripts.github_oidc_claims import OidcClaimError, request_runner_oidc_token, validate_oidc_claims
from scripts.run_github_sts_identity import _new_sts_client


REGION = "eu-west-1"
ISSUER = "https://token.actions.githubusercontent.com"
AUDIENCE = "sts.amazonaws.com"
REPOSITORY = "herrerogusano/honda-mapit-mcp"
TARGET = "dev"
EXPECTED_REF = "refs/heads/develop"
ROLE_NAME = "honda-mapit-mcp-dev-retained-readonly-proof"
ROLE_ENV_NAME = "AWS_RETAINED_DEV_PROOF_ROLE_ARN"
EXPECTED_ACCOUNT_ENV_NAME = "AWS_RETAINED_DEV_EXPECTED_ACCOUNT_ID"
MAX_CREDENTIAL_FIELD = 1_048_576
MAX_CALL_TIMEOUT = 4
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_ROLE = re.compile(r"arn:aws:iam::([0-9]{12}):role/" + re.escape(ROLE_NAME) + r"\Z")
_FORBIDDEN_AWS_ENV = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_ROLE_SESSION_NAME",
    "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE",
    "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE", "AWS_SDK_LOAD_CONFIG",
    "AWS_STS_REGIONAL_ENDPOINTS", "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE", "AWS_BEARER_TOKEN_BEDROCK", "BOTO_CONFIG",
    "BOTOCORE_LOG_LEVEL", "BOTO_LOG_LEVEL", "AWS_LOG_LEVEL", "AWS_DEBUG",
})


class RetainedDevOidcProofError(ValueError):
    """Allowlisted failure; never stores provider or credential text."""

    _CATEGORIES = {
        "ambient_aws_source", "runner_context_invalid", "role_binding_invalid",
        "runner_token_missing", "runner_endpoint_invalid", "runner_request_failed",
        "runner_response_invalid", "claims_mismatch", "sts_client_creation_failed",
        "sts_exchange_failed", "sts_response_invalid", "identity_mismatch",
        "credentials_invalid", "proof_failed",
    }
    _STAGES = {
        "context", "oidc_token_acquisition", "claims_validation", "unsigned_client_creation",
        "assume_role_exchange", "assume_role_response_validation", "credential_validation",
        "signed_client_creation", "caller_identity_exchange", "caller_identity_response_validation",
        "proof_internal",
    }

    def __init__(self, category: str, *, stage: str = "proof_internal") -> None:
        self.category = category if category in self._CATEGORIES else "proof_failed"
        self.stage = stage if stage in self._STAGES else "proof_internal"
        super().__init__(self.category)

    def safe_dict(self) -> dict[str, Any]:
        category = self.category if self.category in self._CATEGORIES else "proof_failed"
        stage = self.stage if self.stage in self._STAGES else "proof_internal"
        return {"status": "failed", "target": TARGET, "category": category, "stage": stage}


def _http_200(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _default_client_factory(*, unsigned: bool, credentials: Mapping[str, str] | None = None, region_name: str = REGION) -> Any:
    if region_name != REGION:
        raise RetainedDevOidcProofError("sts_client_creation_failed", stage="proof_internal")
    return _new_sts_client(unsigned=unsigned, credentials=credentials)


def _reject_ambient(environment: Mapping[str, str]) -> None:
    keys = set(environment)
    if any(key.startswith("AWS_") and key not in {ROLE_ENV_NAME, EXPECTED_ACCOUNT_ENV_NAME} for key in keys):
        raise RetainedDevOidcProofError("ambient_aws_source", stage="context")
    if keys & _FORBIDDEN_AWS_ENV or any(key.startswith("AWS_ENDPOINT_URL_") for key in keys):
        raise RetainedDevOidcProofError("ambient_aws_source", stage="context")


def _context(environment: Mapping[str, str], home: str | os.PathLike[str] | None) -> tuple[str, str, str, str, str]:
    source_sha = environment.get("GITHUB_SHA")
    owner_id = environment.get("GITHUB_REPOSITORY_OWNER_ID")
    repository_id = environment.get("GITHUB_REPOSITORY_ID")
    account_id = environment.get(EXPECTED_ACCOUNT_ENV_NAME)
    role_arn = environment.get(ROLE_ENV_NAME)
    if (
        environment.get("TARGET", TARGET) != TARGET
        or environment.get("GITHUB_REF") != EXPECTED_REF
        or environment.get("SOURCE_REF", EXPECTED_REF) != EXPECTED_REF
        or type(source_sha) is not str or _SHA.fullmatch(source_sha) is None
        or environment.get("SOURCE_SHA", source_sha) != source_sha
        or environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or type(owner_id) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", owner_id) is None
        or type(repository_id) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", repository_id) is None
        or type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000"
    ):
        raise RetainedDevOidcProofError("runner_context_invalid", stage="context")
    match = _ROLE.fullmatch(role_arn or "")
    if match is None or match.group(1) != account_id:
        raise RetainedDevOidcProofError("role_binding_invalid", stage="context")
    home_path = Path(home) if home is not None else Path.home()
    if any((home_path / ".aws" / name).exists() for name in ("credentials", "config")):
        raise RetainedDevOidcProofError("ambient_aws_source", stage="context")
    return source_sha, owner_id, repository_id, account_id, role_arn


def _validate_assume_response(reply: Mapping[str, Any], *, account_id: str, role_arn: str, session_name: str, claims: Any, now: datetime) -> tuple[dict[str, str], str]:
    if not _http_200(reply):
        raise RetainedDevOidcProofError("sts_response_invalid", stage="assume_role_response_validation")
    provider = reply.get("Provider")
    expected_provider = f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
    subject = reply.get("SubjectFromWebIdentityToken")
    subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest() if type(subject) is str and len(subject) <= 1024 else ""
    assumed = reply.get("AssumedRoleUser")
    credentials = reply.get("Credentials")
    expected_assumed = f"arn:aws:sts::{account_id}:assumed-role/{ROLE_NAME}/{session_name}"
    if (
        provider not in {ISSUER, expected_provider} or reply.get("Audience") != AUDIENCE
        or not hmac.compare_digest(subject_digest, claims.subject_sha256)
        or not isinstance(assumed, Mapping) or not isinstance(credentials, Mapping)
        or assumed.get("Arn") != expected_assumed
        or type(assumed.get("AssumedRoleId")) is not str
        or not assumed["AssumedRoleId"].endswith(":" + session_name)
    ):
        raise RetainedDevOidcProofError("identity_mismatch", stage="assume_role_response_validation")
    fields = {"aws_access_key_id": credentials.get("AccessKeyId"), "aws_secret_access_key": credentials.get("SecretAccessKey"), "aws_session_token": credentials.get("SessionToken")}
    expiration = credentials.get("Expiration")
    if any(type(value) is not str or not value or len(value) > MAX_CREDENTIAL_FIELD for value in fields.values()) or not isinstance(expiration, datetime) or expiration.tzinfo is None or expiration.utcoffset() is None or not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise RetainedDevOidcProofError("credentials_invalid", stage="credential_validation")
    try:
        remaining = (expiration.astimezone(timezone.utc) - now.astimezone(timezone.utc)).total_seconds()
    except Exception:
        raise RetainedDevOidcProofError("credentials_invalid", stage="credential_validation") from None
    if remaining <= 0 or remaining > 960:
        raise RetainedDevOidcProofError("credentials_invalid", stage="credential_validation")
    return fields, assumed["AssumedRoleId"]


def run_retained_dev_oidc_proof(
    environment: Mapping[str, str],
    *,
    opener: Any | None = None,
    home: str | os.PathLike[str] | None = None,
    client_factory: Callable[..., Any] | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Run one injected dev proof; successful output contains no account/role IDs."""
    _reject_ambient(environment)
    source_sha, owner_id, repository_id, account_id, role_arn = _context(environment, home)
    try:
        token = request_runner_oidc_token(environment.get("ACTIONS_ID_TOKEN_REQUEST_URL"), environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), opener=opener)
    except OidcClaimError as exc:
        raise RetainedDevOidcProofError(exc.category, stage="oidc_token_acquisition") from None
    except Exception:
        raise RetainedDevOidcProofError("proof_failed", stage="oidc_token_acquisition") from None
    try:
        claims = validate_oidc_claims(token, target=TARGET, source_sha=source_sha, expected_owner_id=owner_id, expected_repository_id=repository_id)
    except OidcClaimError:
        raise RetainedDevOidcProofError("claims_mismatch", stage="claims_validation") from None
    unsigned = None
    signed = None
    factory = client_factory or _default_client_factory
    session_name = f"mapit-retained-dev-{source_sha[:12]}"
    try:
        try:
            unsigned = factory(unsigned=True, region_name=REGION)
        except Exception:
            raise RetainedDevOidcProofError("sts_client_creation_failed", stage="unsigned_client_creation") from None
        try:
            assume = unsigned.assume_role_with_web_identity(RoleArn=role_arn, RoleSessionName=session_name, WebIdentityToken=token, DurationSeconds=900)
        except Exception:
            raise RetainedDevOidcProofError("sts_exchange_failed", stage="assume_role_exchange") from None
        credentials, assumed_id = _validate_assume_response(assume, account_id=account_id, role_arn=role_arn, session_name=session_name, claims=claims, now=clock())
        try:
            signed = factory(unsigned=False, credentials=credentials, region_name=REGION)
        except Exception:
            raise RetainedDevOidcProofError("sts_client_creation_failed", stage="signed_client_creation") from None
        try:
            caller = signed.get_caller_identity()
        except Exception:
            raise RetainedDevOidcProofError("sts_exchange_failed", stage="caller_identity_exchange") from None
        expected_assumed = f"arn:aws:sts::{account_id}:assumed-role/{ROLE_NAME}/{session_name}"
        if not _http_200(caller) or caller.get("Account") != account_id or caller.get("Arn") != expected_assumed or caller.get("UserId") != assumed_id:
            raise RetainedDevOidcProofError("identity_mismatch", stage="caller_identity_response_validation")
        return {"status": "aws_identity_verified", "target": TARGET, "source_sha": source_sha, "account_verified": True, "role_verified": True}
    finally:
        for client in (unsigned, signed):
            close = getattr(client, "close", None) if client is not None else None
            if callable(close):
                try:
                    close()
                except Exception:
                    pass


def main() -> int:
    try:
        print(json.dumps(run_retained_dev_oidc_proof(os.environ), separators=(",", ":"), sort_keys=True))
        return 0
    except RetainedDevOidcProofError as exc:
        print(json.dumps(exc.safe_dict(), separators=(",", ":"), sort_keys=True))
        return 1
    except Exception:
        print('{"status":"failed","target":"dev","category":"proof_failed","stage":"proof_internal"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
