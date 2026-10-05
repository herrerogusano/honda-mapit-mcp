"""Runner entrypoint for the one-shot identity-only OIDC proof.

Token and STS values remain in memory. This is not a deployment command and
does not provide credentials to later steps, files, artifacts, or environment.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any

from scripts.github_oidc_claims import OidcClaimError, request_runner_oidc_token
from scripts.github_sts_identity import (
    REGION,
    StsProofError,
    prove_github_sts_identity,
)


_ROLE_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):role/(honda-mapit-mcp-(dev|prod)-cd)\Z")
_FORBIDDEN_AWS_ENV = frozenset({
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
    "AWS_BEARER_TOKEN_BEDROCK", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE",
    "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_CA_BUNDLE", "AWS_SDK_LOAD_CONFIG",
    "AWS_STS_REGIONAL_ENDPOINTS", "AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "BOTO_CONFIG", "BOTOCORE_LOG_LEVEL", "BOTO_LOG_LEVEL", "AWS_LOG_LEVEL", "AWS_DEBUG",
})
_MAX_CALL_TIMEOUT = 4
_ENDPOINT = "https://sts.eu-west-1.amazonaws.com"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RunnerProofError(ValueError):
    def __init__(self, category: str) -> None:
        allowed = {"ambient_aws_source", "runner_context_invalid", "role_binding_invalid", "proof_failed"}
        self.category = category if category in allowed else "proof_failed"
        super().__init__(self.category)


def _context(environment: Mapping[str, str], home: str | os.PathLike[str] | None) -> tuple[str, str, str, str, str]:
    target = environment.get("TARGET")
    ref = environment.get("GITHUB_REF")
    source_sha = environment.get("GITHUB_SHA")
    expected_ref = {"dev": "refs/heads/develop", "prod": "refs/heads/main"}.get(target)
    repo_id = environment.get("GITHUB_REPOSITORY_ID")
    owner_id = environment.get("GITHUB_REPOSITORY_OWNER_ID")
    if (
        expected_ref is None
        or ref != expected_ref
        or environment.get("SOURCE_REF", ref) != ref
        or type(source_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
        or environment.get("SOURCE_SHA", source_sha) != source_sha
        or environment.get("GITHUB_REPOSITORY") != "herrerogusano/honda-mapit-mcp"
        or type(repo_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", repo_id) is None
        or type(owner_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", owner_id) is None
    ):
        raise RunnerProofError("runner_context_invalid")
    role_arn = environment.get("AWS_CD_IDENTITY_ROLE_ARN")
    match = _ROLE_ARN.fullmatch(role_arn or "")
    expected_name = f"honda-mapit-mcp-{target}-cd"
    if match is None or match.group(2) != expected_name:
        raise RunnerProofError("role_binding_invalid")
    home_path = Path(home) if home is not None else Path.home()
    if any((home_path / ".aws" / name).exists() for name in ("credentials", "config")):
        raise RunnerProofError("ambient_aws_source")
    return target, source_sha, repo_id, owner_id, role_arn


def _reject_ambient_sources(environment: Mapping[str, str]) -> None:
    keys = set(environment)
    if (
        any(key.startswith("AWS_") and key != "AWS_CD_IDENTITY_ROLE_ARN" for key in keys)
        or keys & _FORBIDDEN_AWS_ENV
        or any(key.startswith("AWS_ENDPOINT_URL_") for key in keys)
    ):
        raise RunnerProofError("ambient_aws_source")


def _new_sts_client(*, unsigned: bool, credentials: Mapping[str, str] | None = None) -> Any:
    """Create an isolated client with an explicit non-chain credential source."""
    try:
        import botocore.session
        from botocore import UNSIGNED
        from botocore.config import Config
    except Exception:
        raise RunnerProofError("proof_failed") from None
    session = botocore.session.Session()
    if unsigned:
        # An explicit empty credential object prevents provider-chain lookup;
        # UNSIGNED guarantees it is not used to sign the web-identity request.
        session.set_credentials("", "")
        signature_version = UNSIGNED
    else:
        if (
            not isinstance(credentials, Mapping)
            or set(credentials) != {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
            or any(type(value) is not str or not value for value in credentials.values())
        ):
            raise RunnerProofError("proof_failed")
        session.set_credentials(
            credentials["aws_access_key_id"],
            credentials["aws_secret_access_key"],
            credentials["aws_session_token"],
        )
        signature_version = "v4"
    config = Config(
        signature_version=signature_version,
        connect_timeout=2,
        read_timeout=_MAX_CALL_TIMEOUT,
        retries={"total_max_attempts": 1, "mode": "standard"},
        proxies={},
    )
    try:
        return session.create_client(
            "sts", region_name=REGION, endpoint_url=_ENDPOINT, verify=True, config=config
        )
    except Exception:
        raise RunnerProofError("proof_failed") from None


def run_identity_proof(
    environment: Mapping[str, str],
    *,
    opener: Any | None = None,
    home: str | os.PathLike[str] | None = None,
    client_factory: Callable[..., Any] = _new_sts_client,
    clock: Callable[[], datetime] = _utc_now,
) -> dict[str, Any]:
    """Validate runner context, request one token, and perform the bounded proof."""
    _reject_ambient_sources(environment)
    target, sha, repo_id, owner_id, role_arn = _context(environment, home)
    try:
        token = request_runner_oidc_token(
            environment.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
            environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
            opener=opener,
        )
    except OidcClaimError:
        raise RunnerProofError("proof_failed") from None
    unsigned_client = None
    created: list[Any] = []
    try:
        unsigned_client = client_factory(unsigned=True)

        def explicit_factory(**credentials: str) -> Any:
            if credentials.pop("region_name", None) != REGION:
                raise RunnerProofError("proof_failed")
            client = client_factory(unsigned=False, credentials=credentials)
            created.append(client)
            return client

        match = _ROLE_ARN.fullmatch(role_arn)
        assert match is not None
        proof = prove_github_sts_identity(
            token,
            target=target,
            source_sha=sha,
            expected_account_id=match.group(1),
            expected_owner_id=owner_id,
            expected_repository_id=repo_id,
            role_arn=role_arn,
            anonymous_sts=unsigned_client,
            explicit_sts_factory=explicit_factory,
            clock=clock,
        )
        return proof.safe_dict()
    except (StsProofError, RunnerProofError):
        raise RunnerProofError("proof_failed") from None
    except Exception:
        raise RunnerProofError("proof_failed") from None
    finally:
        for client in [unsigned_client, *created]:
            close = getattr(client, "close", None) if client is not None else None
            if callable(close):
                try:
                    close()
                except Exception:
                    pass


def main() -> int:
    try:
        safe = run_identity_proof(os.environ)
        print(json.dumps(safe, separators=(",", ":"), sort_keys=True))
        return 0
    except RunnerProofError as error:
        print(json.dumps({"status": "failed", "category": error.category}, separators=(",", ":")))
        return 1
    except Exception:
        print('{"status":"failed","category":"proof_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
