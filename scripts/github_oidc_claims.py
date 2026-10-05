"""One-shot GitHub Actions OIDC claim discovery; deliberately not signature verification.

Only a safe projection is emitted. The bearer request token and returned JWT
remain in memory and are never written, logged, or passed on a command line.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import sys
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


FIXED_REPOSITORY = "herrerogusano/honda-mapit-mcp"
FIXED_OWNER = "herrerogusano"
FIXED_REPOSITORY_NAME = "honda-mapit-mcp"
FIXED_ISSUER = "https://token.actions.githubusercontent.com"
FIXED_AUDIENCE = "sts.amazonaws.com"
TARGET_BRANCH = {"dev": "develop", "prod": "main"}
MAX_TOKEN_CHARS = 32_768
MAX_REQUEST_TOKEN_CHARS = 8_192
MAX_RESPONSE_BYTES = 32_768
REQUEST_TIMEOUT_SECONDS = 8.0
MAX_URL_CHARS = 4_096


class OidcClaimError(ValueError):
    """A fixed-category failure that never includes input or network data."""

    def __init__(self, category: str) -> None:
        allowed = {
            "invalid_target", "invalid_source", "runner_token_missing",
            "runner_endpoint_invalid", "runner_request_failed",
            "runner_response_invalid", "token_format_invalid",
            "claims_mismatch", "subject_format_unrecognized",
        }
        self.category = category if category in allowed else "claims_mismatch"
        super().__init__(self.category)


@dataclass(frozen=True, slots=True)
class SafeOidcSummary:
    status: str
    target: str
    source_sha: str
    subject_format: str
    subject_sha256: str

    def safe_dict(self) -> dict[str, str]:
        return {
            "status": self.status,
            "target": self.target,
            "source_sha": self.source_sha,
            "subject_format": self.subject_format,
            "subject_sha256": self.subject_sha256,
        }


def _duplicate_rejecting_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OidcClaimError("token_format_invalid")
        result[key] = value
    return result


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_rejecting_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(OidcClaimError("token_format_invalid")),
        )
    except OidcClaimError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise OidcClaimError("token_format_invalid") from None
    if type(parsed) is not dict:
        raise OidcClaimError("token_format_invalid")
    return parsed


def _decode_segment(segment: str, *, maximum: int) -> bytes:
    if type(segment) is not str or not segment or len(segment) > maximum:
        raise OidcClaimError("token_format_invalid")
    if re.fullmatch(r"[A-Za-z0-9_-]+", segment) is None:
        raise OidcClaimError("token_format_invalid")
    padded = segment + ("=" * (-len(segment) % 4))
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        raise OidcClaimError("token_format_invalid") from None


def _positive_decimal_id(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None


def _target_source(target: Any, source_sha: Any) -> str:
    if type(target) is not str or target not in TARGET_BRANCH:
        raise OidcClaimError("invalid_target")
    if type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise OidcClaimError("invalid_source")
    return f"refs/heads/{TARGET_BRANCH[target]}"


def validate_oidc_claims(
    token: str,
    *,
    target: str,
    source_sha: str,
    expected_repository_id: str,
    expected_owner_id: str,
) -> SafeOidcSummary:
    """Inspect a JWT's bounded header/claims and match only documented sub templates.

    This function does NOT verify the JWT signature, expiry, or key. Its success
    is an observed claim-shape match, never proof suitable by itself for AWS IAM.
    """
    expected_ref = _target_source(target, source_sha)
    if not _positive_decimal_id(expected_repository_id) or not _positive_decimal_id(expected_owner_id):
        raise OidcClaimError("invalid_source")
    if type(token) is not str or not token.isascii() or len(token) > MAX_TOKEN_CHARS:
        raise OidcClaimError("token_format_invalid")
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcClaimError("token_format_invalid")
    header_raw = _decode_segment(parts[0], maximum=8_192)
    claims_raw = _decode_segment(parts[1], maximum=24_576)
    if not parts[2] or len(parts[2]) > 8_192 or re.fullmatch(r"[A-Za-z0-9_-]+", parts[2]) is None:
        raise OidcClaimError("token_format_invalid")
    header = _json_object(header_raw)
    claims = _json_object(claims_raw)
    if header.get("alg") != "RS256" or type(header.get("kid")) is not str or not header["kid"] or len(header["kid"]) > 256:
        raise OidcClaimError("token_format_invalid")
    if "typ" in header and header["typ"] != "JWT":
        raise OidcClaimError("token_format_invalid")

    required = {
        "iss", "aud", "repository", "repository_owner", "repository_id",
        "repository_owner_id", "ref", "sha", "environment", "sub",
    }
    if not required.issubset(claims):
        raise OidcClaimError("claims_mismatch")
    if (
        claims["iss"] != FIXED_ISSUER
        or claims["aud"] != FIXED_AUDIENCE
        or claims["repository"] != FIXED_REPOSITORY
        or claims["repository_owner"] != FIXED_OWNER
        or claims["ref"] != expected_ref
        or claims["sha"] != source_sha
        or claims["environment"] != target
        or claims["repository_id"] != expected_repository_id
        or claims["repository_owner_id"] != expected_owner_id
        or not _positive_decimal_id(claims["repository_id"])
        or not _positive_decimal_id(claims["repository_owner_id"])
        or type(claims["sub"]) is not str
        or len(claims["sub"]) > 1024
    ):
        raise OidcClaimError("claims_mismatch")

    legacy_sub = f"repo:{FIXED_REPOSITORY}:environment:{target}"
    immutable_sub = (
        f"repo:{FIXED_OWNER}@{claims['repository_owner_id']}/"
        f"{FIXED_REPOSITORY_NAME}@{claims['repository_id']}:environment:{target}"
    )
    if claims["sub"] == legacy_sub:
        subject_format = "legacy_environment"
    elif claims["sub"] == immutable_sub:
        subject_format = "immutable_environment"
    else:
        raise OidcClaimError("subject_format_unrecognized")
    digest = hashlib.sha256(claims["sub"].encode("utf-8")).hexdigest()
    return SafeOidcSummary(
        status="claims_match_unverified",
        target=target,
        source_sha=source_sha,
        subject_format=subject_format,
        subject_sha256=digest,
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _runner_request_url(raw_url: Any) -> str:
    if type(raw_url) is not str or not raw_url.isascii() or len(raw_url) > MAX_URL_CHARS:
        raise OidcClaimError("runner_endpoint_invalid")
    if any(ord(char) < 0x20 or char == "\\" for char in raw_url):
        raise OidcClaimError("runner_endpoint_invalid")
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        raise OidcClaimError("runner_endpoint_invalid") from None
    host = hostname.lower()
    if (
        parsed.scheme != "https"
        or not host
        or not (host == "actions.githubusercontent.com" or host.endswith(".actions.githubusercontent.com"))
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or not parsed.path.startswith("/")
        or parsed.fragment
    ):
        raise OidcClaimError("runner_endpoint_invalid")
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=16)
    except ValueError:
        raise OidcClaimError("runner_endpoint_invalid") from None
    names = [key for key, _ in query]
    if len(names) != len(set(names)) or "audience" in names:
        raise OidcClaimError("runner_endpoint_invalid")
    query.append(("audience", FIXED_AUDIENCE))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def _read_bounded_response(response: Any, *, clock: Callable[[], float]) -> bytes:
    status = getattr(response, "status", None)
    if type(status) is not int or status != 200:
        raise OidcClaimError("runner_response_invalid")
    headers = getattr(response, "headers", None)
    if headers is not None:
        content_length = headers.get("Content-Length")
        if content_length is not None:
            if type(content_length) is not str or re.fullmatch(r"[0-9]{1,8}", content_length) is None:
                raise OidcClaimError("runner_response_invalid")
            if int(content_length) > MAX_RESPONSE_BYTES:
                raise OidcClaimError("runner_response_invalid")
    start = clock()
    if type(start) not in (int, float) or not math.isfinite(start):
        raise OidcClaimError("runner_response_invalid")
    body = response.read(MAX_RESPONSE_BYTES + 1)
    end = clock()
    if type(end) not in (int, float) or not math.isfinite(end) or end < start or end - start > REQUEST_TIMEOUT_SECONDS:
        raise OidcClaimError("runner_response_invalid")
    if type(body) is not bytes or len(body) > MAX_RESPONSE_BYTES:
        raise OidcClaimError("runner_response_invalid")
    return body


def request_runner_oidc_token(
    request_url: Any,
    request_token: Any,
    *,
    opener: Any | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Make exactly one bounded HTTPS GET to the runner-provided OIDC endpoint."""
    url = _runner_request_url(request_url)
    if (
        type(request_token) is not str
        or not request_token.isascii()
        or not 20 <= len(request_token) <= MAX_REQUEST_TOKEN_CHARS
        or any(ord(char) <= 0x20 or ord(char) > 0x7E for char in request_token)
    ):
        raise OidcClaimError("runner_token_missing")
    request = Request(url, method="GET", headers={"Authorization": f"Bearer {request_token}", "Accept": "application/json"})
    if opener is None:
        opener = build_opener(ProxyHandler({}), _NoRedirect(), HTTPSHandler())
    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS)
        with response:
            raw = _read_bounded_response(response, clock=clock)
    except OidcClaimError:
        raise
    except Exception:
        raise OidcClaimError("runner_request_failed") from None
    envelope = _json_object(raw)
    if (
        set(envelope) not in ({"value"}, {"count", "value"})
        or ("count" in envelope and (type(envelope["count"]) is not int or envelope["count"] != 1))
    ):
        raise OidcClaimError("runner_response_invalid")
    value = envelope.get("value")
    if type(value) is not str or not value or len(value) > MAX_TOKEN_CHARS:
        raise OidcClaimError("runner_response_invalid")
    return value


def discover_from_environment(
    environment: Mapping[str, str],
    *,
    opener: Any | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> SafeOidcSummary:
    target = environment.get("TARGET")
    source_sha = environment.get("GITHUB_SHA") or environment.get("SOURCE_SHA")
    expected_ref = _target_source(target, source_sha)
    source_ref = environment.get("GITHUB_REF")
    if source_ref is None:
        source_ref = environment.get("SOURCE_REF")
    if source_ref != expected_ref or ("SOURCE_REF" in environment and environment.get("SOURCE_REF") != expected_ref):
        raise OidcClaimError("invalid_source")
    if (
        environment.get("GITHUB_SHA", source_sha) != source_sha
        or environment.get("SOURCE_SHA", source_sha) != source_sha
    ):
        raise OidcClaimError("invalid_source")
    if (
        not _positive_decimal_id(environment.get("EXPECTED_REPOSITORY_ID"))
        or not _positive_decimal_id(environment.get("EXPECTED_OWNER_ID"))
    ):
        raise OidcClaimError("invalid_source")
    token = request_runner_oidc_token(
        environment.get("ACTIONS_ID_TOKEN_REQUEST_URL"),
        environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
        opener=opener,
        clock=clock,
    )
    return validate_oidc_claims(
        token,
        target=target,
        source_sha=source_sha,
        expected_repository_id=environment.get("EXPECTED_REPOSITORY_ID"),
        expected_owner_id=environment.get("EXPECTED_OWNER_ID"),
    )


def main() -> int:
    try:
        result = discover_from_environment(os.environ)
        safe = result.safe_dict()
        print(json.dumps(safe, separators=(",", ":"), sort_keys=True))
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8", newline="\n") as stream:
                stream.write("## OIDC claim-shape discovery (signature unverified)\n\n")
                stream.write(f"- Status: `{safe['status']}`\n")
                stream.write(f"- Target: `{safe['target']}`\n")
                stream.write(f"- Source SHA: `{safe['source_sha']}`\n")
                stream.write(f"- Subject format: `{safe['subject_format']}`\n")
                stream.write(f"- Subject SHA-256: `{safe['subject_sha256']}`\n")
        return 0
    except OidcClaimError as error:
        print(json.dumps({"status": "failed", "category": error.category}, separators=(",", ":")))
        return 1
    except Exception:
        print('{"status":"failed","category":"internal_error"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
