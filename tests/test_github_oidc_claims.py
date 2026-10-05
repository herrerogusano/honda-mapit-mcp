import base64
import json

import pytest

from scripts.github_oidc_claims import (
    FIXED_AUDIENCE,
    FIXED_ISSUER,
    FIXED_REPOSITORY,
    MAX_RESPONSE_BYTES,
    OidcClaimError,
    discover_from_environment,
    request_runner_oidc_token,
    validate_oidc_claims,
)


TARGET = "prod"
SOURCE_SHA = "a" * 40
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"


def _validate(token, *, target="prod", source_sha=SOURCE_SHA):
    return validate_oidc_claims(
        token,
        target=target,
        source_sha=source_sha,
        expected_repository_id=REPOSITORY_ID,
        expected_owner_id=OWNER_ID,
    )


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _claims(*, target=TARGET, sha=SOURCE_SHA, owner_id=OWNER_ID, repo_id=REPOSITORY_ID, sub=None):
    branch = "main" if target == "prod" else "develop"
    expected_sub = (
        f"repo:herrerogusano@{owner_id}/honda-mapit-mcp@{repo_id}:environment:{target}"
        if sub is None
        else sub
    )
    return {
        "iss": FIXED_ISSUER,
        "aud": FIXED_AUDIENCE,
        "repository": FIXED_REPOSITORY,
        "repository_owner": "herrerogusano",
        "repository_id": repo_id,
        "repository_owner_id": owner_id,
        "ref": f"refs/heads/{branch}",
        "sha": sha,
        "environment": target,
        "sub": expected_sub,
        "workflow": "herrerogusano/honda-mapit-mcp/.github/workflows/cd-identity.yml@refs/heads/main",
    }


def _jwt(claims=None, *, raw_claims=None):
    header = {"alg": "RS256", "kid": "synthetic-key-id", "typ": "JWT"}
    payload = json.dumps(claims, separators=(",", ":")).encode() if raw_claims is None else raw_claims
    return f"{_b64(json.dumps(header, separators=(',', ':')).encode())}.{_b64(payload)}.{_b64(b'synthetic-signature-bytes' * 8)}"


class _Response:
    status = 200

    def __init__(self, body: bytes, headers=None):
        self.body = body
        self.headers = headers or {"Content-Length": str(len(body))}
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size):
        self.read_sizes.append(size)
        return self.body[:size]


class _Opener:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def open(self, request, *, timeout):
        self.calls.append((request, timeout))
        return self.response


def test_accepts_only_exact_legacy_or_immutable_environment_subjects() -> None:
    immutable = _validate(_jwt(_claims()))
    assert immutable.status == "claims_match_unverified"
    assert immutable.subject_format == "immutable_environment"
    assert len(immutable.subject_sha256) == 64
    assert immutable.source_sha == SOURCE_SHA

    legacy = _claims(sub="repo:herrerogusano/honda-mapit-mcp:environment:prod")
    result = _validate(_jwt(legacy))
    assert result.subject_format == "legacy_environment"


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://attacker.invalid"},
        {"aud": "other-audience"},
        {"repository": "someone/else"},
        {"repository_owner": "other-owner"},
        {"repository_id": "1234568"},
        {"repository_owner_id": "1234568"},
        {"ref": "refs/heads/develop"},
        {"sha": "b" * 40},
        {"environment": "dev"},
        {"sub": "repo:herrerogusano/honda-mapit-mcp:ref:refs/heads/main"},
    ],
)
def test_claim_mismatch_fails_closed_with_no_raw_claim_echo(change) -> None:
    claims = _claims()
    claims.update(change)
    with pytest.raises(OidcClaimError) as error:
        _validate(_jwt(claims))
    assert error.value.category in {"claims_mismatch", "subject_format_unrecognized"}
    assert str(error.value) == error.value.category
    assert "attacker" not in str(error.value)


@pytest.mark.parametrize(
    ("target", "sha"),
    [("stage", SOURCE_SHA), ("prod", "A" * 40), ("prod", "a" * 39), (True, SOURCE_SHA)],
)
def test_target_and_source_are_strict(target, sha) -> None:
    with pytest.raises(OidcClaimError):
        _validate(_jwt(_claims()), target=target, source_sha=sha)


@pytest.mark.parametrize(
    "token",
    [None, "", "a.b", "a.b.c.d", "@@.@@.@@"],
)
def test_malformed_or_oversized_token_rejected(token) -> None:
    with pytest.raises(OidcClaimError) as error:
        _validate(token)
    assert error.value.category == "token_format_invalid"


def test_oversized_token_is_rejected() -> None:
    with pytest.raises(OidcClaimError) as error:
        _validate("x" * 32_769)
    assert error.value.category == "token_format_invalid"


def test_duplicate_json_claim_keys_are_rejected() -> None:
    raw_claims = json.dumps(_claims(), separators=(",", ":")).replace('"aud":"sts.amazonaws.com"', '"aud":"sts.amazonaws.com","aud":"other"').encode()
    with pytest.raises(OidcClaimError) as error:
        _validate(_jwt(raw_claims=raw_claims))
    assert error.value.category == "token_format_invalid"


def test_safe_projection_contains_only_allowed_fields() -> None:
    safe = _validate(_jwt(_claims())).safe_dict()
    assert set(safe) == {"status", "target", "source_sha", "subject_format", "subject_sha256"}
    rendered = json.dumps(safe)
    assert "1234567" not in rendered
    assert "7654321" not in rendered
    assert "repo:herrerogusano" not in rendered
    assert "sts.amazonaws.com" not in rendered
    assert "synthetic-key-id" not in rendered


def test_runner_request_adds_fixed_audience_and_performs_one_bounded_get() -> None:
    response_body = json.dumps({"value": "a" * 30}).encode()
    response = _Response(response_body)
    opener = _Opener(response)
    token = request_runner_oidc_token(
        "https://pipelines.actions.githubusercontent.com/opaque/path?api-version=2.0",
        "r" * 40,
        opener=opener,
        clock=iter((10.0, 11.0)).__next__,
    )
    assert token == "a" * 30
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url.endswith("api-version=2.0&audience=sts.amazonaws.com")
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == "Bearer " + "r" * 40
    assert timeout == 8.0
    assert response.read_sizes == [MAX_RESPONSE_BYTES + 1]


@pytest.mark.parametrize(
    "url",
    [
        "http://pipelines.actions.githubusercontent.com/token",
        "https://evilactions.githubusercontent.com/token",
        "https://user@pipelines.actions.githubusercontent.com/token",
        "https://pipelines.actions.githubusercontent.com/token?audience=bad",
        "https://pipelines.actions.githubusercontent.com/token?x=1&x=2",
        "https://pipelines.actions.githubusercontent.com/token#fragment",
    ],
)
def test_runner_endpoint_invalid_rejected_before_request(url) -> None:
    opener = _Opener(_Response(b"{}"))
    with pytest.raises(OidcClaimError) as error:
        request_runner_oidc_token(url, "r" * 40, opener=opener)
    assert error.value.category == "runner_endpoint_invalid"
    assert opener.calls == []


@pytest.mark.parametrize(
    "body",
    [b"{}", b'{"count":true,"value":"token"}', b'{"count":1,"value":"token","extra":1}'],
)
def test_runner_response_shape_and_size_fail_closed(body) -> None:
    opener = _Opener(_Response(body))
    with pytest.raises(OidcClaimError) as error:
        request_runner_oidc_token(
            "https://pipelines.actions.githubusercontent.com/token",
            "r" * 40,
            opener=opener,
            clock=iter((1.0, 2.0)).__next__,
        )
    assert error.value.category == "runner_response_invalid"
    assert len(opener.calls) == 1


def test_runner_oversized_response_is_rejected() -> None:
    opener = _Opener(_Response(b"x" * (MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(OidcClaimError) as error:
        request_runner_oidc_token(
            "https://pipelines.actions.githubusercontent.com/token",
            "r" * 40,
            opener=opener,
            clock=iter((1.0, 2.0)).__next__,
        )
    assert error.value.category == "runner_response_invalid"
    assert len(opener.calls) == 1


def test_environment_discovery_validates_ref_before_requesting_token() -> None:
    opener = _Opener(_Response(b"{}"))
    with pytest.raises(OidcClaimError) as error:
        discover_from_environment(
            {
                "TARGET": "prod",
                "SOURCE_SHA": SOURCE_SHA,
                "SOURCE_REF": "refs/heads/develop",
                "GITHUB_REF": "refs/heads/develop",
                "GITHUB_SHA": SOURCE_SHA,
                "EXPECTED_REPOSITORY_ID": REPOSITORY_ID,
                "EXPECTED_OWNER_ID": OWNER_ID,
                "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r" * 40,
            },
            opener=opener,
        )
    assert error.value.category == "invalid_source"
    assert opener.calls == []


def test_environment_discovery_returns_only_safe_projection() -> None:
    token = _jwt(_claims())
    response = _Response(json.dumps({"value": token}).encode())
    opener = _Opener(response)
    summary = discover_from_environment(
        {
            "TARGET": "prod",
            "SOURCE_SHA": SOURCE_SHA,
            "SOURCE_REF": "refs/heads/main",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": SOURCE_SHA,
            "EXPECTED_REPOSITORY_ID": REPOSITORY_ID,
            "EXPECTED_OWNER_ID": OWNER_ID,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner-secret-canary-123456",
        },
        opener=opener,
        clock=iter((20.0, 21.0)).__next__,
    )
    safe_text = json.dumps(summary.safe_dict())
    assert len(opener.calls) == 1
    assert token not in safe_text
    assert "runner-secret-canary" not in safe_text
    assert "1234567" not in safe_text
    assert summary.status == "claims_match_unverified"


def test_environment_discovery_rejects_conflicting_ref_sha_or_repository_binding_before_request() -> None:
    base = {
        "TARGET": "prod",
        "SOURCE_SHA": SOURCE_SHA,
        "SOURCE_REF": "refs/heads/main",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SOURCE_SHA,
        "EXPECTED_REPOSITORY_ID": REPOSITORY_ID,
        "EXPECTED_OWNER_ID": OWNER_ID,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "r" * 40,
    }
    for key, value in (
        ("GITHUB_REF", "refs/heads/develop"),
        ("GITHUB_SHA", "b" * 40),
        ("EXPECTED_REPOSITORY_ID", "7654322"),
        ("EXPECTED_OWNER_ID", "1234568"),
    ):
        opener = _Opener(_Response(json.dumps({"value": _jwt(_claims())}).encode()))
        env = dict(base, **{key: value})
        with pytest.raises(OidcClaimError) as error:
            discover_from_environment(env, opener=opener)
        assert error.value.category in {"invalid_source", "claims_mismatch"}
        if key in {"GITHUB_REF", "GITHUB_SHA"}:
            assert opener.calls == []
        else:
            assert len(opener.calls) == 1


def test_runner_opener_exception_is_sanitized() -> None:
    class BadOpener:
        def open(self, *_args, **_kwargs):
            raise RuntimeError("secret-canary-in-provider-error")

    with pytest.raises(OidcClaimError) as error:
        request_runner_oidc_token(
            "https://pipelines.actions.githubusercontent.com/token",
            "r" * 40,
            opener=BadOpener(),
        )
    assert error.value.category == "runner_request_failed"
    assert "secret-canary" not in repr(error.value)
    assert error.value.__cause__ is None


def test_workflow_is_target_gated_has_only_job_scoped_oidc_and_no_aws_steps() -> None:
    text = open(".github/workflows/cd-identity.yml", encoding="utf-8").read()
    assert "workflow_dispatch:" in text
    assert "dev:refs/heads/develop|prod:refs/heads/main" in text
    assert "environment:" in text
    assert "name: ${{ inputs.target }}" in text
    assert "permissions: {}" in text
    assert "id-token: write" in text
    assert "contents: read" in text
    assert "EXPECTED_REPOSITORY_ID: ${{ github.repository_id }}" in text
    assert "EXPECTED_OWNER_ID: ${{ github.repository_owner_id }}" in text
    assert "ref: ${{ github.sha }}" in text
    assert "persist-credentials: false" in text
    assert "python scripts/github_oidc_claims.py" in text
    for forbidden in ("configure-aws-credentials", "aws-actions/", "sam deploy", "upload-artifact", "id-token: write\npermissions:"):
        assert forbidden not in text
