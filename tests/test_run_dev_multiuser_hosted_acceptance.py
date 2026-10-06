from __future__ import annotations

from pathlib import Path
from dataclasses import replace

import pytest
import base64
import hashlib
import json
from collections import OrderedDict
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.dev_multiuser_managed_login import HttpResponse
from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
from scripts.run_dev_multiuser_hosted_acceptance import (
    HostedAcceptanceError,
    HostedAcceptanceInputs,
    _poll_update,
    _tenant_write,
    _derive_user_window,
    _validate_full_role_bindings,
    _strict_template_body,
    _validate_bucket_encryption,
    _exact_tag_set,
    fetch_public_jwks,
    run_hosted_acceptance,
)
from scripts.run_aws_closed_rehearsal import FileJournal


ACCOUNT = "123456789012"
KEY = "tenant-" + "a" * 64
AUTH = {
    "account": ACCOUNT, "source_sha": "a" * 40, "run_id": 2026100601,
    "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator",
    "start": 1_900_000_000, "end": 1_900_003_600, "ci_run_id": 123,
}


def _private_inputs(tmp_path: Path) -> HostedAcceptanceInputs:
    root = tmp_path / "private"
    root.mkdir()
    auth_path = root / "authorization.json"
    write_private_authorization(auth_path, AUTH, acl_checker=lambda _path: True)
    return HostedAcceptanceInputs(
        authorization_path=auth_path, private_root=root,
        app_binding_path=root / "app.json", roles_binding_path=root / "roles.json",
        controls_binding_path=root / "controls.json", role_bindings_path=root / "role-bindings.json",
        wheel_dir=tmp_path / "wheels",
    )


def test_source_gate_runs_before_client_factory_or_private_bindings(tmp_path):
    inputs = _private_inputs(tmp_path)
    called = []

    def source_gate(_auth):
        raise HostedAcceptanceError("source_verification_failed")

    result = run_hosted_acceptance(
        inputs, source_verifier=source_gate,
        clients_factory=lambda: called.append(True) or {},
        acl_checker=lambda _path: True,
    )
    assert result == {"success": False, "category": "source_verification_failed"}
    assert called == []


@pytest.mark.parametrize("flags", [
    {"allow_confirmed_pair_password_resets": True},
    {"allow_confirmed_pair_password_resets": "yes"},
    {"allow_confirmed_pair_password_resets": True, "allow_single_a_password_reset": True},
    {"confirmed_user_journal_path": Path("absent")},
])
def test_pair_recovery_requires_exact_explicit_inputs_before_clients(tmp_path, flags):
    called = []
    result = run_hosted_acceptance(replace(_private_inputs(tmp_path), **flags), source_verifier=lambda _: None,
                                   clients_factory=lambda: called.append(True) or {}, acl_checker=lambda _: True)
    assert result == {"success": False, "category": "bindings_invalid"}
    assert not called


def test_login_failure_diagnostics_are_allowlisted_and_redacted():
    failure = HostedAcceptanceError(
        "user_provision_failed", stage="token_post", login_category="token_invalid",
        login_reason="scope_missing_required",
    )
    assert failure.category == "user_provision_failed"
    assert failure.stage == "token_post"
    assert failure.login_category == "token_invalid"
    assert failure.login_reason == "scope_missing_required"
    unsafe = HostedAcceptanceError(
        "user_provision_failed", stage="https://private.example/cookie", login_category="raw-secret"
    )
    assert unsafe.stage is None
    assert unsafe.login_category is None
    assert unsafe.login_reason is None


class _DynamoMemory:
    def __init__(self):
        self.item = None

    def get_item(self, **request):
        result = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.item is not None:
            result["Item"] = dict(self.item)
        return result

    def put_item(self, **request):
        if self.item is not None:
            class Conflict(Exception):
                response = {"Error": {"Code": "ConditionalCheckFailedException"}, "ResponseMetadata": {"HTTPStatusCode": 400}}
            raise Conflict()
        self.item = dict(request["Item"])
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def test_tenant_write_is_intent_then_strong_readback_and_redacted(tmp_path):
    from mapit.aws_durable_tenants import DynamoDBTenantStore

    client = _DynamoMemory()
    store = DynamoDBTenantStore(
        client,
        table_arn=f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
        allowed_keys=(KEY,), writer=client,
    )
    journal_dir = tmp_path / "journal"
    journal_dir.mkdir()
    assert _tenant_write(store, FileJournal(journal_dir), KEY) is True
    state = FileJournal(journal_dir).load()
    assert state["phase"] == "committed"
    assert store.get(KEY).status == "active"


def test_poll_update_has_fixed_30_attempt_bound():
    calls = []
    now = [0]

    def call(step):
        calls.append(step)
        return {"success": True, "category": "pending"}

    assert _poll_update(call, sleep=lambda _seconds: None, clock=lambda: now[0], deadline=100) is False
    assert calls[0] == "request-update"
    assert calls[1:] == ["check-update"] * 30


def test_jwks_fetch_rejects_redirect_or_wrong_url_without_persisting():
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_A1b2C3d4E/.well-known/jwks.json"

    def transport(*_args):
        return HttpResponse(200, "https://evil.example/jwks", {}, b"{}")

    with pytest.raises(HostedAcceptanceError, match="^jwks_fetch_failed$"):
        fetch_public_jwks(user_pool_id="eu-west-1_A1b2C3d4E", transport=transport)


def _jwk(private):
    numbers = private.public_key().public_numbers()
    def b64(value):
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return {"kty": "RSA", "kid": "dev-key", "use": "sig", "alg": "RS256", "n": b64(numbers.n), "e": b64(numbers.e)}


def test_jwks_fetch_accepts_exact_bounded_http_response():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    body = json.dumps({"keys": [_jwk(private)]}, separators=(",", ":")).encode("ascii")
    expected = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_A1b2C3d4E/.well-known/jwks.json"

    def transport(*_args):
        return HttpResponse(200, expected, {}, body)

    result, digest = fetch_public_jwks(user_pool_id="eu-west-1_A1b2C3d4E", transport=transport)
    assert result == body
    assert digest == hashlib.sha256(body).hexdigest()


def test_user_window_is_separate_and_never_exceeds_five_minutes():
    start, end = _derive_user_window(AUTH["start"] + 10, AUTH["start"], AUTH["end"])
    assert (start, end) == (AUTH["start"] + 10, AUTH["start"] + 310)
    assert end - start <= 300


def test_role_binding_uses_application_stack_not_cd_delivery_stack():
    values = {
        "account_id": ACCOUNT,
        "provider_arn": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
        "owner_id": "1234567", "repository_id": "7654321",
        "observed_dev_subject_format": "immutable_environment",
        "observed_dev_subject_sha256": hashlib.sha256(b"repo:herrerogusano@1234567/honda-mapit-mcp@7654321:environment:dev").hexdigest(),
        "stack_arn": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555",
        "artifact_stack_arn": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666",
        "handler_arn": "arn:aws:lambda:eu-west-1:123456789012:function:honda-mapit-mcp-dev-retained-handler",
        "api_arn": "arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
        "shutdown_state_machine_arn": "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-dev-retained-shutdown",
        "artifact_bucket_arn": "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        "execution_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-handler-role",
    }
    assert _validate_full_role_bindings(values, account=ACCOUNT)["stack_arn"] == values["stack_arn"]


def test_template_body_accepts_sdk_string_and_ordered_mapping_shapes():
    expected = {"Resources": {"McpApi": {"Type": "AWS::ApiGatewayV2::Api"}}}
    assert _strict_template_body(json.dumps(expected, separators=(",", ":"))) == expected
    assert _strict_template_body(OrderedDict([("Resources", OrderedDict([("McpApi", OrderedDict([("Type", "AWS::ApiGatewayV2::Api")]))]))])) == expected


def test_template_body_rejects_duplicate_or_nonfinite_json():
    with pytest.raises(HostedAcceptanceError, match="^delivery_preflight_failed$"):
        _strict_template_body('{"Resources":{},"Resources":{}}')
    with pytest.raises(HostedAcceptanceError, match="^delivery_preflight_failed$"):
        _strict_template_body('{"Resources":{"x":NaN}}')


def test_bucket_encryption_accepts_real_sdk_optional_closed_controls():
    assert _validate_bucket_encryption({
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
            "BucketKeyEnabled": False,
            "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]},
        }]
    }) is True
    assert _validate_bucket_encryption({
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    }) is True


@pytest.mark.parametrize("value", [
    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True}]},
    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BlockedEncryptionTypes": {"EncryptionType": ["SSE-KMS"]}}]},
    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "Unexpected": False}]},
    {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": 0}]},
])
def test_bucket_encryption_rejects_unsafe_or_unknown_variants(value):
    assert _validate_bucket_encryption(value) is False


def test_bucket_tag_set_is_exact_but_order_insensitive():
    expected = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev-artifacts"},
        {"Key": "OperatorRunId", "Value": "2026100601"},
        {"Key": "aws:cloudformation:stack-id", "Value": "stack"},
        {"Key": "aws:cloudformation:stack-name", "Value": "name"},
        {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"},
    ]
    assert _exact_tag_set(list(reversed(expected)), expected) is True
    for bad in (
        expected[:-1],
        expected + [{"Key": "extra", "Value": "x"}],
        [*expected[:-1], {"Key": "Project", "Value": "honda-mapit-mcp"}],
        [*expected[:-1], {"Key": "foreign", "Value": "x"}],
    ):
        assert _exact_tag_set(bad, expected) is False
