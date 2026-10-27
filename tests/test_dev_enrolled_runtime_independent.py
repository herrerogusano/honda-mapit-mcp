"""Independent request-boundary holdouts for the opt-in DEV runtime."""
from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from types import SimpleNamespace

import jwt
import pytest

from mapit import aws_dev_enrolled_entrypoint as entry
from mapit.aws_enrollment_clients import EnrollmentAwsClients
from mapit.tenant_router import TenantIsolationError
from test_aws_dev_enrolled_entrypoint import KEY_PATH, handler_setup
from test_invited_dev_lambda import _call, _event, _token


def test_wrong_signed_subject_is_rejected_before_resource_loader_or_aws(handler_setup):
    setup = handler_setup
    prior_reads = len(setup.db.get_calls)
    now = int(time.time())
    wrong_subject = jwt.encode({
        "iss": setup.a.issuer_url,
        "aud": setup.a.audience,
        "sub": "00000000-0000-4000-8000-000000000999",
        "client_id": setup.a.client_id,
        "token_use": "access",
        "iat": now - 1,
        "exp": now + 120,
        "scope": setup.a.required_scope,
    }, setup.private, algorithm="RS256", headers={"kid": "dev-key"})

    try:
        result = asyncio.run(_call(setup.runtime, setup.a, wrong_subject))
    except Exception:
        # The SDK may surface the expected authorization rejection during
        # initialize instead of returning a tool-level error object.
        result = None

    assert result is None or result.is_error
    assert setup.calls == []
    assert len(setup.db.get_calls) == prior_reads


def test_latest_config_version_drift_blocks_decrypted_key_and_business_calls(handler_setup, monkeypatch):
    setup = handler_setup
    original_clients = entry._clients

    def clients(deadline):
        aws = original_clients(deadline)
        original_get = aws.ssm.get_parameter

        def get_parameter(*, Name, WithDecryption):
            response = original_get(Name=Name, WithDecryption=WithDecryption)
            if Name == KEY_PATH and WithDecryption is False:
                response["Parameter"]["Version"] = 2
            return response

        aws.ssm.get_parameter = get_parameter
        return aws

    monkeypatch.setattr(entry, "_clients", clients)
    result = asyncio.run(_call(setup.runtime, setup.a, _token(setup.private, setup.a)))

    assert result.is_error
    ssm_calls = [call for call in setup.calls if call[0] == "ssm"]
    assert ssm_calls == [("ssm", KEY_PATH, False)]
    assert not any(call[0] == "business" for call in setup.calls)


def test_wrong_runtime_account_proof_stops_before_authorization_table_read(handler_setup, monkeypatch):
    setup = handler_setup
    prior_reads = len(setup.db.get_calls)
    original_clients = entry._clients

    def clients(deadline):
        aws = original_clients(deadline)
        return EnrollmentAwsClients(aws.ssm, aws.account_verifier, aws.dynamodb,
                                    lambda _client, _account: False)

    monkeypatch.setattr(entry, "_clients", clients)
    result = asyncio.run(_call(setup.runtime, setup.a, _token(setup.private, setup.a)))

    assert result.is_error
    assert len(setup.db.get_calls) == prior_reads
    assert not any(call[0] in {"ssm", "business"} for call in setup.calls)


def test_config_publication_timestamp_outside_pinned_window_never_decrypts(handler_setup, monkeypatch):
    setup = handler_setup
    original_clients = entry._clients

    def clients(deadline):
        aws = original_clients(deadline)
        original_get = aws.ssm.get_parameter

        def get_parameter(*, Name, WithDecryption):
            response = original_get(Name=Name, WithDecryption=WithDecryption)
            if Name == KEY_PATH and WithDecryption is False:
                response["Parameter"]["LastModifiedDate"] = setup_now + timedelta(seconds=3600)
            return response

        aws.ssm.get_parameter = get_parameter
        return aws

    from test_identity_binding import NOW as setup_now
    monkeypatch.setattr(entry, "_clients", clients)
    result = asyncio.run(_call(setup.runtime, setup.a, _token(setup.private, setup.a)))

    assert result.is_error
    assert [call for call in setup.calls if call[0] == "ssm"] == [("ssm", KEY_PATH, False)]
    assert not any(call[0] == "business" for call in setup.calls)


def test_warm_environment_binding_cannot_be_rearmed_after_first_request(handler_setup, monkeypatch):
    setup = handler_setup
    result = asyncio.run(_call(setup.runtime, setup.a, _token(setup.private, setup.a)))
    assert not result.is_error
    prior_calls = len(setup.calls)
    old_end = int(__import__("os").environ["MAPIT_DEV_EXECUTION_END_EPOCH"])
    monkeypatch.setenv("MAPIT_DEV_EXECUTION_END_EPOCH", str(old_end + 1))

    denied = entry.handler({}, type("Context", (), {
        "get_remaining_time_in_millis": lambda self: 30_000,
    })())

    assert denied["statusCode"] == 503
    assert len(setup.calls) == prior_calls


def test_authorization_reader_refuses_client_construction_without_full_lease(monkeypatch):
    from mapit.aws_dev_enrolled_entrypoint import _AuthorizationReader

    clock = [10.0]
    monkeypatch.setattr(entry, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    constructed = []
    monkeypatch.setattr(entry, "_clients", lambda deadline: constructed.append(deadline))
    reader = _AuthorizationReader("123456789012", 17.0)

    with pytest.raises(ValueError, match="runtime_unavailable"):
        reader.get_item(Key={"key": {"S": "fixed"}})

    assert constructed == []


def test_late_sts_verification_does_not_dispatch_authorization_getitem(monkeypatch):
    from mapit.aws_dev_enrolled_entrypoint import _AuthorizationReader

    clock = [10.0]
    deadline = 30.0
    monkeypatch.setattr(entry, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    db = SimpleNamespace(reads=[])
    db.get_item = lambda **request: db.reads.append(request)

    def verify(_client, _account):
        clock[0] = deadline - 3.5
        return True

    clients = EnrollmentAwsClients(object(), lambda _c, _a: True, db, verify)
    constructed = []
    monkeypatch.setattr(entry, "_clients", lambda received_deadline: (constructed.append(received_deadline), clients)[1])
    reader = _AuthorizationReader("123456789012", deadline)

    with pytest.raises(ValueError, match="runtime_unavailable"):
        reader.get_item(Key={"key": {"S": "fixed"}})

    assert constructed == [deadline]
    assert db.reads == []


def test_reused_authorization_reader_rechecks_lease_before_each_getitem(monkeypatch):
    from mapit.aws_dev_enrolled_entrypoint import _AuthorizationReader

    clock = [10.0]
    deadline = 30.0
    monkeypatch.setattr(entry, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    db = SimpleNamespace(reads=[])
    db.get_item = lambda **request: (db.reads.append(request), {"Item": {"fixed": True}})[1]
    clients = EnrollmentAwsClients(object(), lambda _c, _a: True, db,
                                   lambda _client, _account: True)
    constructed = []
    monkeypatch.setattr(entry, "_clients", lambda received_deadline: (constructed.append(received_deadline), clients)[1])
    reader = _AuthorizationReader("123456789012", deadline)

    assert reader.get_item(Key={"key": {"S": "one"}}) == {"Item": {"fixed": True}}
    clock[0] = deadline - 3.5
    with pytest.raises(ValueError, match="runtime_unavailable"):
        reader.get_item(Key={"key": {"S": "two"}})

    assert constructed == [deadline]
    assert len(db.reads) == 1


def test_bounded_resource_client_checks_lease_before_and_after_read(monkeypatch):
    from mapit.aws_dev_enrolled_entrypoint import _BoundedReadClient

    clock = [6.0]
    deadline = 10.0
    monkeypatch.setattr(entry, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    wire = SimpleNamespace(meta=object(), reads=[])

    def get_item(**request):
        wire.reads.append(request)
        clock[0] = deadline
        return {"Item": {"must-not-escape": True}}

    wire.get_item = get_item
    bounded = _BoundedReadClient(wire, deadline)
    with pytest.raises(ValueError, match="runtime_unavailable"):
        bounded.get_item(Key={"key": {"S": "fixed"}})
    assert wire.reads == []

    clock[0] = 5.0
    with pytest.raises(ValueError, match="runtime_unavailable"):
        bounded.get_item(Key={"key": {"S": "fixed"}})
    assert len(wire.reads) == 1


def test_request_check_captured_by_real_contextual_factory_expires_after_response(
    handler_setup, monkeypatch,
):
    from mapit.dev_enrolled_runtime import DevEnrolledProviderFactory

    setup = handler_setup
    captured = []
    original = DevEnrolledProviderFactory.__call__

    def capture(self, **context):
        captured.append(context["request_check"])
        return original(self, **context)

    monkeypatch.setattr(DevEnrolledProviderFactory, "__call__", capture)
    result = asyncio.run(_call(setup.runtime, setup.a, _token(setup.private, setup.a)))

    assert not result.is_error
    assert len(captured) == 1
    with pytest.raises(TenantIsolationError):
        captured[0]()


def test_insufficient_lambda_budget_never_constructs_aws_clients(handler_setup):
    setup = handler_setup
    event = _event(setup.a, _token(setup.private, setup.a), {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "holdout", "version": "1"}},
    })
    response = setup.runtime.handler(event, type("Context", (), {
        "get_remaining_time_in_millis": lambda self: 1000,
    })())

    assert response["statusCode"] == 503
    assert setup.calls == []
