import asyncio

import pytest

from mapit.aws_enrollment_clients import EnrollmentAwsClients
from mapit.cloud_enrollment import CloudEnrollmentFactory, EnrollmentCredentials
from mapit.private_enrollment import PrivateEnrollmentChannel
from test_aws_identity_binding import _DynamoDocument
from test_aws_identity_binding_publisher import Client
from test_identity_binding import NOW, TOKEN_A
from test_private_enrollment import form, request, setup_channel


def test_lazy_cloud_composition_after_signed_form_submission(tmp_path, monkeypatch):
    _, token, _, _, old_registry, authority, guard = setup_channel(tmp_path)
    # Reuse the exact registry's bound test configuration/verifier/transport.
    db, ssm, calls = _DynamoDocument(), Client(), []
    now = [100.0]
    def credentials():
        calls.append("credentials")
        return EnrollmentCredentials("synthetic-access", "synthetic-secret", "synthetic-session")
    def clients(**kwargs):
        calls.append(kwargs)
        assert kwargs["include_dynamodb"] is True
        assert kwargs["deadline"] == 314
        return EnrollmentAwsClients(ssm, lambda client, account: client is ssm and account == "123456789012",
                                    db, lambda client, account: client is db and account == "123456789012")
    monkeypatch.setattr("mapit.cloud_enrollment.create_enrollment_clients", clients)
    factory = CloudEnrollmentFactory(authority=authority, durable_guard=guard,
        environment="dev", account_id="123456789012", config=old_registry.config,
        verifier=old_registry.verifier, binding_key=b"b" * 32,
        auth_transport=old_registry._auth_transport, clock=lambda: NOW,
        credentials_supplier=credentials, monotonic=lambda: now[0])
    channel = PrivateEnrollmentChannel(authority=authority, durable_guard=guard,
        enrollment_factory=factory, port=8787, deadline=500, monotonic=lambda: now[0])
    body = form(channel, token)
    assert calls == [] and db.get_calls == [] and ssm.calls == []
    # User takes 200 seconds reading the form. The cloud lease is still fresh.
    now[0] = 300
    response = request(channel, body=body, method="POST", target="/enroll")
    assert response.status == 200
    assert len(db.put_calls) == 3
    assert [operation for operation, _ in ssm.calls] == ["put", "get"]
    assert TOKEN_A not in repr(factory) and "synthetic-secret" not in repr(credentials())
    assert token.encode() not in response.body


def test_unauthorized_factory_never_obtains_credentials(tmp_path):
    _, token, _, _, registry, authority, guard = setup_channel(tmp_path)
    calls = []
    factory = CloudEnrollmentFactory(authority=authority, durable_guard=guard,
        environment="dev", account_id="123456789012", config=registry.config,
        verifier=registry.verifier, binding_key=b"b" * 32, auth_transport=registry._auth_transport,
        clock=lambda: NOW, credentials_supplier=lambda: calls.append("forbidden"), monotonic=lambda: 100)
    grant = asyncio.run(authority.authenticate(token))
    snapshot = guard.capture(grant)
    authority.revoke(grant.key)
    with pytest.raises(ValueError, match="^cloud_enrollment_configuration_invalid$"):
        factory(grant=grant, snapshot=snapshot, deadline=110)
    assert calls == []


def test_cloud_factory_cannot_target_production(tmp_path):
    _, _, _, _, registry, authority, guard = setup_channel(tmp_path)
    with pytest.raises(ValueError, match="^cloud_enrollment_configuration_invalid$"):
        CloudEnrollmentFactory(authority=authority, durable_guard=guard,
            environment="prod", account_id="123456789012", config=registry.config,
            verifier=registry.verifier, binding_key=b"b" * 32, auth_transport=registry._auth_transport,
            clock=lambda: NOW, credentials_supplier=lambda: None)
