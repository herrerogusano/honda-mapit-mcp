import pytest

from mapit.aws_enrollment_clients import EnrollmentClientError, create_enrollment_clients


def test_explicit_factory_no_network_and_same_pair_fresh_sts(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("network forbidden"))
    clients = []
    original = boto3.session.Session.client
    def capture(self, *args, **kwargs):
        assert kwargs["aws_access_key_id"] == "synthetic-access"
        assert kwargs["aws_secret_access_key"] == "synthetic-secret"
        assert kwargs["aws_session_token"] == "synthetic-session"
        result = original(self, *args, **kwargs)
        clients.append(result)
        return result
    monkeypatch.setattr(boto3.session.Session, "client", capture)
    pair = create_enrollment_clients(access_key="synthetic-access", secret_key="synthetic-secret",
        session_token="synthetic-session", deadline=110, monotonic=lambda: 100)
    assert len(clients) == 2
    assert pair.ssm is clients[0]
    assert not pair.account_verifier(object(), "123456789012")
    with Stubber(clients[1]) as stub:
        stub.add_response("get_caller_identity", {"Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/enrollment/operator", "UserId": "synthetic:user",
            "ResponseMetadata": {"HTTPStatusCode": 200}}, {})
        assert pair.account_verifier(pair.ssm, "123456789012") is True
        assert pair.account_verifier(pair.ssm, "123456789012") is False
        stub.assert_no_pending_responses()
    assert "synthetic-secret" not in repr(pair)


@pytest.mark.parametrize("case", ["account", "root", "http", "deadline", "error"])
def test_sts_failure_is_closed_and_not_retried(monkeypatch, case):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    clients = []
    original = boto3.session.Session.client
    def capture(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        clients.append(result)
        return result
    monkeypatch.setattr(boto3.session.Session, "client", capture)
    now = [100]
    pair = create_enrollment_clients(access_key="synthetic-access", secret_key="synthetic-secret",
        session_token="synthetic-session", deadline=110, monotonic=lambda: now[0])
    with Stubber(clients[1]) as stub:
        if case == "error":
            stub.add_client_error("get_caller_identity", "AccessDenied", "private-canary", expected_params={})
        elif case != "deadline":
            stub.add_response("get_caller_identity", {"Account": "999999999999" if case == "account" else "123456789012",
                "Arn": "arn:aws:iam::123456789012:root" if case == "root" else "arn:aws:sts::123456789012:assumed-role/enrollment/operator",
                "UserId": "synthetic:user", "ResponseMetadata": {"HTTPStatusCode": 403 if case == "http" else 200}}, {})
        else:
            now[0] = 110
        assert pair.account_verifier(pair.ssm, "123456789012") is False
        assert pair.account_verifier(pair.ssm, "123456789012") is False
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("changes", [{"session_token": ""}, {"secret_key": "canary\n"}, {"deadline": True}, {"deadline": 120}, {"deadline": float("nan")}])
def test_invalid_configuration_is_redacted_and_precedes_sdk(changes):
    fields = dict(access_key="synthetic-access", secret_key="synthetic-secret",
                  session_token="synthetic-session", deadline=110, monotonic=lambda: 100)
    fields.update(changes)
    with pytest.raises(EnrollmentClientError, match="^enrollment_client_invalid$"):
        create_enrollment_clients(**fields)


def test_dynamodb_and_ssm_verifiers_share_explicit_credentials_but_are_independent(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber
    clients = []
    original = boto3.session.Session.client
    def capture(self, *args, **kwargs):
        assert kwargs["aws_session_token"] == "synthetic-session"
        result = original(self, *args, **kwargs)
        clients.append(result)
        return result
    monkeypatch.setattr(boto3.session.Session, "client", capture)
    pair = create_enrollment_clients(access_key="synthetic-access", secret_key="synthetic-secret",
        session_token="synthetic-session", deadline=110, monotonic=lambda: 100, include_dynamodb=True)
    assert len(clients) == 3 and pair.dynamodb is clients[2]
    assert not pair.dynamodb_account_verifier(pair.ssm, "123456789012")
    with Stubber(clients[1]) as stub:
        for _ in range(2):
            stub.add_response("get_caller_identity", {"Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/enrollment/operator", "UserId": "synthetic:user",
                "ResponseMetadata": {"HTTPStatusCode": 200}}, {})
        assert pair.dynamodb_account_verifier(pair.dynamodb, "123456789012") is True
        assert pair.account_verifier(pair.ssm, "123456789012") is True
        assert pair.dynamodb_account_verifier(pair.dynamodb, "123456789012") is False
        stub.assert_no_pending_responses()
