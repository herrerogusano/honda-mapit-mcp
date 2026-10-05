"""Independent stage/category and cleanup regressions using synthetic clients only."""

from copy import deepcopy
from datetime import timedelta
import json

import pytest

from scripts import run_github_sts_identity as runner
from test_run_github_sts_identity import (
    ACCOUNT,
    NOW,
    FakeSts,
    _env,
    _sdk_replies,
    _token,
)


class _CanarySts(FakeSts):
    def __init__(self, *, assume=None, caller=None, assume_error=False, caller_error=False):
        super().__init__(assume=assume, caller=caller)
        self.assume_error = assume_error
        self.caller_error = caller_error

    def assume_role_with_web_identity(self, **kwargs):
        if self.assume_error:
            self.calls.append(("assume", kwargs))
            raise RuntimeError("synthetic-assume-secret-canary")
        return super().assume_role_with_web_identity(**kwargs)

    def get_caller_identity(self):
        if self.caller_error:
            self.calls.append(("caller", {}))
            raise RuntimeError("synthetic-caller-secret-canary")
        return super().get_caller_identity()


def _run_failure(monkeypatch, tmp_path, stage):
    token_calls = []
    factory_calls = []
    clients = []
    assume, caller = _sdk_replies()
    assume = deepcopy(assume)
    caller = deepcopy(caller)

    if stage == "assume_role_response_validation":
        assume["Provider"] = "https://synthetic.invalid"
    elif stage == "credential_validation":
        assume["Credentials"]["Expiration"] = NOW - timedelta(seconds=1)
    elif stage == "caller_identity_response_validation":
        caller["Account"] = "000000000000"

    def request_token(*_args, **_kwargs):
        token_calls.append(1)
        if stage == "oidc_token_acquisition":
            raise runner.OidcClaimError("runner_request_failed")
        return _token()

    monkeypatch.setattr(runner, "request_runner_oidc_token", request_token)

    def client_factory(*, unsigned, credentials=None):
        factory_calls.append((unsigned, deepcopy(credentials)))
        if stage == "unsigned_client_creation" and unsigned:
            raise RuntimeError("synthetic-unsigned-client-secret-canary")
        if stage == "signed_client_creation" and not unsigned:
            raise RuntimeError("synthetic-signed-client-secret-canary")
        client = _CanarySts(
            assume=assume,
            caller=caller,
            assume_error=stage == "assume_role_exchange",
            caller_error=stage == "caller_identity_exchange",
        )
        clients.append(client)
        return client

    environment = _env()
    if stage == "claims_validation":
        environment.update({
            "TARGET": "prod",
            "GITHUB_REF": "refs/heads/main",
            "AWS_CD_IDENTITY_ROLE_ARN": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-cd",
        })
    with pytest.raises(runner.RunnerProofError) as raised:
        runner.run_identity_proof(
            environment,
            home=tmp_path / "clean",
            client_factory=client_factory,
            clock=lambda: NOW,
        )
    return raised.value, token_calls, factory_calls, clients


@pytest.mark.parametrize(("stage", "category", "factory_count", "method"), [
    ("oidc_token_acquisition", "runner_request_failed", 0, None),
    ("claims_validation", "claims_mismatch", 1, None),
    ("unsigned_client_creation", "sts_client_creation_failed", 1, None),
    ("assume_role_exchange", "sts_exchange_failed", 1, "assume"),
    ("assume_role_response_validation", "identity_mismatch", 1, "assume"),
    ("credential_validation", "credentials_invalid", 1, "assume"),
    ("signed_client_creation", "sts_client_creation_failed", 2, "assume"),
    ("caller_identity_exchange", "sts_exchange_failed", 2, "both"),
    ("caller_identity_response_validation", "identity_mismatch", 2, "both"),
])
def test_each_failure_stage_is_categorical_bounded_and_closes_created_clients(
    monkeypatch, tmp_path, stage, category, factory_count, method
):
    error, token_calls, factory_calls, clients = _run_failure(monkeypatch, tmp_path, stage)

    assert error.safe_dict() == {"status": "failed", "category": category, "stage": stage}
    assert len(factory_calls) == factory_count
    assert all(client.closed for client in clients)
    assert all("secret-canary" not in repr(client.calls) for client in clients)
    assert token_calls == [1]
    if method == "assume":
        assert [name for name, _ in clients[0].calls] == ["assume"]
    elif method == "both":
        assert [name for name, _ in clients[0].calls] == ["assume"]
        assert [name for name, _ in clients[1].calls] == ["caller"]
    else:
        assert all(client.calls == [] for client in clients)
    assert "canary" not in json.dumps(error.safe_dict())


def test_main_canary_errors_serialize_only_safe_fallback(capsys, monkeypatch):
    error = runner.RunnerProofError("claims_mismatch", stage="claims_validation")
    error.category = "sts_exchange_failed"
    error.stage = ["synthetic-stage-canary"]
    monkeypatch.setattr(runner, "run_identity_proof", lambda _environment: (_ for _ in ()).throw(error))

    assert runner.main() == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "status": "failed", "category": "proof_failed", "stage": "proof_internal"
    }
    assert "synthetic-stage-canary" not in output.out
    assert "claims_mismatch" not in output.out
    assert "sts_exchange_failed" not in output.out

    monkeypatch.setattr(
        runner,
        "run_identity_proof",
        lambda _environment: (_ for _ in ()).throw(RuntimeError("synthetic-secret-canary")),
    )
    assert runner.main() == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "status": "failed", "category": "proof_failed", "stage": "proof_internal"
    }
    assert "synthetic-secret-canary" not in output.out
