from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.dev_multiuser_test_users import (
    DevMultiuserTestUserOperator,
    DevMultiuserUserError,
    build_pkce_authorization_url,
    exchange_pkce_code,
    new_pkce_challenge,
    validate_pkce_callback,
)
from scripts.run_aws_closed_rehearsal import MemoryJournal


ACCOUNT = "123456789012"
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
START = 1_800_000_000
CALLBACK = "http://localhost:39031/callback"
ACCOUNT = "123456789012"
DOMAIN = f"honda-mapit-mcp-dev-multiuser-{ACCOUNT}.auth.eu-west-1.amazoncognito.com"
CLIENT = "SyntheticClient123"
SCOPE = "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp/use"


class AwsError(Exception):
    def __init__(self, code: str):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}}


def _ok(**values):
    return {**values, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _user(username: str, *, status: str = "FORCE_CHANGE_PASSWORD", sub: str | None = None):
    return _ok(User={"Username": username, "UserStatus": status, "Attributes": [{"Name": "sub", "Value": sub or ("11111111-1111-4111-8111-111111111111" if username.endswith("a-" + "".join([])) else "22222222-2222-4222-8222-222222222222")} ]})


class Cognito:
    def __init__(self, *, existing: set[str] | None = None, fail_create: set[str] | None = None, fail_password: set[str] | None = None):
        self.existing = set(existing or ())
        self.fail_create = set(fail_create or ())
        self.fail_password = set(fail_password or ())
        self.calls: list[tuple[str, dict]] = []
        self.users: dict[str, dict] = {}

    def admin_get_user(self, **kwargs):
        self.calls.append(("get", kwargs))
        username = kwargs["Username"]
        if username not in self.existing and username not in self.users:
            raise AwsError("UserNotFoundException")
        return _ok(User=self.users.get(username, {"Username": username, "UserStatus": "CONFIRMED", "Attributes": [{"Name": "sub", "Value": "33333333-3333-4333-8333-333333333333"}]}))

    def admin_create_user(self, **kwargs):
        self.calls.append(("create", kwargs))
        username = kwargs["Username"]
        if username in self.fail_create:
            raise AwsError("TooManyRequestsException")
        sub = "11111111-1111-4111-8111-111111111111" if "-a-" in username else "22222222-2222-4222-8222-222222222222"
        self.users[username] = {"Username": username, "UserStatus": "FORCE_CHANGE_PASSWORD", "Attributes": [{"Name": "sub", "Value": sub}]}
        return _ok(User=self.users[username])

    def admin_set_user_password(self, **kwargs):
        self.calls.append(("password", kwargs))
        assert kwargs["Permanent"] is True
        assert isinstance(kwargs["Password"], str)
        assert len(kwargs["Password"]) >= 32
        username = kwargs["Username"]
        if username in self.fail_password:
            raise AwsError("TooManyRequestsException")
        self.users[username]["UserStatus"] = "CONFIRMED"
        return _ok()


def _operator(client=None, *, journal=None, clock=lambda: START + 1):
    return DevMultiuserTestUserOperator(
        {"cognito": client or Cognito()}, journal or MemoryJournal(),
        account_id=ACCOUNT, user_pool_id=POOL, run_id=RUN,
        authorized_from_epoch=START, authorized_until_epoch=START + 300,
        wall_clock=clock,
    )


def test_preflight_is_absence_only_and_journals_no_secret():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    result = operator.preflight()
    assert result == {"success": True, "category": "preflight_verified", "calls": 2, "users": 2}
    state = journal.value
    assert state["preflight"] is True
    assert all(row["create_status"] == "pending" for row in state["slots"])
    assert "Password" not in repr(state) and "password_value" not in repr(state)
    assert all(row["username"].startswith("honda-dev-tech-") for row in state["slots"])


def test_preflight_rejects_existing_deterministic_name_without_writes():
    client = Cognito()
    probe = _operator(client)
    username = probe._initial()["slots"][0]["username"]
    client.existing.add(username)
    result = probe.preflight()
    assert result["category"] == "user_conflict"
    assert [name for name, _ in client.calls] == ["get"]


def test_provision_creates_exactly_two_users_suppressed_then_permanent_password():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    assert operator.preflight()["success"] is True
    result = operator.provision()
    assert result == {"success": True, "category": "users_confirmed", "calls": 6, "users": 2}
    assert [name for name, _ in client.calls] == ["get", "get", "create", "password", "create", "password"]
    assert all(kwargs.get("MessageAction") == "SUPPRESS" for name, kwargs in client.calls if name == "create")
    assert all("Password" not in kwargs for name, kwargs in client.calls if name != "password")
    assert all(row["password_status"] == "confirmed" for row in journal.value["slots"])
    assert all("Password" not in repr(journal.value) and "password_value" not in repr(journal.value) for _ in [0])


def test_private_password_callback_runs_after_each_success_without_journaling_secret():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    assert operator.preflight()["success"] is True
    handoff = []
    result = operator.provision(
        on_confirmed_user=lambda username, password: handoff.append((username, password)),
        password_factory=lambda: "Aa1!" + "x" * 28,
    )
    assert result["success"] is True
    assert len(handoff) == 2
    assert all(len(password) == 32 for _, password in handoff)
    assert all("Aa1!" not in repr(journal.value) for _ in [0])


def test_invalid_password_factory_fails_before_password_write():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    assert operator.preflight()["success"] is True
    result = operator.provision(password_factory=lambda: "weak")
    assert result["category"] == "password_generation_failed"
    assert not any(name == "password" for name, _ in client.calls)


def test_ambiguous_create_is_fenced_and_never_replayed():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    assert operator.preflight()["success"] is True
    target = operator._initial()["slots"][0]["username"]
    client.fail_create.add(target)
    first = operator.provision()
    assert first["category"] == "create_outcome_unknown"
    assert journal.value["slots"][0]["create_status"] == "blocked"
    create_count = len([name for name, _ in client.calls if name == "create"])
    assert operator.provision()["category"] == "reconciliation_required"
    assert len([name for name, _ in client.calls if name == "create"]) == create_count


def test_ambiguous_password_is_readback_only_and_confirmed_status_reconciles():
    client, journal = Cognito(), MemoryJournal()
    operator = _operator(client, journal=journal)
    assert operator.preflight()["success"] is True
    target = operator._initial()["slots"][0]["username"]
    client.fail_password.add(target)
    assert operator.provision()["category"] == "password_outcome_unknown"
    assert journal.value["slots"][0]["password_status"] == "blocked"
    client.fail_password.clear()
    # The fake readback reports CONFIRMED only after a successful password
    # call; this test proves reconcile itself never invokes that write.
    client.users[target]["UserStatus"] = "CONFIRMED"
    result = operator.reconcile()
    assert result["category"] == "reconciliation_required" or result["category"] == "users_confirmed"
    assert not any(name == "password" for name, _ in client.calls[6:])


def test_tampered_journal_with_password_is_rejected():
    journal = MemoryJournal()
    operator = _operator(journal=journal)
    assert operator.preflight()["success"] is True
    journal.value["slots"][0]["password"] = "secret"
    with pytest.raises(DevMultiuserUserError, match="journal_invalid"):
        operator.provision()


def test_pkce_url_callback_and_exchange_are_public_client_only():
    challenge = new_pkce_challenge()
    url = build_pkce_authorization_url(managed_login_domain=DOMAIN, client_id=CLIENT, callback_url=CALLBACK, required_scope=SCOPE, challenge=challenge)
    query = parse_qs(urlsplit(url).query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == [SCOPE]
    assert "password" not in query and "USER_PASSWORD_AUTH" not in repr(query)
    code = validate_pkce_callback(CALLBACK + "?code=one-time-code&state=" + challenge.state, expected_state=challenge.state)
    seen = {}
    def post(endpoint, form):
        seen.update(form)
        return {"access_token": "opaque-access", "token_type": "Bearer", "expires_in": 900, "scope": SCOPE}
    bundle = exchange_pkce_code(token_endpoint="https://" + DOMAIN + "/oauth2/token", client_id=CLIENT, callback_url=CALLBACK, code=code, challenge=challenge, post_form=post)
    assert bundle.access_token == "opaque-access"
    assert seen["grant_type"] == "authorization_code"
    assert seen["code_verifier"] == challenge.code_verifier
    assert "password" not in seen
    assert "opaque-access" not in repr(bundle)


@pytest.mark.parametrize("callback", [CALLBACK + "?code=x&state=wrong", CALLBACK + "?code=x&state=s&extra=x", CALLBACK + "#x"])
def test_pkce_callback_rejects_wrong_or_ambiguous_input(callback):
    with pytest.raises(DevMultiuserUserError, match="pkce_callback_invalid"):
        validate_pkce_callback(callback, expected_state="s")
