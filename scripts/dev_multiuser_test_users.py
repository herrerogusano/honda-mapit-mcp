"""Bounded private operator for two retained-dev Cognito test users.

This module is deliberately injectable and does not construct an AWS client.
It creates exactly two administrator-managed technical users only when a
future private runner supplies a Cognito client and an approved journal.  A
password exists only in the stack frame containing the single
``AdminSetUserPassword`` call; it is never returned, logged, or journaled.

The OAuth helpers prepare a public-client authorization-code + PKCE browser
flow.  They do not open a browser, call Cognito, retain tokens, or fall back
to ``USER_PASSWORD_AUTH``.  A private runner may inject its one HTTPS form
exchange after a human/GUI callback.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import base64
import hashlib
import json
import math
import re
import secrets
import string
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit


REGION = "eu-west-1"
MAX_USERS = 2
MAX_CALLS = 24
MAX_AUTHORITY_SECONDS = 300
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_RUN = re.compile(r"[1-9][0-9]{0,19}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_DOMAIN = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\.auth\.eu-west-1\.amazoncognito\.com\Z")
_RESOURCE = re.compile(r"https://[a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com/mcp\Z")
_SCOPE = re.compile(r"https://[a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com/mcp/use\Z")
_CALLBACK = re.compile(r"http://localhost:[1-9][0-9]{2,5}/[A-Za-z0-9._~/-]+\Z")
_STATUSES = {"pending", "intent", "created", "reconciled", "confirmed", "blocked"}
_PASSWORD_STATUSES = {"not_started", "intent", "confirmed", "reconciled", "blocked"}


class DevMultiuserUserError(ValueError):
    """Stable category only; never includes usernames, IDs, or AWS text."""

    _ALLOWED = frozenset({
        "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid",
        "window_expired", "call_budget_exhausted", "preflight_required",
        "preflight_failed", "user_conflict", "create_intent_present",
        "create_outcome_unknown", "password_outcome_unknown", "user_readback_mismatch",
        "reconciliation_required", "users_confirmed", "login_failed", "pkce_configuration_invalid",
        "pkce_callback_invalid", "pkce_exchange_invalid", "password_generation_failed",
    })

    def __init__(self, category: str):
        self.category = category if category in self._ALLOWED else "journal_invalid"
        super().__init__(self.category)


def _fail(category: str) -> None:
    raise DevMultiuserUserError(category)


def _ok(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    metadata = value.get("ResponseMetadata")
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _error_code(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return code if type(code) is str and len(code) <= 128 else None


def _not_found(exc: BaseException) -> bool:
    return _error_code(exc) in {"UserNotFoundException", "ResourceNotFoundException"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _validate_url(value: Any, *, callback: bool = False) -> str:
    pattern = _CALLBACK if callback else _DOMAIN
    if type(value) is not str or len(value.encode("utf-8")) > 512 or pattern.fullmatch(value) is None:
        _fail("pkce_configuration_invalid")
    return value


def _validate_managed_domain(value: Any) -> str:
    if type(value) is not str or _DOMAIN.fullmatch(value) is None or re.fullmatch(r"honda-mapit-mcp-dev-multiuser-[0-9]{12}\.auth\.eu-west-1\.amazoncognito\.com", value) is None:
        _fail("pkce_configuration_invalid")
    return value


def _username(run_id: str, slot: str) -> str:
    digest = hashlib.sha256(f"honda-mapit-mcp-dev-users\0{run_id}".encode("ascii")).hexdigest()
    return f"honda-dev-tech-{slot.lower()}-{digest[:16]}"


def _token(account: str, pool: str, run_id: str, slot: str, operation: str) -> str:
    return hashlib.sha256(f"{account}\0{pool}\0{run_id}\0{slot}\0{operation}".encode("ascii")).hexdigest()


def _slot(*, account: str, pool: str, run_id: str, slot: str) -> dict[str, Any]:
    return {
        "slot": slot, "username": _username(run_id, slot),
        "create_status": "pending", "create_intent": None,
        "password_status": "not_started", "password_intent": None,
        "user_sub_sha256": None,
    }


def _base(*, account: str, pool: str, run_id: str, binding_sha256: str,
          start: int, end: int) -> dict[str, Any]:
    return {
        "schema": 1, "kind": "retained-dev-multiuser-test-users", "revision": 0,
        "account_id": account, "user_pool_id": pool, "run_id": run_id,
        "binding_sha256": binding_sha256, "authorized_from_epoch": start,
        "authorized_until_epoch": end, "preflight": False,
        "slots": [_slot(account=account, pool=pool, run_id=run_id, slot=slot) for slot in ("A", "B")],
    }


def _intent(value: Any, *, operation: str, expected: str) -> bool:
    return isinstance(value, Mapping) and set(value) == {"operation", "token"} and value.get("operation") == operation and value.get("token") == expected


def _validate_state(value: Any, *, account: str, pool: str, run_id: str,
                    binding_sha256: str, start: int, end: int) -> dict[str, Any]:
    fields = {"schema", "kind", "revision", "account_id", "user_pool_id", "run_id", "binding_sha256", "authorized_from_epoch", "authorized_until_epoch", "preflight", "slots"}
    if not isinstance(value, Mapping) or set(value) != fields or value.get("schema") != 1 or value.get("kind") != "retained-dev-multiuser-test-users":
        _fail("journal_invalid")
    if any(value.get(key) != expected for key, expected in (("account_id", account), ("user_pool_id", pool), ("run_id", run_id), ("binding_sha256", binding_sha256), ("authorized_from_epoch", start), ("authorized_until_epoch", end))):
        _fail("journal_invalid")
    if type(value.get("revision")) is not int or isinstance(value["revision"], bool) or value["revision"] < 0 or type(value.get("preflight")) is not bool:
        _fail("journal_invalid")
    slots = value.get("slots")
    if not isinstance(slots, list) or len(slots) != MAX_USERS:
        _fail("journal_invalid")
    seen: set[str] = set()
    for expected_slot, row in zip(("A", "B"), slots):
        if not isinstance(row, Mapping) or set(row) != {"slot", "username", "create_status", "create_intent", "password_status", "password_intent", "user_sub_sha256"}:
            _fail("journal_invalid")
        if row.get("slot") != expected_slot or row.get("username") != _username(run_id, expected_slot) or row["username"] in seen:
            _fail("journal_invalid")
        seen.add(row["username"])
        cs, ps = row.get("create_status"), row.get("password_status")
        if cs not in _STATUSES or ps not in _PASSWORD_STATUSES:
            _fail("journal_invalid")
        ci, pi, sub = row.get("create_intent"), row.get("password_intent"), row.get("user_sub_sha256")
        if cs == "pending" and ci is not None or cs != "pending" and not _intent(ci, operation="create", expected=_token(account, pool, run_id, expected_slot, "create")):
            _fail("journal_invalid")
        if ps == "not_started" and pi is not None or ps != "not_started" and not _intent(pi, operation="set-password", expected=_token(account, pool, run_id, expected_slot, "set-password")):
            _fail("journal_invalid")
        if sub is not None and (type(sub) is not str or _HEX.fullmatch(sub) is None):
            _fail("journal_invalid")
        if cs in {"created", "reconciled", "confirmed"} and sub is None:
            _fail("journal_invalid")
        if ps != "not_started" and cs not in {"created", "reconciled", "confirmed", "blocked"}:
            _fail("journal_invalid")
        # A password is never a legal journal member, even under an unknown
        # future field name.  The exact-field check above enforces this.
    return dict(value)


def _digest_subject(value: Any) -> str:
    if type(value) is not str or _UUID.fullmatch(value) is None:
        _fail("user_readback_mismatch")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _generate_private_password() -> str:
    """Generate a policy-shaped password without exposing it beyond the caller."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}:,.?"
    required = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
                secrets.choice(string.digits), secrets.choice("!@#$%^&*()-_=+[]{}:,.?")]
    required.extend(secrets.choice(alphabet) for _ in range(28))
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


def _valid_private_password(value: Any) -> bool:
    return (
        type(value) is str and 32 <= len(value) <= 256
        and any(char in string.ascii_uppercase for char in value)
        and any(char in string.ascii_lowercase for char in value)
        and any(char in string.digits for char in value)
        and any(char in "!@#$%^&*()-_=+[]{}:,.?" for char in value)
        and all(ord(char) >= 32 and char not in "\r\n" for char in value)
    )


class DevMultiuserTestUserOperator:
    """Injectable, two-user operator; no SDK construction or automatic retry."""

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, account_id: str,
                 user_pool_id: str, run_id: str, authorized_from_epoch: int,
                 authorized_until_epoch: int, wall_clock: Callable[[], float] = time.time):
        if not isinstance(clients, Mapping) or set(clients) != {"cognito"} or clients.get("cognito") is None:
            _fail("clients_invalid")
        if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            _fail("journal_invalid")
        if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000" or type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None or type(run_id) is not str or _RUN.fullmatch(run_id) is None:
            _fail("binding_invalid")
        if type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool) or authorized_until_epoch <= authorized_from_epoch or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS:
            _fail("window_invalid")
        self.clients, self.journal = dict(clients), journal
        self.account, self.pool, self.run_id = account_id, user_pool_id, run_id
        self.start, self.end, self.wall_clock = authorized_from_epoch, authorized_until_epoch, wall_clock
        self.binding_sha256 = hashlib.sha256(_canonical({"account_id": account_id, "user_pool_id": user_pool_id, "run_id": run_id, "authorized_from_epoch": authorized_from_epoch, "authorized_until_epoch": authorized_until_epoch})).hexdigest()
        self.calls = 0

    def _guard(self) -> None:
        now = self.wall_clock()
        if type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now) or now < self.start or now >= self.end:
            _fail("window_expired")

    def _call(self, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._guard()
        if self.calls >= MAX_CALLS:
            _fail("call_budget_exhausted")
        function = getattr(self.clients["cognito"], method, None)
        if not callable(function):
            _fail("clients_invalid")
        self.calls += 1
        try:
            response = function(**kwargs)
        except Exception:
            raise DevMultiuserUserError("preflight_failed" if method == "admin_get_user" else "create_outcome_unknown") from None
        self._guard()
        if not _ok(response):
            _fail("user_readback_mismatch")
        return response

    def _load(self) -> dict[str, Any] | None:
        try:
            value = self.journal.load()
        except Exception:
            _fail("journal_invalid")
        if value is None:
            return None
        return _validate_state(value, account=self.account, pool=self.pool, run_id=self.run_id, binding_sha256=self.binding_sha256, start=self.start, end=self.end)

    def _save(self, state: dict[str, Any]) -> None:
        self._guard()
        state["revision"] = int(state.get("revision", 0)) + 1
        try:
            self.journal.save(state)
        except Exception:
            _fail("journal_invalid")

    def _initial(self) -> dict[str, Any]:
        return _base(account=self.account, pool=self.pool, run_id=self.run_id, binding_sha256=self.binding_sha256, start=self.start, end=self.end)

    def preflight(self) -> dict[str, Any]:
        """Confirm both deterministic names are absent; perform no writes."""
        with self.journal.locked():
            state = self._load() or self._initial()
            if any(row["create_status"] != "pending" for row in state["slots"]):
                return {"success": False, "category": "preflight_required", "calls": self.calls}
            try:
                for row in state["slots"]:
                    self._guard()
                    try:
                        response = self.clients["cognito"].admin_get_user(UserPoolId=self.pool, Username=row["username"])
                        self.calls += 1
                        if _ok(response):
                            return {"success": False, "category": "user_conflict", "calls": self.calls}
                        return {"success": False, "category": "preflight_failed", "calls": self.calls}
                    except Exception as exc:
                        self.calls += 1
                        if not _not_found(exc):
                            return {"success": False, "category": "preflight_failed", "calls": self.calls}
                        self._guard()
                self._guard()
                state["preflight"] = True
                self._save(state)
                return {"success": True, "category": "preflight_verified", "calls": self.calls, "users": MAX_USERS}
            except DevMultiuserUserError as exc:
                if exc.category == "window_expired":
                    return {"success": False, "category": exc.category, "calls": self.calls}
                raise

    def _user_from_response(self, response: Mapping[str, Any], username: str) -> str:
        user = response.get("User")
        if not isinstance(user, Mapping) or user.get("Username") != username:
            _fail("create_outcome_unknown")
        attributes = user.get("Attributes")
        sub = None
        if isinstance(attributes, list):
            for item in attributes:
                if isinstance(item, Mapping) and item.get("Name") == "sub":
                    if sub is not None:
                        _fail("create_outcome_unknown")
                    sub = item.get("Value")
        return _digest_subject(sub)

    def provision(self, *, on_confirmed_user: Callable[[str, str], Any] | None = None,
                  password_factory: Callable[[], str] = _generate_private_password) -> dict[str, Any]:
        """Create/set exactly two users; never retry an ambiguous AWS write."""
        if on_confirmed_user is not None and not callable(on_confirmed_user) or not callable(password_factory):
            return {"success": False, "category": "password_generation_failed", "calls": self.calls}
        with self.journal.locked():
            state = self._load()
            if state is None or state.get("preflight") is not True:
                return {"success": False, "category": "preflight_required", "calls": self.calls}
            for row in state["slots"]:
                if row["password_status"] in {"confirmed", "reconciled"}:
                    continue
                if row["create_status"] == "blocked" or row["password_status"] == "blocked":
                    return {"success": False, "category": "reconciliation_required", "calls": self.calls}
                if row["create_status"] == "pending":
                    row["create_status"] = "intent"
                    row["create_intent"] = {"operation": "create", "token": _token(self.account, self.pool, self.run_id, row["slot"], "create")}
                    self._save(state)
                    try:
                        response = self.clients["cognito"].admin_create_user(UserPoolId=self.pool, Username=row["username"], MessageAction="SUPPRESS")
                        self.calls += 1
                        self._guard()
                    except Exception:
                        row["create_status"] = "blocked"
                        self._save(state)
                        return {"success": False, "category": "create_outcome_unknown", "calls": self.calls}
                    if not _ok(response):
                        row["create_status"] = "blocked"; self._save(state)
                        return {"success": False, "category": "create_outcome_unknown", "calls": self.calls}
                    row["user_sub_sha256"] = self._user_from_response(response, row["username"])
                    row["create_status"] = "created"
                    self._save(state)
                if row["password_status"] == "not_started":
                    try:
                        password = password_factory()
                    except Exception:
                        return {"success": False, "category": "password_generation_failed", "calls": self.calls}
                    if not _valid_private_password(password):
                        return {"success": False, "category": "password_generation_failed", "calls": self.calls}
                    row["password_status"] = "intent"
                    row["password_intent"] = {"operation": "set-password", "token": _token(self.account, self.pool, self.run_id, row["slot"], "set-password")}
                    self._save(state)
                    try:
                        response = self.clients["cognito"].admin_set_user_password(UserPoolId=self.pool, Username=row["username"], Password=password, Permanent=True)
                        self.calls += 1
                        self._guard()
                    except DevMultiuserUserError:
                        raise
                    except Exception:
                        row["password_status"] = "blocked"; self._save(state)
                        return {"success": False, "category": "password_outcome_unknown", "calls": self.calls}
                    if not _ok(response):
                        row["password_status"] = "blocked"; self._save(state)
                        return {"success": False, "category": "password_outcome_unknown", "calls": self.calls}
                    row["password_status"] = "confirmed"
                    self._save(state)
                    if on_confirmed_user is not None:
                        try:
                            # The callback owns the only in-memory handoff to
                            # Managed Login.  Its return value is deliberately
                            # discarded so tokens cannot enter this result or
                            # the journal.
                            on_confirmed_user(row["username"], password)
                        except Exception:
                            return {"success": False, "category": "login_failed", "calls": self.calls, "users": 0}
            return {"success": True, "category": "users_confirmed", "calls": self.calls, "users": MAX_USERS}

    def reconcile(self) -> dict[str, Any]:
        """Read only; it never retries AdminCreateUser or AdminSetUserPassword."""
        with self.journal.locked():
            state = self._load()
            if state is None:
                return {"success": False, "category": "preflight_required", "calls": self.calls}
            changed = False
            for row in state["slots"]:
                if row["create_status"] == "blocked" and row["password_status"] == "not_started":
                    try:
                        response = self._call("admin_get_user", UserPoolId=self.pool, Username=row["username"])
                    except DevMultiuserUserError:
                        continue
                    row["user_sub_sha256"] = self._user_from_response(response, row["username"])
                    row["create_status"] = "reconciled"; changed = True
                if row["password_status"] == "blocked":
                    try:
                        response = self._call("admin_get_user", UserPoolId=self.pool, Username=row["username"])
                    except DevMultiuserUserError:
                        continue
                    user = response.get("User")
                    if isinstance(user, Mapping) and user.get("Username") == row["username"] and user.get("UserStatus") == "CONFIRMED":
                        row["password_status"] = "reconciled"; changed = True
            if changed:
                self._save(state)
            complete = all(row["password_status"] in {"confirmed", "reconciled"} for row in state["slots"])
            return {"success": complete, "category": "users_confirmed" if complete else "reconciliation_required", "calls": self.calls, "users": MAX_USERS if complete else 0}


@dataclass(frozen=True, repr=False)
class PkceChallenge:
    state: str
    code_verifier: str
    code_challenge: str

    def __repr__(self) -> str:
        return "PkceChallenge(<redacted>)"


@dataclass(frozen=True, repr=False)
class PkceTokenBundle:
    _access_token: str
    _token_type: str
    _expires_in: int
    _scope: str

    @property
    def access_token(self) -> str:
        return self._access_token

    def __repr__(self) -> str:
        return "PkceTokenBundle(<redacted>)"


def new_pkce_challenge() -> PkceChallenge:
    verifier = secrets.token_urlsafe(48)
    state = secrets.token_urlsafe(32)
    encoded = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return PkceChallenge(state=state, code_verifier=verifier, code_challenge=encoded)


def build_pkce_authorization_url(*, managed_login_domain: str, client_id: str,
                                 callback_url: str, required_scope: str,
                                 challenge: PkceChallenge) -> str:
    domain = _validate_managed_domain(managed_login_domain)
    if type(client_id) is not str or _CLIENT.fullmatch(client_id) is None or type(required_scope) is not str or _SCOPE.fullmatch(required_scope) is None or not isinstance(challenge, PkceChallenge):
        _fail("pkce_configuration_invalid")
    if _CALLBACK.fullmatch(callback_url) is None:
        _fail("pkce_configuration_invalid")
    params = {"response_type": "code", "client_id": client_id, "redirect_uri": callback_url, "scope": required_scope, "state": challenge.state, "code_challenge": challenge.code_challenge, "code_challenge_method": "S256"}
    return f"https://{domain}/oauth2/authorize?{urlencode(params)}"


def validate_pkce_callback(callback_url: str, *, expected_state: str) -> str:
    if type(expected_state) is not str or not expected_state or type(callback_url) is not str or len(callback_url.encode("utf-8")) > 2048:
        _fail("pkce_callback_invalid")
    parsed = urlsplit(callback_url)
    if parsed.scheme != "http" or parsed.hostname != "localhost" or not parsed.query or parsed.fragment:
        _fail("pkce_callback_invalid")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if set(query) != {"code", "state"} or query.get("state") != [expected_state] or len(query.get("code", [])) != 1 or not query["code"][0] or len(query["code"][0]) > 4096:
        _fail("pkce_callback_invalid")
    return query["code"][0]


def exchange_pkce_code(*, token_endpoint: str, client_id: str, callback_url: str,
                       code: str, challenge: PkceChallenge,
                       post_form: Callable[[str, Mapping[str, str]], Mapping[str, Any]],
                       expected_domain: str | None = None) -> PkceTokenBundle:
    if type(token_endpoint) is not str or type(client_id) is not str or _CLIENT.fullmatch(client_id) is None or type(code) is not str or not code or not isinstance(challenge, PkceChallenge):
        _fail("pkce_configuration_invalid")
    parsed = urlsplit(token_endpoint)
    domain = _validate_managed_domain(expected_domain) if expected_domain is not None else _validate_managed_domain(parsed.hostname)
    if parsed.scheme != "https" or parsed.hostname != domain or parsed.port not in (None, 443) or parsed.path != "/oauth2/token" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        _fail("pkce_configuration_invalid")
    if _CALLBACK.fullmatch(callback_url) is None:
        _fail("pkce_configuration_invalid")
    form = {"grant_type": "authorization_code", "client_id": client_id, "code": code, "redirect_uri": callback_url, "code_verifier": challenge.code_verifier}
    try:
        response = post_form(token_endpoint, form)
    except Exception:
        _fail("pkce_exchange_invalid")
    if not isinstance(response, Mapping) or type(response.get("access_token")) is not str or not response["access_token"] or response.get("token_type") != "Bearer" or type(response.get("expires_in")) is not int or isinstance(response["expires_in"], bool) or not 1 <= response["expires_in"] <= 3600 or type(response.get("scope")) is not str or not response["scope"]:
        _fail("pkce_exchange_invalid")
    return PkceTokenBundle(response["access_token"], response["token_type"], response["expires_in"], response["scope"])


__all__ = [
    "DevMultiuserTestUserOperator", "DevMultiuserUserError", "PkceChallenge", "PkceTokenBundle",
    "new_pkce_challenge", "build_pkce_authorization_url", "validate_pkce_callback", "exchange_pkce_code",
]
