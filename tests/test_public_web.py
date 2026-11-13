from __future__ import annotations

import base64
import hashlib
import hmac
import re

import pytest

from mapit import multiuser_common as common
from mapit import public_web as web
from scripts import build_multiuser_stack as stack

KEY = bytes(range(32))
TENANT = "0123456789abcdef0123456789abcdef"
FP = "ab" * 32
NOW = 1_794_000_000  # 2026-11-06T21:20:00Z


# --- Mode -------------------------------------------------------------------

def test_mode_absent_is_invitation_mode():
    assert web.public_mode_enabled({}) is False
    assert web.public_mode_enabled({"OTHER": "public"}) is False


def test_mode_public_enables_public_mode():
    assert web.public_mode_enabled({"MAPIT_WEB_MODE": "public"}) is True


@pytest.mark.parametrize("value", ["", "Public", "PUBLIC", " public", "public ", "invite", "1", "true"])
def test_mode_other_values_fail_closed(value):
    with pytest.raises(web.PublicWebError) as caught:
        web.public_mode_enabled({"MAPIT_WEB_MODE": value})
    assert caught.value.code == str(caught.value) == "web_mode_invalid"


# --- Names ------------------------------------------------------------------

@pytest.mark.parametrize("env", ["dev", "prod"])
def test_names(env):
    assert web.web_stack_name(env) == f"honda-mapit-mcp-{env}-web"
    assert web.web_table_name(env) == f"honda-mapit-mcp-{env}-web-state"
    assert web.web_session_parameter_prefix(env) == f"/honda-mapit-mcp/{env}/web/sessions/"
    assert web.web_session_parameter_name(env, TENANT) == (
        f"/honda-mapit-mcp/{env}/web/sessions/{TENANT}/mapit-refresh-token")
    assert web.fingerprint_key_parameter_name(env) == f"/honda-mapit-mcp/{env}/web/fingerprint-key"
    assert {web.web_function_name(env, r) for r in web.FUNCTION_ROLES} == {
        f"honda-mapit-mcp-{env}-web-{r}" for r in ("identity", "mcp", "pass", "sweep")}


@pytest.mark.parametrize("env", ["dev", "prod"])
def test_names_never_match_the_invitation_stack(env):
    web_names = {
        web.web_stack_name(env), web.web_table_name(env), web.fingerprint_key_parameter_name(env),
        web.web_session_parameter_name(env, TENANT),
        *(web.web_function_name(env, r) for r in web.FUNCTION_ROLES),
    }
    invitation_names = {
        common.stack_name(env), common.artifacts_stack_name(env), common.table_name(env),
        common.session_parameter_name(env, TENANT), stack.public_config_parameter_name(env),
        stack.mcp_function_name(env), stack.identity_function_name(env),
        stack.artifacts_export_name(env),
    }
    assert not web_names & invitation_names
    # No prefix overlap in either direction: IAM ARNs ending in "*" and the
    # age-based sweep work on prefixes.
    web_prefixes = (web.web_parameter_root(env), web.web_session_parameter_prefix(env))
    invitation_prefixes = (common.users_parameter_prefix(env), f"/honda-mapit-mcp/{env}/multiuser/")
    for a in web_prefixes:
        for b in invitation_prefixes:
            assert not a.startswith(b) and not b.startswith(a)
    for name in invitation_names:
        assert not any(name.startswith(prefix) for prefix in web_prefixes)


@pytest.mark.parametrize("env", ["dev", "prod"])
def test_fingerprint_key_is_outside_the_swept_sessions_prefix(env):
    assert not web.fingerprint_key_parameter_name(env).startswith(web.web_session_parameter_prefix(env))


def test_names_validate_inputs():
    with pytest.raises(common.MultiuserError):
        web.web_stack_name("staging")
    with pytest.raises(web.PublicWebError, match="^function_role_invalid$"):
        web.web_function_name("dev", "admin")
    with pytest.raises(web.PublicWebError, match="^tenant_invalid$"):
        web.web_session_parameter_name("dev", "../x")


# --- Constants --------------------------------------------------------------

def test_constants_match_the_decided_values():
    assert (web.DAILY_LOGINS_PER_PERSON, web.SESSION_CALL_LIMIT, web.CALLS_PER_MINUTE) == (10, 80, 30)
    assert (web.BREAKER_REJECTIONS, web.BREAKER_WINDOW_SECONDS, web.BREAKER_OPEN_SECONDS) == (20, 600, 900)
    assert web.PERSON_TTL_SECONDS == 365 * 86400
    assert web.ATTEMPTS_TTL_SECONDS == 86400
    assert web.SESSION_USAGE_TTL_SECONDS == 7200
    assert (web.SESSION_MAX_AGE_SECONDS, web.SWEEP_AGE_SECONDS) == (3300, 3000)
    assert (web.PASS_TTL_SECONDS, web.PASS_ATTEMPTS) == (300, 3)
    assert (web.IP_PASSES_PER_WINDOW, web.IP_WINDOW_SECONDS) == (5, 600)
    assert web.USED_RESULT_TTL_SECONDS == 600
    assert web.DEFAULT_CAP == 100
    assert web.MAX_FAILED_LOGINS is common.MAX_FAILED_LOGINS == 5
    assert web.LOCK_SECONDS is common.LOCK_SECONDS == 900


def test_time_limits_are_ordered():
    # sweep < service cut < one-hour access token; usage counters outlive a session.
    assert web.SWEEP_AGE_SECONDS < web.SESSION_MAX_AGE_SECONDS < 3600 < web.SESSION_USAGE_TTL_SECONDS


# --- Keys and expiry --------------------------------------------------------

def test_key_constructors():
    assert web.config_key() == {"pk": {"S": "config"}}
    assert web.person_key(FP) == {"pk": {"S": f"person#{FP}"}}
    assert web.attempts_key(FP) == {"pk": {"S": f"attempts#{FP}"}}
    assert web.pass_key(FP) == {"pk": {"S": f"pass#{FP}"}}
    assert web.used_result_key(FP) == {"pk": {"S": f"result#{FP}"}}
    assert web.ip_passes_key(FP, 7) == {"pk": {"S": f"ip#{FP}#7"}}
    assert web.breaker_key(9) == {"pk": {"S": "breaker#9"}}
    assert web.session_usage_key(TENANT) == {"pk": {"S": f"usage#{TENANT}"}}
    assert web.day_key(0) == {"pk": {"S": "day#1970-01-01"}}
    assert web.month_key(NOW) == {"pk": {"S": "month#2026-11"}}
    assert web.day_key(NOW) == {"pk": {"S": "day#2026-11-06"}}


def test_every_kind_has_a_distinct_prefix_and_a_documented_lifetime():
    prefixes = [
        web.config_key(), web.person_key(FP), web.attempts_key(FP), web.pass_key(FP),
        web.used_result_key(FP), web.ip_passes_key(FP, 1), web.breaker_key(1),
        web.session_usage_key(TENANT), web.day_key(NOW), web.month_key(NOW),
    ]
    kinds = [key["pk"]["S"].split("#")[0] for key in prefixes]
    assert kinds == list(web.ROW_KINDS)
    assert len(set(kinds)) == len(kinds)
    for kind, text in web.ROW_KINDS.items():
        assert text.startswith(f"pk '{kind}")
        assert "Expires" in text or "No expiry" in text


@pytest.mark.parametrize("bad", ["AB" * 32, "ab" * 31, "ab" * 33, "g" * 64, FP + "#x", None, 1, b"ab" * 32])
def test_fingerprint_keys_reject_anything_but_a_fingerprint(bad):
    for build in (web.person_key, web.attempts_key, web.pass_key, web.used_result_key):
        with pytest.raises(web.PublicWebError, match="^fingerprint_invalid$"):
            build(bad)
    with pytest.raises(web.PublicWebError, match="^fingerprint_invalid$"):
        web.ip_passes_key(bad, 1)


@pytest.mark.parametrize("bad", [-1, 1.0, True, "1", None, 2**40])
def test_window_and_time_arguments_are_strict(bad):
    with pytest.raises(web.PublicWebError, match="^window_invalid$"):
        web.breaker_key(bad)
    with pytest.raises(web.PublicWebError, match="^window_invalid$"):
        web.ip_passes_key(FP, bad)
    with pytest.raises(web.PublicWebError, match="^time_invalid$"):
        web.day_key(bad)
    with pytest.raises(web.PublicWebError, match="^time_invalid$"):
        web.pass_expires_at(bad)


def test_session_usage_key_rejects_bad_tenants():
    with pytest.raises(web.PublicWebError, match="^tenant_invalid$"):
        web.session_usage_key("A" * 32)


def test_expiry_values():
    assert web.person_expires_at(NOW) == NOW + 365 * 86400
    assert web.attempts_expires_at(NOW) == NOW + 86400
    assert web.pass_expires_at(NOW) == NOW + 300
    assert web.used_result_expires_at(NOW) == NOW + 600
    assert web.session_usage_expires_at(NOW) == NOW + 7200
    window = web.ip_window(NOW)
    assert window == NOW // 600
    assert web.ip_passes_expires_at(window) == (window + 2) * 600
    assert web.ip_passes_expires_at(window) > NOW + 600 - 1  # outlives the whole window
    window = web.breaker_window(NOW)
    assert web.breaker_expires_at(window) == (window + 2) * 600 + 900
    assert web.ttl_value(NOW) == {"N": str(NOW)}
    assert web.TTL_ATTRIBUTE == "expires_at" and web.PARTITION_KEY == "pk"


# --- Fingerprints -----------------------------------------------------------

# Known answers: a change here changes every stored fingerprint and resets
# every count. Do not update them without a migration plan.
KNOWN_EMAIL = "8cd729db48e6da5bd4b26150d7085c7cbaa1820ad5d8e1f443e3965c6862b11a"
KNOWN_IP = "63972fdf831bbbb86a205f8355852fd9626232b60d6d0da51dc3906940676575"
KNOWN_RESULT = "467bffa8f84b63328915473557bb9822fa861122ab768623d4f09a9233d4fd8a"


def test_fingerprint_known_answers():
    assert web.email_fingerprint(KEY, " Rider@Example.COM ") == KNOWN_EMAIL
    assert web.ip_fingerprint(KEY, "2001:DB8:0:0::1") == KNOWN_IP
    assert web.result_fingerprint(KEY, "XXXX.DUMMY.TOKEN") == KNOWN_RESULT


def test_fingerprint_format_is_documented_hmac_sha256():
    expected = hmac.new(KEY, b"honda-mapit-mcp/web/fingerprint/v1/email\x00rider@example.com",
                        hashlib.sha256).hexdigest()
    assert web.email_fingerprint(KEY, "rider@example.com") == expected
    assert re.fullmatch(r"[0-9a-f]{64}", expected)


def test_fingerprint_normalizes_email_and_ip():
    assert web.email_fingerprint(KEY, "RIDER@example.com") == web.email_fingerprint(KEY, "rider@example.com")
    assert web.ip_fingerprint(KEY, "2001:db8::1") == web.ip_fingerprint(KEY, "2001:DB8:0000::1")
    assert web.ip_fingerprint(KEY, "192.0.2.1") != web.ip_fingerprint(KEY, "192.0.2.2")


def test_fingerprint_domains_are_separated():
    value = "192.0.2.1"
    assert web.fingerprint(KEY, "ip", value) != web.fingerprint(KEY, "result", value)
    assert web.fingerprint(KEY, "email", "a@b.co") != web.fingerprint(KEY, "result", "a@b.co")


def test_fingerprint_depends_on_the_key():
    other = bytes(32)
    assert web.email_fingerprint(KEY, "a@b.co") != web.email_fingerprint(other, "a@b.co")


@pytest.mark.parametrize(("call", "code"), [
    (lambda: web.fingerprint(b"short", "email", "a@b.co"), "fingerprint_key_invalid"),
    (lambda: web.fingerprint(bytearray(KEY), "email", "a@b.co"), "fingerprint_key_invalid"),
    (lambda: web.fingerprint(KEY, "phone", "x"), "fingerprint_domain_invalid"),
    (lambda: web.fingerprint(KEY, "email", ""), "fingerprint_value_invalid"),
    (lambda: web.email_fingerprint(KEY, "secret.person@"), "email_invalid"),
    (lambda: web.email_fingerprint(KEY, None), "email_invalid"),
    (lambda: web.ip_fingerprint(KEY, "203.0.113.999"), "ip_invalid"),
    (lambda: web.ip_fingerprint(KEY, 3232235777), "ip_invalid"),
    (lambda: web.result_fingerprint(KEY, ""), "result_invalid"),
    (lambda: web.result_fingerprint(KEY, "x" * 2049), "result_invalid"),
])
def test_fingerprint_errors_are_fixed_codes(call, code):
    with pytest.raises(web.PublicWebError) as caught:
        call()
    assert str(caught.value) == caught.value.code == code


def test_result_at_the_documented_maximum_is_accepted():
    assert re.fullmatch(r"[0-9a-f]{64}", web.result_fingerprint(KEY, "x" * 2048))


# --- Fingerprint key store (SSM doubles with the documented shapes) --------

class ClientError(Exception):
    """Same attributes botocore.exceptions.ClientError exposes."""

    def __init__(self, code: str, operation: str, status: int = 400):
        self.response = {"Error": {"Code": code, "Message": "synthetic"},
                         "ResponseMetadata": {"HTTPStatusCode": status}}
        self.operation_name = operation
        super().__init__(f"An error occurred ({code}) when calling the {operation} operation: synthetic")


def _parameter(name: str, value: str, type_: str = "SecureString", version: int = 1) -> dict:
    return {"Parameter": {
        "Name": name, "Type": type_, "Value": value, "Version": version,
        "LastModifiedDate": "2026-11-13T00:00:00Z", "ARN": f"arn:aws:ssm:eu-west-1:123456789012:parameter{name}",
        "DataType": "text",
    }}


class FakeSSM:
    def __init__(self, *, stored: str | None = None, race_value: str | None = None,
                 get_error: str | None = None, put_error: str | None = None,
                 put_response: object = None):
        self.stored = stored
        self.race_value = race_value
        self.get_error = get_error
        self.put_error = put_error
        self.put_response = {"Version": 1, "Tier": "Standard"} if put_response is None else put_response
        self.calls: list[tuple[str, dict]] = []

    def get_parameter(self, **kwargs):
        self.calls.append(("get_parameter", kwargs))
        if self.get_error:
            raise ClientError(self.get_error, "GetParameter")
        if self.stored is None:
            raise ClientError("ParameterNotFound", "GetParameter")
        return _parameter(kwargs["Name"], self.stored)

    def put_parameter(self, **kwargs):
        self.calls.append(("put_parameter", kwargs))
        if self.put_error:
            raise ClientError(self.put_error, "PutParameter")
        if self.race_value is not None:
            self.stored = self.race_value
            raise ClientError("ParameterAlreadyExists", "PutParameter")
        if self.stored is not None and not kwargs.get("Overwrite"):
            raise ClientError("ParameterAlreadyExists", "PutParameter")
        self.stored = kwargs["Value"]
        return self.put_response


NAME = "/honda-mapit-mcp/dev/web/fingerprint-key"
STORED_KEY = bytes(range(100, 132))
STORED = base64.b64encode(STORED_KEY).decode()


def _store(ssm, token=lambda n: KEY):
    return web.FingerprintKeyStore(ssm, "dev", token_bytes=token)


def test_store_reads_an_existing_key_and_caches_it():
    ssm = FakeSSM(stored=STORED)
    store = _store(ssm, token=lambda n: pytest.fail("must not generate"))
    assert store.key() == STORED_KEY
    assert store.key() == STORED_KEY
    assert ssm.calls == [("get_parameter", {"Name": NAME, "WithDecryption": True})]
    assert store.parameter_name == NAME


def test_store_creates_the_key_once_without_overwrite():
    ssm = FakeSSM()
    store = _store(ssm)
    assert store.key() == KEY
    assert store.key() == KEY
    assert ssm.calls == [
        ("get_parameter", {"Name": NAME, "WithDecryption": True}),
        ("put_parameter", {"Name": NAME, "Value": base64.b64encode(KEY).decode(), "Type": "SecureString",
                           "Overwrite": False, "Tier": "Standard"}),
    ]
    assert ssm.stored == base64.b64encode(KEY).decode()


def test_store_rereads_when_another_caller_created_the_key_first():
    ssm = FakeSSM(race_value=STORED)
    store = _store(ssm)
    assert store.key() == STORED_KEY  # the winner's key, not our candidate
    assert [c[0] for c in ssm.calls] == ["get_parameter", "put_parameter", "get_parameter"]


def test_store_uses_the_real_generator_by_default():
    ssm = FakeSSM()
    key = web.FingerprintKeyStore(ssm, "prod").key()
    assert type(key) is bytes and len(key) == 32
    assert ssm.calls[0][1]["Name"] == "/honda-mapit-mcp/prod/web/fingerprint-key"


@pytest.mark.parametrize(("ssm", "code", "provider"), [
    (FakeSSM(get_error="AccessDeniedException"), "fingerprint_key_read_failed", "AccessDeniedException"),
    (FakeSSM(get_error="InternalServerError"), "fingerprint_key_read_failed", "InternalServerError"),
    (FakeSSM(put_error="AccessDeniedException"), "fingerprint_key_write_failed", "AccessDeniedException"),
    (FakeSSM(put_error="ParameterLimitExceeded"), "fingerprint_key_write_failed", "ParameterLimitExceeded"),
])
def test_store_provider_errors_are_closed_codes(ssm, code, provider):
    with pytest.raises(web.PublicWebError) as caught:
        _store(ssm).key()
    error = caught.value
    assert (str(error), error.code, error.provider_code, error.cause_type) == (code, code, provider, "ClientError")
    assert error.__suppress_context__


def test_store_unknown_exception_has_no_provider_code():
    class Broken:
        def get_parameter(self, **kwargs):
            raise TimeoutError("connect timeout to ssm")

    with pytest.raises(web.PublicWebError) as caught:
        _store(Broken()).key()
    assert (caught.value.code, caught.value.provider_code, caught.value.cause_type) == (
        "fingerprint_key_read_failed", None, "TimeoutError")


def test_store_race_with_vanished_parameter_is_unavailable():
    class Vanishing(FakeSSM):
        def put_parameter(self, **kwargs):
            self.calls.append(("put_parameter", kwargs))
            raise ClientError("ParameterAlreadyExists", "PutParameter")

    with pytest.raises(web.PublicWebError, match="^fingerprint_key_unavailable$"):
        _store(Vanishing()).key()


@pytest.mark.parametrize("value", [
    "", "short", base64.b64encode(bytes(31)).decode(), base64.b64encode(bytes(33)).decode(),
    STORED.rstrip("="), STORED[:-2] + "!=", base64.urlsafe_b64encode(b"\xfb" * 32).decode(),
    STORED.replace("Z", "Z", 1) + " ",
])
def test_store_never_overwrites_an_invalid_existing_key(value):
    ssm = FakeSSM(stored=value)
    with pytest.raises(web.PublicWebError, match="^fingerprint_key_invalid$") as caught:
        _store(ssm).key()
    assert [c[0] for c in ssm.calls] == ["get_parameter"]
    assert value not in repr(caught.value) or value == ""


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(Type="String"),
    lambda p: p.update(Name="/honda-mapit-mcp/dev/users/x"),
    lambda p: p.pop("Value"),
])
def test_store_rejects_unexpected_parameter_shapes(mutate):
    class Odd(FakeSSM):
        def get_parameter(self, **kwargs):
            response = _parameter(kwargs["Name"], STORED)
            mutate(response["Parameter"])
            return response

    with pytest.raises(web.PublicWebError, match="^fingerprint_key_invalid$"):
        _store(Odd()).key()


@pytest.mark.parametrize("response", [{}, {"Version": 0}, {"Version": "1"}, [], None])
def test_store_requires_a_confirmed_put(response):
    class Unconfirmed(FakeSSM):
        def put_parameter(self, **kwargs):
            self.calls.append(("put_parameter", kwargs))
            return response

    with pytest.raises(web.PublicWebError, match="^fingerprint_key_write_unconfirmed$"):
        _store(Unconfirmed()).key()


@pytest.mark.parametrize("token", [lambda n: b"x" * 31, lambda n: "x" * 32, lambda n: bytearray(32)])
def test_store_rejects_a_bad_generator(token):
    ssm = FakeSSM()
    with pytest.raises(web.PublicWebError, match="^fingerprint_key_generation_failed$"):
        _store(ssm, token=token).key()
    assert [c[0] for c in ssm.calls] == ["get_parameter"]


def test_store_failure_is_not_cached():
    ssm = FakeSSM(get_error="ThrottlingException")
    store = _store(ssm)
    with pytest.raises(web.PublicWebError):
        store.key()
    ssm.get_error = None
    ssm.stored = STORED
    assert store.key() == STORED_KEY


def test_errors_never_contain_the_key_or_inputs():
    ssm = FakeSSM(stored=STORED)
    store = _store(ssm)
    key = store.key()
    texts = []
    for call in (lambda: web.email_fingerprint(key, "secret.person@example"),
                 lambda: web.ip_fingerprint(key, "198.51.100.300"),
                 lambda: web.result_fingerprint(key, "t" * 3000)):
        with pytest.raises(web.PublicWebError) as caught:
            call()
        texts.append(repr(caught.value) + str(caught.value.args))
    for text in texts:
        assert "secret.person" not in text and "198.51.100" not in text and "ttt" not in text
        assert STORED not in text


# --- Configuration row ------------------------------------------------------

def test_config_absent_uses_the_decided_defaults():
    config = web.parse_web_config(None)
    assert (config.open, config.pause_until, config.cap, config.occupied, config.pass_required) == (
        True, 0, 100, 0, True)
    assert config.source == web.CONFIG_SOURCE_DEFAULT
    assert config.accepting(NOW) and config.has_room()


def test_config_full_row():
    item = {"pk": {"S": "config"}, "open": {"BOOL": True}, "pause_until": {"N": str(NOW + 60)},
            "cap": {"N": "2"}, "occupied": {"N": "2"}, "pass_required": {"BOOL": False}}
    config = web.parse_web_config(item)
    assert config == web.WebConfig(open=True, pause_until=NOW + 60, cap=2, occupied=2,
                                   pass_required=False, source=web.CONFIG_SOURCE_ROW)
    assert not config.accepting(NOW)
    assert config.accepting(NOW + 60)
    assert not config.has_room()


def test_config_partial_row_takes_defaults():
    config = web.parse_web_config({"pk": {"S": "config"}, "occupied": {"N": "7"}})
    assert (config.open, config.cap, config.occupied, config.pass_required, config.source) == (
        True, 100, 7, True, web.CONFIG_SOURCE_ROW)


def test_config_cap_zero_means_no_cap():
    config = web.parse_web_config({"pk": {"S": "config"}, "cap": {"N": "0"}, "occupied": {"N": "5000"}})
    assert config.has_room()


def test_config_closed_switch():
    config = web.parse_web_config({"pk": {"S": "config"}, "open": {"BOOL": False}})
    assert not config.accepting(NOW) and config.source == web.CONFIG_SOURCE_ROW


@pytest.mark.parametrize("item", [
    {"pk": {"S": "config"}, "open": {"S": "true"}},
    {"pk": {"S": "config"}, "open": {"BOOL": "true"}},
    {"pk": {"S": "config"}, "open": {"BOOL": 1}},
    {"pk": {"S": "config"}, "open": {"BOOL": True, "S": "x"}},
    {"pk": {"S": "config"}, "cap": {"N": "-1"}},
    {"pk": {"S": "config"}, "cap": {"N": "1.5"}},
    {"pk": {"S": "config"}, "cap": {"N": "1e2"}},
    {"pk": {"S": "config"}, "cap": {"N": "010"}},
    {"pk": {"S": "config"}, "cap": {"N": 100}},
    {"pk": {"S": "config"}, "cap": {"S": "100"}},
    {"pk": {"S": "config"}, "occupied": {"N": "99999999999999"}},
    {"pk": {"S": "config"}, "pause_until": {"NULL": True}},
    {"pk": {"S": "config"}, "pass_required": {"N": "0"}},
    {"pk": {"S": "config"}, "unknown": {"S": "x"}},
    {"pk": {"S": "config"}, "expires_at": {"N": "1"}},
    {"pk": {"S": "person#x"}},
    {"open": {"BOOL": True}},
    {"pk": "config"},
    [],
    "config",
])
def test_config_malformed_fails_closed(item):
    config = web.parse_web_config(item)
    assert config == web.CLOSED_WEB_CONFIG
    assert config.source == web.CONFIG_SOURCE_MALFORMED
    assert not config.accepting(NOW)
    assert config.pass_required


def test_config_accepting_rejects_bad_time():
    with pytest.raises(web.PublicWebError, match="^time_invalid$"):
        web.DEFAULT_WEB_CONFIG.accepting(1.5)


# --- Module hygiene ---------------------------------------------------------

def test_public_api_is_exported():
    for name in ("public_mode_enabled", "FingerprintKeyStore", "parse_web_config", "WebConfig",
                 "person_key", "email_fingerprint", "MAX_FAILED_LOGINS", "LOCK_SECONDS", "ROW_KINDS"):
        assert name in web.__all__
    assert not any(name.startswith("_") for name in web.__all__)
    for name in web.__all__:
        assert hasattr(web, name)


def test_module_does_not_import_the_sdk():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(web))
    imported = {alias.name.split(".")[0] for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    imported |= {node.module.split(".")[0] for node in ast.walk(tree)
                 if isinstance(node, ast.ImportFrom) and node.module}
    assert not imported & {"boto3", "botocore", "urllib", "http", "socket", "requests", "httpx"}
