"""Pass endpoint of the public web mode, offline.

DynamoDB, SSM and the Cloudflare transport are in-memory doubles that follow
the documented request/response/error shapes; no network, no AWS.
"""

from __future__ import annotations

import base64
import json
import urllib.error
from urllib.parse import parse_qs

import pytest

from mapit import public_pass as pp
from mapit import public_web as web

NOW = 1_794_000_000  # 2026-11-06T21:20:00Z
KEY = bytes(range(32))
SECRET = "0x4AAAAAAAtestsecretvalue000000000"
EMAIL = "Rider@Example.com"
RESULT = "XXXX.result-token.0123456789"
IP = "203.0.113.7"
ENV = {
    "MAPIT_WEB_MODE": "public", "MAPIT_MCP_ENV": "dev", "AWS_REGION": "eu-west-1",
    "MAPIT_WEB_TABLE": "honda-mapit-mcp-dev-web-state",
    "MAPIT_WEB_TURNSTILE_HOSTNAMES": "localhost,web.example.org",
}
OK = {"success": True, "challenge_ts": "2026-11-06T21:19:50.000Z", "hostname": "localhost",
      "error-codes": [], "action": "web-pass", "cdata": ""}


class ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "x"}}


class FakeDynamo:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []
        self.fail: dict[str, str] = {}

    def _maybe_fail(self, op: str) -> None:
        if op in self.fail:
            raise ClientError(self.fail[op])

    def get_item(self, **kwargs):
        self.calls.append(("get_item", kwargs))
        self._maybe_fail("get_item")
        item = self.items.get(kwargs["Key"]["pk"]["S"])
        return {"Item": item} if item is not None else {}

    def put_item(self, **kwargs):
        self.calls.append(("put_item", kwargs))
        pk = kwargs["Item"]["pk"]["S"]
        self._maybe_fail("put_item:" + pk.split("#")[0])
        if "ConditionExpression" in kwargs:
            assert kwargs["ConditionExpression"] == "attribute_not_exists(#pk)"
            assert kwargs["ExpressionAttributeNames"] == {"#pk": "pk"}
            if pk in self.items:
                raise ClientError("ConditionalCheckFailedException")
        self.items[pk] = dict(kwargs["Item"])
        return {}

    def update_item(self, **kwargs):
        self.calls.append(("update_item", kwargs))
        self._maybe_fail("update_item")
        pk = kwargs["Key"]["pk"]["S"]
        values = kwargs["ExpressionAttributeValues"]
        assert kwargs["UpdateExpression"] == "SET #exp = :exp ADD passes :one"
        assert kwargs["ConditionExpression"] == "attribute_not_exists(passes) OR passes < :limit"
        item = self.items.setdefault(pk, {"pk": {"S": pk}})
        current = int(item["passes"]["N"]) if "passes" in item else None
        if current is not None and not current < int(values[":limit"]["N"]):
            raise ClientError("ConditionalCheckFailedException")
        item["passes"] = {"N": str((current or 0) + int(values[":one"]["N"]))}
        item["expires_at"] = values[":exp"]
        return {}

    def writes(self) -> list[str]:
        return [c[1].get("Item", c[1].get("Key"))["pk"]["S"].split("#")[0]
                for c in self.calls if c[0] != "get_item"]


class FakeSsm:
    def __init__(self, secret: str | None = SECRET) -> None:
        self.values = {"/honda-mapit-mcp/dev/web/fingerprint-key": base64.b64encode(KEY).decode(),
                       "/honda-mapit-mcp/prod/web/fingerprint-key": base64.b64encode(KEY).decode()}
        if secret is not None:
            self.values["/honda-mapit-mcp/dev/web/turnstile-secret"] = secret
            self.values["/honda-mapit-mcp/prod/web/turnstile-secret"] = secret
        self.calls: list[str] = []

    def get_parameter(self, Name, WithDecryption):
        assert WithDecryption is True
        self.calls.append(Name)
        if Name not in self.values:
            raise ClientError("ParameterNotFound")
        return {"Parameter": {"Name": Name, "Type": "SecureString", "Value": self.values[Name],
                              "Version": 1}}

    def put_parameter(self, **kwargs):  # pragma: no cover - the key always exists here
        raise AssertionError("no key creation expected")


class FakeTransport:
    def __init__(self, answer=None, status: int = 200) -> None:
        self.answer = OK if answer is None else answer
        self.status = status
        self.calls: list[tuple] = []

    def __call__(self, url, body, timeout, limit):
        self.calls.append((url, body, timeout, limit))
        if isinstance(self.answer, BaseException):
            raise self.answer
        raw = self.answer if isinstance(self.answer, bytes) else json.dumps(self.answer).encode()
        return self.status, raw


class World:
    def __init__(self, monkeypatch, *, secret: str | None = SECRET, env: dict | None = None) -> None:
        self.dynamo = FakeDynamo()
        self.ssm = FakeSsm(secret)
        self.transport = FakeTransport()
        self.now = NOW
        self.logs: list[tuple] = []
        self.environ = dict(ENV if env is None else env)
        pp.reset_services()
        monkeypatch.setattr(pp, "_log", lambda *args: self.logs.append(args))
        monkeypatch.setattr(pp, "_service_factory", lambda settings: pp.PassService(
            settings, dynamodb=self.dynamo, ssm=self.ssm,
            transport=lambda *a: self.transport(*a), clock=lambda: self.now))

    def call(self, body=None, *, ip: object = IP, email=EMAIL, result=RESULT, raw: str | None = None,
             headers=None, method="POST", path="/pase", b64=False):
        payload = raw if raw is not None else json.dumps(
            {"email": email, "turnstile": result} if body is None else body)
        http = {"method": method, "path": path, "protocol": "HTTP/1.1", "userAgent": "test"}
        if ip is not None:
            http["sourceIp"] = ip
        event = {"version": "2.0", "routeKey": f"{method} {path}", "rawPath": path,
                 "rawQueryString": "",
                 "headers": {"content-type": "application/json"} if headers is None else headers,
                 "requestContext": {"http": http, "stage": "$default"},
                 "body": payload, "isBase64Encoded": b64}
        reply = pp.handle(event, self.environ)
        return reply["statusCode"], json.loads(reply["body"])

    @property
    def codes(self) -> list[str]:
        return [entry[0] for entry in self.logs]


@pytest.fixture
def world(monkeypatch):
    yield World(monkeypatch)
    pp.reset_services()


def _pass_pk(email=EMAIL) -> str:
    return web.pass_key(web.email_fingerprint(KEY, email))["pk"]["S"]


# --- Happy path -----------------------------------------------------------------

def test_issues_a_pass_with_the_identity_contract(world):
    assert world.call() == (200, {"pase": "emitido", "caduca_en_segundos": 300})
    row = world.dynamo.items[_pass_pk()]
    assert row == {"pk": {"S": _pass_pk()}, "attempts_left": {"N": "3"},
                   "issued_at": {"N": str(NOW)}, "expires_at": {"N": str(NOW + 300)}}
    result_pk = web.used_result_key(web.result_fingerprint(KEY, RESULT))["pk"]["S"]
    assert world.dynamo.items[result_pk] == {"pk": {"S": result_pk},
                                             "expires_at": {"N": str(NOW + 600)}}
    ip_pk = web.ip_passes_key(web.ip_fingerprint(KEY, IP), NOW // 600)["pk"]["S"]
    assert world.dynamo.items[ip_pk]["passes"] == {"N": "1"}
    assert world.dynamo.items[ip_pk]["expires_at"] == {"N": str((NOW // 600 + 2) * 600)}
    assert world.dynamo.writes() == ["result", "ip", "pass"]
    assert world.codes == ["pass_issued"]
    get = world.dynamo.calls[0]
    assert get == ("get_item", {"TableName": ENV["MAPIT_WEB_TABLE"], "Key": {"pk": {"S": "config"}},
                                "ConsistentRead": True})


def test_siteverify_request_shape(world):
    world.call()
    [(url, body, timeout, limit)] = world.transport.calls
    assert url == "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    assert parse_qs(body.decode("ascii"), strict_parsing=True) == {
        "secret": [SECRET], "response": [RESULT], "remoteip": [IP]}
    assert 0 < timeout <= 3 and limit == 16 * 1024


def test_same_answer_for_any_email_and_a_new_pass_resets_attempts(world):
    world.dynamo.items[_pass_pk("old@example.com")] = {
        "pk": {"S": _pass_pk("old@example.com")}, "attempts_left": {"N": "0"},
        "issued_at": {"N": str(NOW - 100)}, "expires_at": {"N": str(NOW + 200)}}
    first = world.call(email="new@example.com", result="r-1")
    second = world.call(email="old@example.com", result="r-2")
    assert first == second == (200, {"pase": "emitido", "caduca_en_segundos": 300})
    assert world.dynamo.items[_pass_pk("old@example.com")]["attempts_left"] == {"N": "3"}


def test_email_is_normalized_before_the_fingerprint(world):
    world.call(email="  RIDER@example.COM ")
    assert _pass_pk("rider@example.com") in world.dynamo.items


def test_full_cap_and_pass_not_required_still_issue(world):
    world.dynamo.items["config"] = {"pk": {"S": "config"}, "cap": {"N": "1"}, "occupied": {"N": "1"},
                                    "pass_required": {"BOOL": False}}
    assert world.call()[0] == 200


# --- Bad input --------------------------------------------------------------------

BAD_BODIES = [
    {"raw": '{"email":"a@example.com","turnstile":"x","extra":1}'},
    {"raw": '{"email":"a@example.com","email":"b@example.com","turnstile":"x"}'},
    {"raw": '{"email":"a@example.com"}'},
    {"raw": '{"email":1,"turnstile":"x"}'},
    {"raw": '{"email":"a@example.com","turnstile":["x"]}'},
    {"raw": '["a@example.com","x"]'},
    {"raw": "not json"},
    {"raw": ""},
    {"raw": '{"email":"a@example.com","turnstile":NaN}'},
    {"email": "not-an-email"},
    {"email": "a" * 250 + "@example.com"},
    {"result": ""},
    {"result": "x" * 2049},
    {"result": "has space"},
    {"result": "café"},
    {"raw": '{"email":"a@example.com","turnstile":"' + "x" * 4100 + '"}'},
    {"raw": '{"email":"a@example.com","turnstile":"\\ud800"}'},
    {"headers": {"content-type": "text/plain"}},
    {"headers": {"content-type": "application/json; charset=latin-1"}},
    {"headers": {}},
    {"headers": {"Content-Type": "application/json", "content-type": "application/json"}},
    {"b64": True},
]


@pytest.mark.parametrize("case", BAD_BODIES)
def test_bad_input_gets_the_same_fixed_400_and_no_side_effects(world, case):
    assert world.call(**case) == (400, {"error": "peticion_invalida"})
    assert world.transport.calls == [] and world.dynamo.calls == [] and world.ssm.calls == []
    assert world.codes == ["request_invalid"]


def test_charset_utf8_is_accepted(world):
    assert world.call(headers={"Content-Type": "application/json; charset=UTF-8"})[0] == 200


@pytest.mark.parametrize("ip,code", [(None, "source_ip_missing"), ("", "source_ip_missing"),
                                     (7, "source_ip_missing"), ("999.1.1.1", "source_ip_invalid"),
                                     ("203.0.113.7:443", "source_ip_invalid"),
                                     ("fe80::1%eth0", "source_ip_invalid")])
def test_missing_or_invalid_source_ip_fails_closed(world, ip, code):
    assert world.call(ip=ip) == (503, {"error": "no_disponible"})
    assert world.transport.calls == [] and world.dynamo.calls == []
    assert world.codes == [code]


def test_ipv6_limit_counts_the_slash_64_but_cloudflare_gets_the_address(world):
    for n in range(web.IP_PASSES_PER_WINDOW):
        assert world.call(ip=f"2001:db8:1:2::{n + 1}", result=f"r{n}")[0] == 200
    assert world.call(ip="2001:db8:1:2:ffff::9", result="r-last")[0] == 429
    assert world.call(ip="2001:db8:1:3::1", result="r-other")[0] == 200
    remote = parse_qs(world.transport.calls[0][1].decode())["remoteip"]
    assert remote == ["2001:db8:1:2::1"]


def test_ipv4_mapped_address_counts_and_is_sent_as_the_ipv4_address(world):
    world.call(ip="::ffff:203.0.113.7")
    ip_pk = web.ip_passes_key(web.ip_fingerprint(KEY, IP), NOW // 600)["pk"]["S"]
    assert ip_pk in world.dynamo.items
    assert parse_qs(world.transport.calls[0][1].decode())["remoteip"] == [IP]


def test_ip_row_uses_the_base_fingerprint_of_the_address(world):
    world.call(ip="2001:db8:1:2::abcd")
    expected = web.ip_passes_key(web.ip_fingerprint(KEY, "2001:db8:1:2::abcd"), NOW // 600)
    assert web.ip_fingerprint_value("2001:db8:1:2::abcd") == "2001:db8:1:2::/64"
    assert expected["pk"]["S"] in world.dynamo.items


# --- Configuration row ------------------------------------------------------------

@pytest.mark.parametrize("item,expected,code", [
    ({"pk": {"S": "config"}, "open": {"BOOL": False}}, {"estado": "cerrado"}, "web_closed"),
    ({"pk": {"S": "config"}, "pause_until": {"N": str(NOW + 1)}}, {"estado": "pausa"}, "web_paused"),
    ({"pk": {"S": "config"}, "open": {"S": "yes"}}, {"estado": "cerrado"}, "config_malformed"),
])
def test_closed_or_paused_answers_like_estado_without_cloudflare(world, item, expected, code):
    world.dynamo.items["config"] = item
    assert world.call() == (503, expected)
    assert world.transport.calls == [] and world.ssm.calls == []
    assert world.dynamo.writes() == [] and world.codes == [code]


def test_pause_over_issues_again(world):
    world.dynamo.items["config"] = {"pk": {"S": "config"}, "pause_until": {"N": str(NOW)}}
    assert world.call()[0] == 200


def test_config_read_failure_is_closed(world):
    world.dynamo.fail["get_item"] = "ProvisionedThroughputExceededException"
    assert world.call() == (503, {"error": "no_disponible"})
    assert world.transport.calls == []
    # load_web_config fails closed and keeps no cause, so none is logged.
    assert world.logs == [("config_read_failed", None, None)]


# --- Cloudflare -------------------------------------------------------------------

CLOUDFLARE_CASES = [
    (TimeoutError("timed out"), 200, 503, "turnstile_unavailable"),
    (urllib.error.URLError("down"), 200, 503, "turnstile_unavailable"),
    (OK, 500, 503, "turnstile_http_status"),
    (OK, 400, 503, "turnstile_http_status"),
    (b"<html>oops</html>", 200, 503, "turnstile_response_malformed"),
    (b"x" * (16 * 1024 + 1), 200, 503, "turnstile_response_too_large"),
    ([], 200, 503, "turnstile_response_malformed"),
    ({"hostname": "localhost", "action": "web-pass"}, 200, 503, "turnstile_response_malformed"),
    ({"success": "true", "hostname": "localhost", "action": "web-pass"}, 200, 503,
     "turnstile_response_malformed"),
    ({**OK, "error-codes": "x"}, 200, 503, "turnstile_response_malformed"),
    ({**OK, "error-codes": ["internal-error"]}, 200, 503, "turnstile_response_malformed"),
    ({"success": False, "error-codes": ["timeout-or-duplicate"]}, 200, 403, "turnstile_rejected"),
    ({"success": False, "error-codes": ["invalid-input-response"]}, 200, 403, "turnstile_rejected"),
    ({"success": False, "error-codes": ["missing-input-response"]}, 200, 403, "turnstile_rejected"),
    ({"success": False, "error-codes": ["invalid-input-secret"]}, 200, 503, "turnstile_secret_rejected"),
    ({"success": False, "error-codes": ["missing-input-secret", "invalid-input-response"]}, 200, 503,
     "turnstile_secret_rejected"),
    ({"success": False, "error-codes": ["internal-error"]}, 200, 503, "turnstile_failed_unexpected"),
    ({"success": False, "error-codes": ["bad-request"]}, 200, 503, "turnstile_failed_unexpected"),
    ({"success": False, "error-codes": ["timeout-or-duplicate", "something-new"]}, 200, 503,
     "turnstile_failed_unexpected"),
    ({"success": False, "error-codes": []}, 200, 503, "turnstile_failed_unexpected"),
    ({"success": False}, 200, 503, "turnstile_failed_unexpected"),
    ({**OK, "hostname": "evil.example"}, 200, 403, "turnstile_hostname_mismatch"),
    ({**OK, "hostname": None}, 200, 403, "turnstile_hostname_mismatch"),
    ({**OK, "action": "login"}, 200, 403, "turnstile_action_mismatch"),
    ({k: v for k, v in OK.items() if k != "action"}, 200, 403, "turnstile_action_mismatch"),
]


@pytest.mark.parametrize("answer,status,expected_status,code", CLOUDFLARE_CASES)
def test_cloudflare_answers_never_open_the_door(world, answer, status, expected_status, code):
    world.transport = FakeTransport(answer, status)
    got_status, body = world.call()
    assert got_status == expected_status and world.codes == [code]
    assert body == ({"error": "control_no_valido"} if expected_status == 403 else {"error": "no_disponible"})
    assert world.dynamo.writes() == []


def test_rejected_secret_is_read_again_on_the_next_request(world):
    world.transport = FakeTransport({"success": False, "error-codes": ["invalid-input-secret"]})
    world.call()
    world.transport = FakeTransport()
    assert world.call(result="r-2")[0] == 200
    assert world.ssm.calls.count("/honda-mapit-mcp/dev/web/turnstile-secret") == 2


def test_secret_is_cached_between_requests(world):
    world.call(result="r-1")
    world.call(result="r-2")
    assert world.ssm.calls.count("/honda-mapit-mcp/dev/web/turnstile-secret") == 1


def test_missing_secret_fails_closed_without_calling_cloudflare(monkeypatch):
    world = World(monkeypatch, secret=None)
    assert world.call() == (503, {"error": "no_disponible"})
    assert world.transport.calls == [] and world.dynamo.writes() == []
    assert world.logs == [("turnstile_secret_missing", "ClientError", "ParameterNotFound")]


@pytest.mark.parametrize("secret", ["", "has space", "x" * 257])
def test_invalid_secret_value_fails_closed(monkeypatch, secret):
    world = World(monkeypatch, secret=secret)
    assert world.call()[0] == 503 and world.codes == ["turnstile_secret_invalid"]
    assert world.transport.calls == []


def test_dummy_secret_is_refused_in_prod_only(monkeypatch):
    dummy = "1x0000000000000000000000000000000AA"
    prod = World(monkeypatch, secret=dummy, env={
        **ENV, "MAPIT_MCP_ENV": "prod", "MAPIT_WEB_TABLE": "honda-mapit-mcp-prod-web-state",
        "MAPIT_WEB_TURNSTILE_HOSTNAMES": "web.example.org"})
    assert prod.call()[0] == 503 and prod.codes == ["turnstile_secret_invalid"]
    dev = World(monkeypatch, secret=dummy)
    assert dev.call()[0] == 200


def test_fingerprint_key_failure_fails_closed(world):
    del world.ssm.values["/honda-mapit-mcp/dev/web/fingerprint-key"]
    world.ssm.put_parameter = lambda **kw: (_ for _ in ()).throw(ClientError("AccessDeniedException"))
    assert world.call()[0] == 503
    assert world.logs == [("fingerprint_key_write_failed", "ClientError", "AccessDeniedException")]
    assert world.transport.calls == []


# --- Used results and the per-IP limit --------------------------------------------

def test_a_result_gives_at_most_one_pass(world):
    assert world.call(email="a@example.com")[0] == 200
    assert world.call(email="b@example.com") == (403, {"error": "control_no_valido"})
    assert world.codes[-1] == "result_reused"
    assert _pass_pk("b@example.com") not in world.dynamo.items


def test_ip_limit_returns_429_and_writes_no_pass(world):
    for n in range(web.IP_PASSES_PER_WINDOW):
        assert world.call(email=f"u{n}@example.com", result=f"r{n}")[0] == 200
    assert world.call(email="late@example.com", result="r-late") == (429, {"error": "demasiados_pases"})
    assert world.codes[-1] == "ip_limit_reached"
    assert _pass_pk("late@example.com") not in world.dynamo.items
    world.now = NOW + web.IP_WINDOW_SECONDS
    assert world.call(email="late@example.com", result="r-next")[0] == 200


@pytest.mark.parametrize("op,code", [("put_item:result", "result_mark_failed"),
                                     ("update_item", "ip_count_failed"),
                                     ("put_item:pass", "pass_write_failed")])
def test_table_write_failures_fail_closed(world, op, code):
    world.dynamo.fail[op] = "InternalServerError"
    assert world.call() == (503, {"error": "no_disponible"})
    assert world.logs == [(code, "ClientError", "InternalServerError")]
    assert _pass_pk() not in world.dynamo.items


def test_invalid_clock_fails_closed(world):
    world.now = float("nan")
    assert world.call()[0] == 503 and world.codes == ["clock_invalid"]


# --- Settings, routing, logs ------------------------------------------------------

@pytest.mark.parametrize("change,code", [
    ({"MAPIT_WEB_MODE": None}, "pass_mode_disabled"),
    ({"MAPIT_WEB_MODE": "Public"}, "pass_mode_disabled"),
    ({"MAPIT_MCP_ENV": "qa"}, "pass_config_invalid"),
    ({"AWS_REGION": "us-east-1"}, "pass_config_invalid"),
    ({"MAPIT_WEB_TABLE": "honda-mapit-mcp-dev-invitations"}, "pass_config_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": None}, "pass_hostnames_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": ""}, "pass_hostnames_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": "localhost,"}, "pass_hostnames_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": "https://web.example.org"}, "pass_hostnames_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": "Web.Example.org"}, "pass_hostnames_invalid"),
    ({"MAPIT_WEB_TURNSTILE_HOSTNAMES": ",".join(["a.example"] * 11)}, "pass_hostnames_invalid"),
    ({"MAPIT_MCP_ENV": "prod", "MAPIT_WEB_TABLE": "honda-mapit-mcp-prod-web-state"},
     "pass_hostnames_invalid"),
])
def test_bad_settings_fail_closed(monkeypatch, change, code):
    env = {k: v for k, v in {**ENV, **change}.items() if v is not None}
    world = World(monkeypatch, env=env)
    assert world.call() == (503, {"error": "no_disponible"})
    assert world.codes == [code] and world.transport.calls == [] and world.dynamo.calls == []


@pytest.mark.parametrize("method,path", [("GET", "/pase"), ("POST", "/estado"), ("POST", "/pase/")])
def test_other_routes_are_404(world, method, path):
    assert world.call(method=method, path=path) == (404, {"error": "no_encontrado"})
    assert world.dynamo.calls == []


def test_non_mapping_event_is_closed(world):
    reply = pp.handle(["x"], world.environ)
    assert reply["statusCode"] == 503 and world.codes == ["event_invalid"]


def test_unexpected_exception_is_closed_and_carries_only_the_class(world, monkeypatch):
    def boom(event):
        raise RuntimeError(EMAIL)

    monkeypatch.setattr(pp, "parse_body", boom)
    assert world.call() == (503, {"error": "no_disponible"})
    assert world.logs == [("pass_internal_error", "RuntimeError", None)]


def test_config_response_with_null_item_is_closed(world):
    world.dynamo.get_item = lambda **kw: {"Item": None}
    assert world.call() == (503, {"estado": "cerrado"})
    assert world.transport.calls == []


def test_response_headers_have_no_cors_and_no_store(world):
    reply = pp.response("issued")
    assert reply["headers"] == {"content-type": "application/json; charset=utf-8",
                                "cache-control": "no-store", "x-content-type-options": "nosniff"}
    assert reply["isBase64Encoded"] is False


def test_logs_never_carry_sensitive_values(world, capsys, monkeypatch):
    monkeypatch.setattr(pp, "_log", pp._log_line)
    world.call()
    world.call(email="other@example.com")
    world.transport = FakeTransport({**OK, "hostname": "evil.example"})
    world.call(result="r-3")
    out = capsys.readouterr().out
    lines = [json.loads(line) for line in out.splitlines()]
    assert [line["web_pass_outcome"] for line in lines] == [
        "pass_issued", "result_reused", "turnstile_hostname_mismatch"]
    secrets = [EMAIL, EMAIL.lower(), "other@example.com", IP, RESULT, "r-3", SECRET,
               base64.b64encode(KEY).decode(), web.email_fingerprint(KEY, EMAIL),
               web.ip_fingerprint(KEY, IP), web.result_fingerprint(KEY, RESULT)]
    assert not any(s in out for s in secrets)


def test_secret_parameter_is_outside_the_swept_prefix():
    for env in ("dev", "prod"):
        name = pp.turnstile_secret_parameter_name(env)
        assert name == f"/honda-mapit-mcp/{env}/web/turnstile-secret"
        assert name.startswith(web.web_parameter_root(env))
        assert not name.startswith(web.web_session_parameter_prefix(env))
        assert name != web.fingerprint_key_parameter_name(env)


# --- Default transport ------------------------------------------------------------

class _FakeResponse:
    def __init__(self, status, data):
        self.status, self._data, self.closed = status, data, False

    def read1(self, n):
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk

    def close(self):
        self.closed = True


def test_default_transport_posts_form_and_bounds_the_read(monkeypatch):
    seen = {}
    response = _FakeResponse(200, b'{"success":true}')

    def fake_open(request, *, timeout, opener):
        seen.update(url=request.full_url, method=request.get_method(), data=request.data,
                    ctype=request.get_header("Content-type"), timeout=timeout)
        return response

    monkeypatch.setattr(pp, "open_direct", fake_open)
    assert pp.default_transport(pp.SITEVERIFY_URL, b"a=1", 2.0, 100) == (200, b'{"success":true}')
    assert seen == {"url": pp.SITEVERIFY_URL, "method": "POST", "data": b"a=1",
                    "ctype": "application/x-www-form-urlencoded", "timeout": 2.0}
    assert response.closed
    monkeypatch.setattr(pp, "open_direct", lambda *a, **k: _FakeResponse(200, b"x" * 101))
    with pytest.raises(Exception, match="limit"):
        pp.default_transport(pp.SITEVERIFY_URL, b"a=1", 2.0, 100)


def test_default_transport_maps_http_errors_to_their_status(monkeypatch):
    def fake_open(request, *, timeout, opener):
        raise urllib.error.HTTPError(request.full_url, 502, "bad gateway", None, None)

    monkeypatch.setattr(pp, "open_direct", fake_open)
    assert pp.default_transport(pp.SITEVERIFY_URL, b"a=1", 2.0, 100) == (502, b"")
