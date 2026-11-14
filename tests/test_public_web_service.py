"""Public web mode of the /mcp service, offline, against the real botocore models.

Every AWS call goes through botocore's Stubber: each request is validated
against the installed SSM, DynamoDB and Cognito service models and errors are
real modelled ClientError objects. Nothing leaves the process; MAPIT is never
called (the tenant provider is a synthetic one or the session is missing).
"""

from __future__ import annotations

import json
import time

import pytest

botocore_session = pytest.importorskip("botocore.session")
stub = pytest.importorskip("botocore.stub")

from mapit import multiuser_entrypoint as entry  # noqa: E402
from mapit import public_web as web  # noqa: E402
from mapit.multiuser_runtime import (  # noqa: E402
    MSG_UNAVAILABLE, JwksCache, create_multiuser_runtime,
)
from mapit.public_web_service import (  # noqa: E402
    DELETE_DONE, DELETE_FAILED, DELETE_NO_SESSION, MSG_PUBLIC_DELETE_FAILED, MSG_PUBLIC_DELETE_NO_SESSION,
    MSG_PUBLIC_EXPIRED, MSG_LOGOUT_DONE, MSG_LOGOUT_FAILED, MSG_PUBLIC_DELETE_DONE, MSG_PUBLIC_DELETE_PREVIEW,
    MSG_PUBLIC_LIMIT, MSG_PUBLIC_PAUSED, MSG_PUBLIC_RATE, PUBLIC_TOOLS, REFUSED_EXPIRED,
    REFUSED_LIMIT, REFUSED_PAUSED, REFUSED_RATE, REFUSED_UNAVAILABLE, PublicSessionGate,
    PublicSessionRefused,
)
from tests.test_multiuser_runtime import (  # noqa: E402,F401  (keys is a shared fixture)
    ISSUER, METADATA, POOL, TENANT_A, Context, Fetcher, Session, env_values, event, jwks_bytes, keys,
    policy, token, tool_result,
)

NOW = 1_800_000_000
MINUTE = NOW // 60
TABLE = web.web_table_name("dev")
PARAM = web.web_session_parameter_name("dev", TENANT_A)
FP = "c" * 64
USER = "user-a"
WEB_TOOLS = ["borrar_mis_datos", "cerrar_sesion", "get_route_detail", "get_vehicle_details",
             "get_vehicle_status", "list_routes"]


def make_clients():
    session = botocore_session.get_session()
    clients, stubbers = {}, {}
    for service in ("ssm", "dynamodb", "cognito-idp"):
        client = session.create_client(service, region_name="eu-west-1", aws_access_key_id="testing",
                                       aws_secret_access_key="testing")
        clients[service], stubbers[service] = client, stub.Stubber(client)
    return clients, stubbers


class Aws:
    def __init__(self):
        self.clients, self.stubbers = make_clients()
        self.lines = []

    def __enter__(self):
        for stubber in self.stubbers.values():
            stubber.activate()
        return self

    def __exit__(self, *exc):
        for stubber in self.stubbers.values():
            stubber.deactivate()

    def done(self):
        for stubber in self.stubbers.values():
            stubber.assert_no_pending_responses()

    def gate(self, clock=lambda: NOW):
        return PublicSessionGate(env="dev", pool=POOL, client=self.clients.__getitem__, clock=clock,
                                 log=self.lines.append)

    # -- expected requests ---------------------------------------------------

    def config(self, item=None, values=stub.ANY):
        response = {} if item is None else {"Item": {"pk": {"S": "config"}, **item}}
        self.stubbers["dynamodb"].add_response("get_item", response, {
            "TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True})

    def count(self, now=NOW, error=None, old=None):
        params = {
            "TableName": TABLE, "Key": {"pk": {"S": f"usage#{TENANT_A}"}},
            "UpdateExpression": "SET #c = #c + :one, #m = if_not_exists(#m, :zero) + :one REMOVE #p",
            "ConditionExpression": (
                "attribute_exists(#k) AND #e > :now AND #l > :oldest AND #c < :limit "
                "AND (attribute_not_exists(#m) OR #m < :per_minute)"),
            "ExpressionAttributeNames": {"#k": "pk", "#e": "expires_at", "#l": "login_at", "#c": "calls",
                                         "#m": f"m{now // 60}", "#p": f"m{now // 60 - 1}"},
            "ExpressionAttributeValues": {":one": {"N": "1"}, ":zero": {"N": "0"}, ":now": {"N": str(now)},
                                          ":oldest": {"N": str(now - 3300)}, ":limit": {"N": "80"},
                                          ":per_minute": {"N": "30"}},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
        } if now is not None else None  # None: the runtime tests use the real clock
        ddb = self.stubbers["dynamodb"]
        if error is None:
            ddb.add_response("update_item", {}, params)
        elif old is None:
            ddb.add_client_error("update_item", error, http_status_code=400, expected_params=params)
        else:
            ddb.add_client_error("update_item", error, http_status_code=400, expected_params=params,
                                 modeled_fields={"Item": old})

    def deletes(self, ssm_error=None, user_error=None, user=USER):
        if ssm_error:
            self.stubbers["ssm"].add_client_error("delete_parameter", ssm_error, http_status_code=400,
                                                  expected_params={"Name": PARAM})
        else:
            self.stubbers["ssm"].add_response("delete_parameter", {}, {"Name": PARAM})
        if user_error:
            self.stubbers["cognito-idp"].add_client_error(
                "admin_delete_user", user_error, http_status_code=400,
                expected_params={"UserPoolId": POOL, "Username": user})
        else:
            self.stubbers["cognito-idp"].add_response("admin_delete_user", {},
                                                      {"UserPoolId": POOL, "Username": user})
        self.stubbers["dynamodb"].add_response("delete_item", {}, {
            "TableName": TABLE, "Key": {"pk": {"S": f"usage#{TENANT_A}"}}})


def usage(**overrides):
    item = {"pk": {"S": f"usage#{TENANT_A}"}, "person_fp": {"S": FP}, "login_at": {"N": str(NOW - 600)},
            "calls": {"N": "3"}, "expires_at": {"N": str(NOW - 600 + 7200)}}
    item.update({key: value for key, value in overrides.items() if value is not None})
    for key in [key for key, value in overrides.items() if value is None]:
        item.pop(key)
    return item


def refused(gate, auth_time=NOW - 600):
    with pytest.raises(PublicSessionRefused) as info:
        gate.admit(TENANT_A, USER, auth_time)
    return info.value


# -- admission ------------------------------------------------------------------

def test_admit_reads_config_and_counts_once():
    with Aws() as aws:
        aws.config()
        aws.count()
        assert aws.gate().admit(TENANT_A, USER, NOW - 600) is None
    aws.done()
    assert aws.lines == []


@pytest.mark.parametrize("age", [3300, 3301, 7200])
def test_login_age_from_token_expires_and_deletes_without_counting(age):
    with Aws() as aws:
        aws.deletes()
        error = refused(aws.gate(), NOW - age)
    aws.done()
    assert (error.code, error.step) == (REFUSED_EXPIRED, "session_aged")
    assert json.loads(aws.lines[0]) == {"event": "public_call_refused", "code": "session_expired",
                                        "step": "session_aged", "cause": None, "provider_code": None}


def test_login_age_just_under_the_limit_is_served():
    with Aws() as aws:
        aws.config()
        aws.count()
        aws.gate().admit(TENANT_A, USER, NOW - 3299)
    aws.done()


@pytest.mark.parametrize(("old", "label"), [
    (None, "missing row"),
    (usage(login_at={"N": str(NOW - 3300)}), "row login older than the token"),
    (usage(expires_at={"N": str(NOW)}), "expired row"),
    (usage(login_at=None), "row without login_at"),
    (usage(expires_at={"N": "01"}), "non-canonical number"),
])
def test_invalid_usage_row_expires_the_session(old, label):
    with Aws() as aws:
        aws.config()
        aws.count(error="ConditionalCheckFailedException", old=old)
        aws.deletes()
        error = refused(aws.gate())
    aws.done()
    assert (error.code, error.step) == (REFUSED_EXPIRED, "usage_invalid"), label


@pytest.mark.parametrize(("old", "code"), [
    (usage(calls={"N": "80"}), REFUSED_LIMIT),
    (usage(calls={"N": "79"}, **{f"m{MINUTE}": {"N": "30"}}), REFUSED_RATE),
    (usage(calls={"N": "79"}, **{f"m{MINUTE - 1}": {"N": "30"}}), REFUSED_UNAVAILABLE),
])
def test_limits_refuse_without_deleting(old, code):
    with Aws() as aws:
        aws.config()
        aws.count(error="ConditionalCheckFailedException", old=old)
        error = refused(aws.gate())
    aws.done()
    assert error.code == code
    # Only the refusal line: an attempted deletion would log public_delete_failed (unstubbed).
    assert [json.loads(line)["event"] for line in aws.lines] == ["public_call_refused"]


def test_pause_stops_calls_and_closed_signups_do_not():
    with Aws() as aws:
        aws.config({"pause_until": {"N": str(NOW + 1)}})
        assert refused(aws.gate()).code == REFUSED_PAUSED
        aws.config({"pause_until": {"N": str(NOW)}, "open": {"BOOL": False}, "cap": {"N": "1"},
                    "occupied": {"N": "1"}})
        aws.count()
        aws.gate().admit(TENANT_A, USER, NOW - 600)
    aws.done()


@pytest.mark.parametrize("item", [{"open": {"S": "yes"}}, {"unknown": {"N": "1"}}])
def test_malformed_config_refuses(item):
    with Aws() as aws:
        aws.config(item)
        error = refused(aws.gate())
    aws.done()
    assert (error.code, error.step) == (REFUSED_UNAVAILABLE, "config_malformed")


def test_aws_failures_refuse_with_step_and_provider_code():
    with Aws() as aws:
        aws.stubbers["dynamodb"].add_client_error("get_item", "InternalServerError", http_status_code=500)
        first = refused(aws.gate())
        aws.config()
        aws.count(error="ThrottlingException")
        second = refused(aws.gate())
    aws.done()
    assert (first.code, first.step, first.provider_code) == (REFUSED_UNAVAILABLE, "config_read_failed",
                                                             None)
    assert (second.step, second.cause_type, second.provider_code) == ("usage_write_failed", "ThrottlingException",
                                                                       "ThrottlingException")
    assert all(TENANT_A not in line and USER not in line for line in aws.lines)


@pytest.mark.parametrize("auth_time", [None, "1", True, NOW + 1, -1])
def test_invalid_auth_time_refuses_without_aws(auth_time):
    with Aws() as aws:
        assert refused(aws.gate(), auth_time).step == "auth_time_invalid"
    aws.done()


# -- logout and delete ----------------------------------------------------------

def test_end_session_is_idempotent_and_reports_failure():
    with Aws() as aws:
        aws.deletes(ssm_error="ParameterNotFound", user_error="UserNotFoundException")
        assert aws.gate().end_session(TENANT_A, USER) is True
        aws.deletes(ssm_error="AccessDeniedException")
        assert aws.gate().end_session(TENANT_A, USER) is False
    aws.done()
    assert json.loads(aws.lines[0])["step"] == "session_parameter"


def _usage_read(item):
    def add(aws):
        aws.stubbers["dynamodb"].add_response("get_item", {} if item is None else {"Item": item}, {
            "TableName": TABLE, "Key": {"pk": {"S": f"usage#{TENANT_A}"}}, "ConsistentRead": True})
    return add


PERSON_KEY = {"pk": {"S": f"person#{FP}"}}
TRANSACTION = {"TransactItems": [
    {"Delete": {"TableName": TABLE, "Key": PERSON_KEY, "ConditionExpression": "attribute_exists(#k)",
                "ExpressionAttributeNames": {"#k": "pk"}}},
    {"Update": {"TableName": TABLE, "Key": {"pk": {"S": "config"}}, "UpdateExpression": "ADD #o :minus_one",
                "ConditionExpression": "#o > :zero", "ExpressionAttributeNames": {"#o": "occupied"},
                "ExpressionAttributeValues": {":minus_one": {"N": "-1"}, ":zero": {"N": "0"}}}},
]}


def _transaction(aws, error=None, reasons=None):
    ddb = aws.stubbers["dynamodb"]
    if error is None:
        ddb.add_response("transact_write_items", {}, TRANSACTION)
    elif reasons is None:
        ddb.add_client_error("transact_write_items", error, http_status_code=500, expected_params=TRANSACTION)
    else:
        ddb.add_client_error("transact_write_items", error, http_status_code=400, expected_params=TRANSACTION,
                             modeled_fields={"CancellationReasons": [{"Code": code} for code in reasons]})


def test_delete_account_deletes_person_and_frees_the_seat_in_one_transaction():
    with Aws() as aws:
        _usage_read(usage())(aws)
        _transaction(aws)
        aws.deletes()
        assert aws.gate().delete_account(TENANT_A, USER) == DELETE_DONE
    aws.done()
    assert aws.lines == []


def test_delete_account_person_already_gone_frees_no_seat():
    with Aws() as aws:
        _usage_read(usage())(aws)
        _transaction(aws, "TransactionCanceledException", ["ConditionalCheckFailed", "None"])
        aws.deletes()  # no plain delete and no counter update: they would be unstubbed calls
        assert aws.gate().delete_account(TENANT_A, USER) == DELETE_DONE
    aws.done()
    assert aws.lines == []


def test_delete_account_with_occupied_zero_deletes_the_row_without_the_counter():
    with Aws() as aws:
        _usage_read(usage())(aws)
        _transaction(aws, "TransactionCanceledException", ["None", "ConditionalCheckFailed"])
        aws.stubbers["dynamodb"].add_response("delete_item", {}, {"TableName": TABLE, "Key": PERSON_KEY})
        aws.deletes()
        assert aws.gate().delete_account(TENANT_A, USER) == DELETE_DONE
    aws.done()
    assert aws.lines == []


@pytest.mark.parametrize(("item", "step"), [
    (None, "usage_invalid"), (usage(expires_at={"N": str(NOW)}), "usage_invalid"),
    (usage(person_fp=None), "usage_invalid"), (usage(person_fp={"S": "not-a-fingerprint"}), "person_fp_invalid"),
])
def test_delete_account_without_a_valid_usage_row_deletes_nothing(item, step):
    with Aws() as aws:
        _usage_read(item)(aws)
        assert aws.gate().delete_account(TENANT_A, USER) == DELETE_NO_SESSION
    aws.done()
    lines = [json.loads(line) for line in aws.lines]
    assert [(line["event"], line["step"]) for line in lines] == [("public_delete_failed", step)]


@pytest.mark.parametrize(("error", "reasons"), [
    ("InternalServerError", None),
    ("TransactionCanceledException", ["None", "TransactionConflict"]),
])
def test_delete_account_keeps_the_session_when_the_person_transaction_fails(error, reasons):
    with Aws() as aws:
        _usage_read(usage())(aws)
        _transaction(aws, error, reasons)
        assert aws.gate().delete_account(TENANT_A, USER) == DELETE_FAILED
    aws.done()
    assert FP not in "".join(aws.lines)
    assert [json.loads(line)["step"] for line in aws.lines] == ["person_transaction"]  # no session deletion


# -- runtime --------------------------------------------------------------------

class PublicHarness:
    def __init__(self, keys, aws, *, missing=False):
        self.aws, self.created, self.missing = aws, [], missing
        self.runtime = create_multiuser_runtime(
            policy(), JwksCache(ISSUER, fetcher=Fetcher(jwks_bytes((keys[0], "k1")))),
            services_factory=self.factory, relink=lambda tenant, user: aws.gate(time.time).end_session(tenant, user),
            delete_account=lambda tenant, user: False, public_gate=aws.gate(time.time),
        )

    def factory(self, tenant, deadline):
        if self.missing:
            from mapit.multiuser_runtime import TenantSessionMissing
            raise TenantSessionMissing()
        session = Session(tenant)
        self.created.append(session)
        return session

    def call(self, access, **kwargs):
        return self.runtime.lambda_handler(event(access, **kwargs), Context())


def public_token(keys, **overrides):
    now = int(time.time())
    return token(keys[0], auth_time=now - 60, **overrides)


def text(response):
    """(isError, text); the SDK prefixes tool errors with "Error executing tool <name>: "."""
    result = tool_result(response)
    body = result["content"][0]["text"]
    if result.get("isError", False):
        prefix = "Error executing tool "
        assert body.startswith(prefix)
        body = body.split(": ", 1)[1]
    return result.get("isError", False), body


def test_public_tool_list_is_the_short_list(keys):
    with Aws() as aws:
        harness = PublicHarness(keys, aws)
        tools = tool_result(harness.call(public_token(keys), method="tools/list"))["tools"]
    assert sorted(tool["name"] for tool in tools) == WEB_TOOLS
    assert sorted(PUBLIC_TOOLS) == WEB_TOOLS and harness.created == []
    blocked = harness.call(public_token(keys), name="get_distance",
                           arguments={"from_time": "2026-01-01T00:00:00Z", "to_time": "2026-02-01T00:00:00Z"})
    assert tool_result(blocked)["isError"] is True and harness.created == []


def test_public_mode_requires_auth_time_not_after_iat(keys):
    with Aws() as aws:
        harness = PublicHarness(keys, aws)
        now = int(time.time())
        assert harness.call(token(keys[0]), method="tools/list")["statusCode"] == 401
        assert harness.call(token(keys[0], auth_time=now + 5, iat=now), method="tools/list")["statusCode"] == 401
        assert harness.call(token(keys[0], auth_time="1"), method="tools/list")["statusCode"] == 401
    aws.done()


PERIOD = {"from_time": "2026-01-01T00:00:00Z", "to_time": "2026-07-01T00:00:00Z"}


@pytest.mark.parametrize(("name", "arguments"), [
    ("get_vehicle_status", {}), ("get_vehicle_details", {}), ("list_routes", PERIOD),
    ("get_route_detail", {"route_id": "synthetic-route"}),
])
def test_public_read_is_counted_once_then_served(keys, name, arguments):
    with Aws() as aws:
        aws.config()
        aws.count(now=None)
        harness = PublicHarness(keys, aws)
        error, body = text(harness.call(public_token(keys), name=name, arguments=arguments))
    aws.done()
    assert error is False and len(harness.created) == 1 and harness.created[0].tenant == TENANT_A
    assert harness.created[0].services.dispatch_count == 1


def test_unexpected_admission_error_is_unavailable_without_mapit(keys, monkeypatch):
    def broken(self, tenant, username, auth_time):
        raise RuntimeError("boom")

    monkeypatch.setattr(PublicSessionGate, "admit", broken)
    with Aws() as aws:
        harness = PublicHarness(keys, aws)
        assert text(harness.call(public_token(keys))) == (True, f"service_unavailable: {MSG_UNAVAILABLE}")
    aws.done()
    assert harness.created == []


@pytest.mark.parametrize(("old", "code", "message"), [
    (usage(calls={"N": "80"}, login_at={"N": str(int(time.time()) - 60)},
           expires_at={"N": str(int(time.time()) + 3600)}), "session_limit_reached", MSG_PUBLIC_LIMIT),
])
def test_public_limit_refuses_before_mapit(keys, old, code, message):
    with Aws() as aws:
        aws.config()
        aws.count(now=None, error="ConditionalCheckFailedException", old=old)
        harness = PublicHarness(keys, aws)
        error, body = text(harness.call(public_token(keys)))
    aws.done()
    assert error is True and body == f"{code}: {message}" and harness.created == []


def test_public_pause_and_age_messages(keys):
    with Aws() as aws:
        aws.config({"pause_until": {"N": str(int(time.time()) + 600)}})
        harness = PublicHarness(keys, aws)
        assert text(harness.call(public_token(keys))) == (True, f"service_paused: {MSG_PUBLIC_PAUSED}")
        aws.deletes()
        old = token(keys[0], auth_time=int(time.time()) - 3300)
        assert text(harness.call(old)) == (True, f"session_expired: {MSG_PUBLIC_EXPIRED}")
    aws.done()
    assert harness.created == []


def test_public_missing_mapit_session_ends_the_session(keys):
    with Aws() as aws:
        aws.config()
        aws.count(now=None)
        aws.deletes()
        harness = PublicHarness(keys, aws, missing=True)
        assert text(harness.call(public_token(keys))) == (True, f"session_expired: {MSG_PUBLIC_EXPIRED}")
    aws.done()


def test_logout_and_delete_tools(keys):
    with Aws() as aws:
        harness = PublicHarness(keys, aws)
        aws.deletes()
        assert text(harness.call(public_token(keys), name="cerrar_sesion")) == (False, MSG_LOGOUT_DONE)
        aws.deletes(ssm_error="AccessDeniedException")
        assert text(harness.call(public_token(keys), name="cerrar_sesion")) == (
            True, f"logout_failed: {MSG_LOGOUT_FAILED}")
        preview = harness.call(public_token(keys), name="borrar_mis_datos", arguments={"confirmar": False})
        assert text(preview) == (False, MSG_PUBLIC_DELETE_PREVIEW)
        live = usage(expires_at={"N": str(int(time.time()) + 3600)})
        _usage_read(live)(aws)
        _transaction(aws)
        aws.deletes()
        done = harness.call(public_token(keys), name="borrar_mis_datos", arguments={"confirmar": True})
        assert text(done) == (False, MSG_PUBLIC_DELETE_DONE)
        _usage_read(None)(aws)
        failed = harness.call(public_token(keys), name="borrar_mis_datos", arguments={"confirmar": True})
        assert text(failed) == (True, f"delete_failed: {MSG_PUBLIC_DELETE_NO_SESSION}")
        _usage_read(live)(aws)
        _transaction(aws, "InternalServerError")
        failed = harness.call(public_token(keys), name="borrar_mis_datos", arguments={"confirmar": True})
        assert text(failed) == (True, f"delete_failed: {MSG_PUBLIC_DELETE_FAILED}")
    aws.done()
    assert harness.created == []


def test_public_gate_rejects_geography(keys):
    with Aws() as aws, pytest.raises(ValueError):
        create_multiuser_runtime(
            policy(), JwksCache(ISSUER, fetcher=Fetcher(jwks_bytes((keys[0], "k1")))),
            services_factory=lambda tenant, deadline: None, relink=lambda tenant, user: None,
            delete_account=lambda tenant, user: None, geographic_queries=True, public_gate=aws.gate(),
        )


# -- entrypoint -----------------------------------------------------------------

def public_env(**overrides):
    values = env_values(AWS_LAMBDA_FUNCTION_NAME="honda-mapit-mcp-dev-web-mcp", MULTIUSER_TABLE=TABLE,
                        MAPIT_WEB_MODE="public")
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


@pytest.fixture
def public_entry(monkeypatch, keys):
    aws = Aws()
    monkeypatch.setattr(entry, "_client_factory", aws.clients.__getitem__)
    monkeypatch.setattr(entry, "_jwks_fetcher", Fetcher(jwks_bytes((keys[0], "k1"))))
    monkeypatch.setattr(entry, "_CACHED_RUNTIME", None)
    monkeypatch.setattr(entry, "_CACHED_SIGNATURE", None)
    monkeypatch.setattr(entry, "_CACHED_CLIENTS", {})
    for name in entry.ENV_NAMES + ("MAPIT_WEB_MODE",):
        monkeypatch.delenv(name, raising=False)
    for name, value in public_env().items():
        monkeypatch.setenv(name, value)
    return aws


def test_entrypoint_public_mode_reads_the_web_session_parameter(public_entry, keys):
    aws = public_entry
    with aws:
        assert entry.handler(event(None, path=METADATA), Context())["statusCode"] == 200
        aws.config()
        aws.count(now=None)
        aws.stubbers["ssm"].add_client_error("get_parameter", "ParameterNotFound", http_status_code=400,
                                             expected_params={"Name": PARAM, "WithDecryption": True})
        aws.deletes()
        response = entry.handler(event(public_token(keys)), Context())
        tools = tool_result(entry.handler(event(public_token(keys), method="tools/list"), Context()))["tools"]
    aws.done()
    assert text(response) == (True, f"session_expired: {MSG_PUBLIC_EXPIRED}")
    assert sorted(tool["name"] for tool in tools) == sorted(PUBLIC_TOOLS)


@pytest.mark.parametrize("overrides", [
    {"MAPIT_WEB_MODE": "Public"}, {"MAPIT_WEB_MODE": ""},
    {"AWS_LAMBDA_FUNCTION_NAME": "honda-mapit-mcp-dev-mcp"},
    {"MULTIUSER_TABLE": "honda-mapit-mcp-dev-invitations"},
    {"MULTIUSER_GEOGRAPHY": "1"},
])
def test_entrypoint_public_environment_fails_closed(public_entry, monkeypatch, overrides):
    for name, value in overrides.items():
        monkeypatch.setenv(name, value)
    with public_entry:
        response = entry.handler(event(None, path=METADATA), Context())
    assert response["statusCode"] == 503 and response["body"] == '{"error":"service_unavailable"}'
    public_entry.done()


def test_public_settings_refuse_geography_directly():
    with pytest.raises(entry._EntryError):
        entry._settings(public_env(MULTIUSER_GEOGRAPHY="1"))
    assert entry._settings(public_env())["public"] is True


def test_unexpected_public_tool_set_fails_closed(keys, monkeypatch):
    from mapit import multiuser_runtime as runtime
    monkeypatch.setattr(runtime, "PUBLIC_READ_TOOLS", runtime.PUBLIC_READ_TOOLS + ("get_distance",))
    with Aws() as aws:
        harness = PublicHarness(keys, aws)
        assert harness.call(public_token(keys), method="tools/list")["statusCode"] != 200
    aws.done()


def test_entrypoint_without_the_mode_keeps_the_invitation_names(public_entry, monkeypatch):
    monkeypatch.delenv("MAPIT_WEB_MODE")
    # The public function and table names are refused in invitation mode.
    assert entry.handler(event(None, path=METADATA), Context())["statusCode"] == 503
    for name, value in env_values().items():
        monkeypatch.setenv(name, value)
    assert entry.handler(event(None, path=METADATA), Context())["statusCode"] == 200
    assert entry._settings(dict(env_values()))["public"] is False


def test_public_texts_do_not_use_invitation_wording():
    texts = (MSG_PUBLIC_EXPIRED, MSG_PUBLIC_DELETE_NO_SESSION, MSG_PUBLIC_DELETE_FAILED, MSG_PUBLIC_LIMIT,
             MSG_PUBLIC_RATE, MSG_PUBLIC_PAUSED, MSG_PUBLIC_DELETE_PREVIEW, MSG_PUBLIC_DELETE_DONE,
             MSG_LOGOUT_DONE, MSG_LOGOUT_FAILED)
    for value in texts:
        assert not any(word in value.lower() for word in ("conector", "administrador", "invitación"))


def test_missing_auth_time_in_the_request_context_is_a_coded_error(monkeypatch):
    # Unreachable through the verifier (it requires auth_time); checked directly.
    from types import SimpleNamespace

    from mapit import multiuser_runtime as runtime
    monkeypatch.setattr(runtime, "get_access_token", lambda: SimpleNamespace(claims={"username": USER}))
    with pytest.raises(runtime.ToolError) as info:
        runtime._current_auth_time()
    assert str(info.value) == f"service_unavailable: {MSG_UNAVAILABLE}"
