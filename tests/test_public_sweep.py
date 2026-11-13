"""Public web sweep with in-memory doubles (no network, no SDK).

The doubles follow the documented shapes of SSM DescribeParameters and
DeleteParameter and Cognito ListUsers and AdminDeleteUser; the same calls are
checked against the real botocore models in test_public_sweep_sdk.py.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mapit import public_sweep as sweep
from mapit import public_web as web

NOW = 1_800_000_000.0
POOL = "eu-west-1_AbCdEfGhI"
ENV = "dev"
T1, T2, T3 = "a" * 32, "b" * 32, "c" * 32
OLD = web.SWEEP_AGE_SECONDS
ENVIRON = {web.MODE_VARIABLE: "public", sweep.ENV_VARIABLE: ENV, sweep.POOL_VARIABLE: POOL}


def at(age: float) -> datetime:
    return datetime.fromtimestamp(NOW - age, tz=timezone.utc)


def param(name: str, age: float) -> dict:
    return {"Name": name, "Type": "SecureString", "LastModifiedDate": at(age), "Version": 1}


def session(tenant: str, age: float) -> dict:
    return param(web.web_session_parameter_name(ENV, tenant), age)


def user(name: str, age: float) -> dict:
    return {"Username": name, "UserCreateDate": at(age), "Enabled": True, "UserStatus": "CONFIRMED"}


class AwsError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "x"}}


class FakeSsm:
    def __init__(self, pages: list, delete_errors: dict | None = None) -> None:
        self.pages = list(pages)
        self.delete_errors = delete_errors or {}
        self.describe_calls: list[dict] = []
        self.deleted: list[str] = []

    def describe_parameters(self, **kwargs):
        self.describe_calls.append(kwargs)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page

    def delete_parameter(self, **kwargs):
        assert set(kwargs) == {"Name"}
        self.deleted.append(kwargs["Name"])
        if kwargs["Name"] in self.delete_errors:
            raise self.delete_errors[kwargs["Name"]]
        return {}


def pool_response(pool_id: str = POOL, name: str | None = None) -> dict:
    return {"UserPool": {"Id": pool_id, "Name": name if name is not None else "honda-mapit-mcp-dev-web-users",
                         "Status": "Enabled"}}


class FakeCognito:
    def __init__(self, pages: list, delete_errors: dict | None = None, pool=None) -> None:
        self.pages = list(pages)
        self.delete_errors = delete_errors or {}
        self.pool = pool if pool is not None else pool_response()
        self.describe_calls: list[dict] = []
        self.list_calls: list[dict] = []
        self.deleted: list[tuple[str, str]] = []

    def describe_user_pool(self, **kwargs):
        self.describe_calls.append(kwargs)
        if isinstance(self.pool, Exception):
            raise self.pool
        return self.pool

    def list_users(self, **kwargs):
        self.list_calls.append(kwargs)
        page = self.pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page

    def admin_delete_user(self, **kwargs):
        assert set(kwargs) == {"UserPoolId", "Username"}
        self.deleted.append((kwargs["UserPoolId"], kwargs["Username"]))
        if kwargs["Username"] in self.delete_errors:
            raise self.delete_errors[kwargs["Username"]]
        return {}


def sweeper(ssm, cognito, remaining=lambda: 60_000, pool=POOL):
    return sweep.Sweeper(env=ENV, user_pool_id=pool, ssm=ssm, cognito=cognito,
                         now=lambda: NOW, remaining_ms=remaining)


def empty_users():
    return FakeCognito([{"Users": []}])


def empty_sessions():
    return FakeSsm([{"Parameters": []}])


# --- Sessions --------------------------------------------------------------

def test_sessions_deleted_from_fifty_minutes_and_young_kept():
    ssm = FakeSsm([{"Parameters": [session(T1, OLD), session(T2, OLD - 1), session(T3, 3 * 3600)]}])
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1), web.web_session_parameter_name(ENV, T3)]
    assert result.status == sweep.STATUS_OK and result.codes == []
    assert (result.sessions_seen, result.sessions_deleted) == (3, 2)
    assert result.oldest_session_age == 3 * 3600


def test_describe_request_is_metadata_only_under_the_sessions_path():
    ssm = empty_sessions()
    sweeper(ssm, empty_users()).run()
    assert ssm.describe_calls == [{
        "ParameterFilters": [{"Key": "Path", "Option": "Recursive",
                              "Values": ["/honda-mapit-mcp/dev/web/sessions"]}],
        "MaxResults": 50,
    }]
    assert web.web_session_parameter_prefix(ENV) == "/honda-mapit-mcp/dev/web/sessions/"


FOREIGN = [
    web.fingerprint_key_parameter_name(ENV),
    web.fingerprint_key_parameter_name("prod"),
    web.web_session_parameter_name("prod", T1),
    "/honda-mapit-mcp/dev/multiuser/users/" + T1 + "/mapit-refresh-token",
    "/honda-mapit-mcp/dev/web/sessions-x/" + T1 + "/mapit-refresh-token",
    "/honda-mapit-mcp/dev/web/sessions/" + T1 + "/other",
    "/honda-mapit-mcp/dev/web/sessions/" + T1 + "/mapit-refresh-token/extra",
    "/honda-mapit-mcp/dev/web/sessions/" + "A" * 32 + "/mapit-refresh-token",
    "/honda-mapit-mcp/dev/web/sessions/" + "a" * 31 + "/mapit-refresh-token",
    "/honda-mapit-mcp/dev/web/sessions/",
    "/honda-mapit-mcp/dev/web/sessions/" + T1,
    "honda-mapit-mcp/dev/web/sessions/" + T1 + "/mapit-refresh-token",
    "/other/" + T1,
]


def test_nothing_outside_the_exact_session_names_is_deleted():
    pages = [{"Parameters": [param(name, 10 * 3600) for name in FOREIGN] + [session(T1, OLD)]}]
    ssm = FakeSsm(pages)
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1)]
    assert result.codes == ["sweep_sessions_unexpected"]
    assert result.status == sweep.STATUS_FAILED


@pytest.mark.parametrize("name", FOREIGN + [None, 7, ""])
def test_session_name_guard_rejects_each_foreign_name(name):
    assert sweeper(empty_sessions(), empty_users()).session_name(name) is None


def test_non_mapping_parameter_entry_is_unexpected():
    ssm = FakeSsm([{"Parameters": ["/honda-mapit-mcp/dev/web/sessions/x", session(T1, OLD)]}])
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1)]
    assert result.codes == ["sweep_sessions_unexpected"]


def test_sessions_follow_next_token_including_empty_best_effort_pages():
    ssm = FakeSsm([
        {"Parameters": [], "NextToken": "t1"},
        {"Parameters": [session(T1, OLD)], "NextToken": "t2"},
        {"Parameters": [session(T2, OLD)]},
    ])
    result = sweeper(ssm, empty_users()).run()
    assert [call.get("NextToken") for call in ssm.describe_calls] == [None, "t1", "t2"]
    assert result.sessions_deleted == 2 and result.status == sweep.STATUS_OK


@pytest.mark.parametrize("token", ["", 5, "x" * 4097])
def test_invalid_next_token_stops_listing(token):
    ssm = FakeSsm([{"Parameters": [session(T1, OLD)], "NextToken": token}])
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == []
    assert result.codes == ["sweep_sessions_list_malformed"]


def test_repeated_next_token_stops_listing_but_deletes_what_was_listed():
    ssm = FakeSsm([
        {"Parameters": [session(T1, OLD)], "NextToken": "same"},
        {"Parameters": [session(T2, OLD)], "NextToken": "same"},
    ])
    result = sweeper(ssm, empty_users()).run()
    assert len(ssm.describe_calls) == 2
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1)]
    assert result.codes == ["sweep_sessions_list_malformed"]


@pytest.mark.parametrize("page", [None, {}, {"Parameters": None}, {"Parameters": {}}, []])
def test_malformed_describe_response(page):
    result = sweeper(FakeSsm([page]), empty_users()).run()
    assert result.codes == ["sweep_sessions_list_malformed"]


def test_session_page_cap_marks_incomplete(monkeypatch):
    monkeypatch.setattr(sweep, "MAX_SESSION_PAGES", 2)
    ssm = FakeSsm([{"Parameters": [session(T1, OLD)], "NextToken": "t1"},
                   {"Parameters": [session(T2, OLD)], "NextToken": "t2"}])
    result = sweeper(ssm, empty_users()).run()
    assert len(ssm.describe_calls) == 2 and len(ssm.deleted) == 2
    assert result.incomplete and result.status == sweep.STATUS_INCOMPLETE


def test_parameter_already_gone_is_not_an_error():
    name = web.web_session_parameter_name(ENV, T1)
    ssm = FakeSsm([{"Parameters": [session(T1, OLD), session(T2, OLD)]}],
                  delete_errors={name: AwsError("ParameterNotFound")})
    result = sweeper(ssm, empty_users()).run()
    assert result.status == sweep.STATUS_OK
    assert (result.sessions_deleted, result.sessions_gone) == (1, 1)


def test_parameter_delete_failure_is_coded_and_others_continue():
    name = web.web_session_parameter_name(ENV, T1)
    ssm = FakeSsm([{"Parameters": [session(T1, OLD), session(T2, OLD)]}],
                  delete_errors={name: AwsError("AccessDeniedException")})
    result = sweeper(ssm, empty_users()).run()
    assert len(ssm.deleted) == 2 and result.sessions_deleted == 1
    assert result.codes == ["sweep_sessions_delete_failed"]


def test_session_list_failure_is_coded_and_users_still_swept():
    cognito = FakeCognito([{"Users": [user("u1", OLD)]}])
    result = sweeper(FakeSsm([AwsError("ThrottlingException")]), cognito).run()
    assert result.codes == ["sweep_sessions_list_failed"]
    assert cognito.deleted == [(POOL, "u1")]


@pytest.mark.parametrize("value", [None, "2026-01-01T00:00:00Z", datetime(2020, 1, 1),
                                   datetime.fromtimestamp(NOW + 301, tz=timezone.utc)])
def test_missing_naive_or_far_future_date_counts_as_old(value):
    item = session(T1, 0)
    item["LastModifiedDate"] = value
    if value is None:
        del item["LastModifiedDate"]
    ssm = FakeSsm([{"Parameters": [item]}])
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1)]
    assert result.invalid_dates == 1


def test_small_clock_skew_is_young_not_invalid():
    item = session(T1, 0)
    item["LastModifiedDate"] = datetime.fromtimestamp(NOW + 299, tz=timezone.utc)
    ssm = FakeSsm([{"Parameters": [item]}])
    result = sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [] and result.invalid_dates == 0 and result.oldest_session_age == 0


def test_non_utc_aware_dates_are_compared_by_instant():
    item = session(T1, 0)
    item["LastModifiedDate"] = at(OLD).astimezone(timezone(timedelta(hours=2)))
    ssm = FakeSsm([{"Parameters": [item]}])
    sweeper(ssm, empty_users()).run()
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T1)]


# --- Users -----------------------------------------------------------------

def test_users_deleted_by_create_date_in_the_configured_pool_only():
    cognito = FakeCognito([{"Users": [user("u1", OLD), user("u2", OLD - 1), user("u3", 7200)]}])
    result = sweeper(empty_sessions(), cognito).run()
    assert cognito.deleted == [(POOL, "u1"), (POOL, "u3")]
    assert cognito.list_calls == [{"UserPoolId": POOL, "AttributesToGet": [], "Limit": 60}]
    assert (result.users_seen, result.users_deleted, result.oldest_user_age) == (3, 2, 7200)


def test_users_follow_pagination_token():
    cognito = FakeCognito([{"Users": [user("u1", OLD)], "PaginationToken": "p1"},
                           {"Users": [user("u2", OLD)]}])
    result = sweeper(empty_sessions(), cognito).run()
    assert [call.get("PaginationToken") for call in cognito.list_calls] == [None, "p1"]
    assert result.users_deleted == 2


def test_users_are_listed_completely_before_any_delete():
    order = []

    class Ordered(FakeCognito):
        def list_users(self, **kwargs):
            order.append("list")
            return super().list_users(**kwargs)

        def admin_delete_user(self, **kwargs):
            order.append("delete")
            return super().admin_delete_user(**kwargs)

    cognito = Ordered([{"Users": [user("u1", OLD)], "PaginationToken": "p1"}, {"Users": [user("u2", OLD)]}])
    sweeper(empty_sessions(), cognito).run()
    assert order == ["list", "list", "delete", "delete"]


def test_user_already_gone_is_not_an_error():
    cognito = FakeCognito([{"Users": [user("u1", OLD)]}], {"u1": AwsError("UserNotFoundException")})
    result = sweeper(empty_sessions(), cognito).run()
    assert result.status == sweep.STATUS_OK and result.users_gone == 1


def test_user_delete_failure_is_coded():
    cognito = FakeCognito([{"Users": [user("u1", OLD), user("u2", OLD)]}],
                          {"u1": AwsError("TooManyRequestsException")})
    result = sweeper(empty_sessions(), cognito).run()
    assert result.codes == ["sweep_users_delete_failed"] and result.users_deleted == 1


def test_user_list_failure_and_malformed_users():
    assert sweeper(empty_sessions(), FakeCognito([AwsError("AccessDeniedException")])).run().codes == [
        "sweep_users_list_failed"]
    assert sweeper(empty_sessions(), FakeCognito([{"Users": None}])).run().codes == [
        "sweep_users_list_malformed"]
    cognito = FakeCognito([{"Users": [{"UserCreateDate": at(OLD)}, {"Username": ""},
                                      {"Username": "x" * 129}, "u", user("ok", OLD)]}])
    result = sweeper(empty_sessions(), cognito).run()
    assert cognito.deleted == [(POOL, "ok")] and result.codes == ["sweep_users_unexpected"]


@pytest.mark.parametrize("pool", [None, "", "eu-west-2_AbCdEfGhI", "eu-west-1_short",
                                  "eu-west-1_AbCdEfGhI/x", "eu-west-1_" + "a" * 46, 5])
def test_sweeper_refuses_an_invalid_pool_id(pool):
    with pytest.raises(web.PublicWebError):
        sweeper(empty_sessions(), empty_users(), pool=pool)


# --- Deadline --------------------------------------------------------------

def test_no_call_without_time_margin():
    ssm, cognito = FakeSsm([]), FakeCognito([])
    result = sweeper(ssm, cognito, remaining=lambda: sweep.DEADLINE_MARGIN_MS).run()
    assert ssm.describe_calls == [] and cognito.list_calls == []
    assert result.status == sweep.STATUS_INCOMPLETE


def test_stops_mid_run_and_leaves_the_rest():
    # pool check, session list, two deletes, then the margin is gone
    budget = iter([60_000, 60_000, 60_000, 60_000, 1_000])
    ssm = FakeSsm([{"Parameters": [session(T1, OLD), session(T2, OLD), session(T3, OLD)]}])
    cognito = FakeCognito([])
    result = sweeper(ssm, cognito, remaining=lambda: next(budget, 0)).run()
    assert len(ssm.deleted) == 2 and cognito.list_calls == []
    assert result.incomplete and result.status == sweep.STATUS_INCOMPLETE


def test_stops_mid_user_deletes_and_leaves_the_rest():
    # pool check, session list, user list, two user deletes, then the margin is gone
    budget = iter([60_000, 60_000, 60_000, 60_000, 60_000, 1_000])
    cognito = FakeCognito([{"Users": [user("u1", OLD), user("u2", OLD), user("u3", OLD)]}])
    result = sweeper(empty_sessions(), cognito, remaining=lambda: next(budget, 0)).run()
    assert cognito.deleted == [(POOL, "u1"), (POOL, "u2")]
    assert result.users_deleted == 2
    assert result.incomplete and result.status == sweep.STATUS_INCOMPLETE


def test_user_page_cap_marks_incomplete(monkeypatch):
    monkeypatch.setattr(sweep, "MAX_USER_PAGES", 2)
    cognito = FakeCognito([{"Users": [user("u1", OLD)], "PaginationToken": "p1"},
                           {"Users": [user("u2", OLD)], "PaginationToken": "p2"}])
    result = sweeper(empty_sessions(), cognito).run()
    assert len(cognito.list_calls) == 2 and len(cognito.deleted) == 2
    assert result.incomplete and result.status == sweep.STATUS_INCOMPLETE


# --- Pool check ------------------------------------------------------------

def test_pool_is_described_before_anything_else():
    order = []

    class OrderedSsm(FakeSsm):
        def describe_parameters(self, **kwargs):
            order.append("ssm")
            return super().describe_parameters(**kwargs)

    class OrderedCognito(FakeCognito):
        def describe_user_pool(self, **kwargs):
            order.append("pool")
            return super().describe_user_pool(**kwargs)

    cognito = OrderedCognito([{"Users": []}])
    sweeper(OrderedSsm([{"Parameters": []}]), cognito).run()
    assert order == ["pool", "ssm"] and cognito.describe_calls == [{"UserPoolId": POOL}]
    assert sweep.web_user_pool_name("dev") == "honda-mapit-mcp-dev-web-users"
    assert sweep.web_user_pool_name("prod") == "honda-mapit-mcp-prod-web-users"


@pytest.mark.parametrize("pool, code", [
    (pool_response(name="honda-mapit-mcp-dev-users"), "sweep_pool_mismatch"),
    (pool_response(name="honda-mapit-mcp-prod-web-users"), "sweep_pool_mismatch"),
    (pool_response(name="honda-mapit-mcp-dev-web-users-x"), "sweep_pool_mismatch"),
    (pool_response(pool_id="eu-west-1_ZzZzZzZzZ"), "sweep_pool_mismatch"),
    ({"UserPool": {"Id": POOL}}, "sweep_pool_mismatch"),
    ({"UserPool": None}, "sweep_pool_check_failed"),
    ({}, "sweep_pool_check_failed"),
    (AwsError("ResourceNotFoundException"), "sweep_pool_check_failed"),
])
def test_another_pool_or_failed_check_deletes_nothing(pool, code):
    ssm = FakeSsm([{"Parameters": [session(T1, OLD)]}])
    cognito = FakeCognito([{"Users": [user("u1", OLD)]}], pool=pool)
    result = sweeper(ssm, cognito).run()
    assert ssm.describe_calls == [] and ssm.deleted == []
    assert cognito.list_calls == [] and cognito.deleted == []
    assert result.codes == [code] and result.status == sweep.STATUS_FAILED


def test_broken_remaining_time_counts_as_no_time():
    def broken():
        raise RuntimeError("x")

    ssm = FakeSsm([])
    result = sweeper(ssm, FakeCognito([]), remaining=broken).run()
    assert ssm.describe_calls == [] and result.incomplete


# --- run_sweep and handler -------------------------------------------------

@pytest.fixture
def factory(monkeypatch):
    made = {}

    def make(service):
        made[service] = {"ssm": FakeSsm([{"Parameters": [session(T1, OLD)]}]),
                         "cognito-idp": FakeCognito([{"Users": [user("u-secret", OLD)]}])}[service]
        return made[service]

    monkeypatch.setattr(sweep, "_client_factory", make)
    return made


class Context:
    def get_remaining_time_in_millis(self):
        return 60_000


@pytest.mark.parametrize("change", [
    {sweep.POOL_VARIABLE: None}, {sweep.POOL_VARIABLE: ""}, {sweep.POOL_VARIABLE: "eu-west-2_AbCdEfGhI"},
    {sweep.POOL_VARIABLE: " eu-west-1_AbCdEfGhI"}, {sweep.ENV_VARIABLE: None}, {sweep.ENV_VARIABLE: "test"},
    {web.MODE_VARIABLE: None}, {web.MODE_VARIABLE: "Public"},
])
def test_invalid_configuration_deletes_nothing(factory, change):
    environ = {k: v for k, v in {**ENVIRON, **change}.items() if v is not None}
    result = sweep.run_sweep(environ, Context())
    assert factory == {}
    assert result.codes == ["sweep_config_invalid"]


def test_run_sweep_with_valid_configuration(factory):
    result = sweep.run_sweep(ENVIRON, Context())
    assert result.status == sweep.STATUS_OK
    assert factory["ssm"].deleted == [web.web_session_parameter_name(ENV, T1)]
    assert factory["cognito-idp"].deleted == [(POOL, "u-secret")]


def test_client_failure_and_internal_error_are_coded(monkeypatch):
    def broken(service):
        raise web.PublicWebError("credentials_unavailable")

    monkeypatch.setattr(sweep, "_client_factory", broken)
    assert sweep.run_sweep(ENVIRON, Context()).codes == ["sweep_clients_unavailable"]
    monkeypatch.setattr(sweep, "_client_factory", lambda service: object())
    monkeypatch.setattr(sweep.Sweeper, "run", lambda self: 1 / 0)
    assert sweep.run_sweep(ENVIRON, Context()).codes == ["sweep_internal_error"]


def test_make_client_refuses_other_services_and_missing_credentials(monkeypatch):
    with pytest.raises(web.PublicWebError):
        sweep._make_client("dynamodb")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    with pytest.raises(web.PublicWebError):
        sweep._make_client("ssm")


def test_run_sweep_with_the_real_clock_keeps_a_one_minute_item(monkeypatch):
    real_now = datetime.now(timezone.utc)
    young, old = real_now - timedelta(minutes=1), real_now - timedelta(minutes=51)
    ssm = FakeSsm([{"Parameters": [
        {"Name": web.web_session_parameter_name(ENV, T1), "LastModifiedDate": young},
        {"Name": web.web_session_parameter_name(ENV, T2), "LastModifiedDate": old},
    ]}])
    cognito = FakeCognito([{"Users": [{"Username": "young", "UserCreateDate": young},
                                      {"Username": "old", "UserCreateDate": old}]}])
    monkeypatch.setattr(sweep, "_client_factory", {"ssm": ssm, "cognito-idp": cognito}.__getitem__)
    result = sweep.run_sweep(ENVIRON, Context())
    assert result.status == sweep.STATUS_OK and result.invalid_dates == 0
    assert ssm.deleted == [web.web_session_parameter_name(ENV, T2)]
    assert cognito.deleted == [(POOL, "old")]
    assert 50 * 60 <= result.oldest_age <= 52 * 60


def test_invalid_dates_are_an_emf_metric():
    record = sweep.emf_record(sweep.SweepResult(invalid_dates=3), "dev", 1)
    names = [m["Name"] for m in record["_aws"]["CloudWatchMetrics"][0]["Metrics"]]
    assert "InvalidDates" in names and record["InvalidDates"] == 3


def test_handler_logs_one_emf_line_without_identifiers(factory, monkeypatch):
    lines = []
    monkeypatch.setattr(sweep, "_emit", lines.append)
    for key, value in ENVIRON.items():
        monkeypatch.setenv(key, value)
    assert sweep.handler({}, Context()) == {"status": "ok", "codes": []}
    assert len(lines) == 1
    record = json.loads(lines[0])
    directive = record["_aws"]["CloudWatchMetrics"][0]
    assert directive["Namespace"] == "honda-mapit-mcp/web"
    assert directive["Dimensions"] == [["Environment"]] and record["Environment"] == "dev"
    for metric in directive["Metrics"]:
        assert isinstance(record[metric["Name"]], int)
    assert record["SessionsDeleted"] == 1 and record["UsersDeleted"] == 1
    assert record["OldestItemAgeSeconds"] >= OLD and record["SweepFailed"] == 0
    assert "error" not in record
    for secret in ("u-secret", T1, POOL, "sessions/"):
        assert secret not in lines[0]


def test_handler_failure_has_fixed_code_and_never_raises(monkeypatch):
    lines = []
    monkeypatch.setattr(sweep, "_emit", lines.append)
    monkeypatch.delenv(sweep.POOL_VARIABLE, raising=False)
    monkeypatch.setenv(web.MODE_VARIABLE, "public")
    monkeypatch.setenv(sweep.ENV_VARIABLE, "prod")
    assert sweep.handler({}, None) == {"status": "failed", "codes": ["sweep_config_invalid"]}
    record = json.loads(lines[0])
    assert record["error"] == sweep.FAILURE_CODE and record["SweepFailed"] == 1
    assert record["Environment"] == "prod"

    def boom(line):
        raise OSError("closed")

    monkeypatch.setattr(sweep, "_emit", boom)
    monkeypatch.setenv(sweep.ENV_VARIABLE, "bogus")
    assert sweep.handler({}, None)["status"] == "failed"


def test_emf_record_for_incomplete_run():
    result = sweep.SweepResult(incomplete=True, oldest_session_age=10, oldest_user_age=70)
    record = sweep.emf_record(result, "dev", 123)
    assert record["SweepIncomplete"] == 1 and record["SweepFailed"] == 0
    assert record["OldestItemAgeSeconds"] == 70 and record["_aws"]["Timestamp"] == 123


def test_remaining_falls_back_to_a_fixed_budget():
    remaining = sweep._remaining(None, sweep.time.monotonic())
    assert sweep.DEADLINE_MARGIN_MS < remaining() <= sweep.FALLBACK_BUDGET_MS


def test_sweep_age_is_below_the_service_cut_and_token_life():
    # Swept at 50 min, refused by the service at 55, access token lives 60.
    assert web.SWEEP_AGE_SECONDS < web.SESSION_MAX_AGE_SECONDS < 60 * 60
    # Worst case: an item just under 50 min is swept on the next 5-minute run.
    assert web.SWEEP_AGE_SECONDS + 5 * 60 <= web.SESSION_MAX_AGE_SECONDS
