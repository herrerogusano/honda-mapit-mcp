"""Public web base: IP fingerprint values, UTC day keys, key-creation event,
config read and the atomic seat-claim condition."""

from __future__ import annotations

import base64
import re
import time

import pytest

from mapit import public_web as web
from test_public_web import KEY, NON_CANONICAL, NOW, STORED, STORED_KEY, ClientError, FakeSSM

TABLE = "honda-mapit-mcp-dev-web-state"


def test_non_canonical_fixture_really_decodes_to_the_same_key():
    assert NON_CANONICAL != STORED and len(NON_CANONICAL) == 44
    assert base64.b64decode(NON_CANONICAL, validate=True) == STORED_KEY


# --- IP fingerprint value ----------------------------------------------------

@pytest.mark.parametrize(("ip", "value"), [
    ("192.0.2.1", "192.0.2.1"),
    ("::ffff:192.0.2.1", "192.0.2.1"),
    ("::FFFF:c000:0201", "192.0.2.1"),
    ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
    ("2001:DB8:1:2::", "2001:db8:1:2::/64"),
    ("::1", "::/64"),
])
def test_ip_fingerprint_value(ip, value):
    assert web.ip_fingerprint_value(ip) == value


def test_ipv6_addresses_in_one_slash64_share_a_fingerprint():
    assert web.ip_fingerprint(KEY, "2001:db8:1:2::1") == web.ip_fingerprint(KEY, "2001:db8:1:2:ffff:ffff:ffff:ffff")
    assert web.ip_fingerprint(KEY, "2001:db8:1:2::1") != web.ip_fingerprint(KEY, "2001:db8:1:3::1")
    assert web.ip_fingerprint(KEY, "::ffff:198.51.100.7") == web.ip_fingerprint(KEY, "198.51.100.7")


@pytest.mark.parametrize("ip", ["fe80::1%eth0", "fe80::1%1", "192.0.2.0/24", "2001:db8::/64", " 192.0.2.1", ""])
def test_ip_fingerprint_rejects_scoped_networks_and_padding(ip):
    with pytest.raises(web.PublicWebError, match="^ip_invalid$"):
        web.ip_fingerprint(KEY, ip)


# --- UTC day and month ---------------------------------------------------------

def test_day_and_month_keys_use_utc_not_local_time(monkeypatch):
    late = 1_796_081_400  # 2026-11-30T23:30:00Z: already the next day and month east of UTC
    has_tzset = hasattr(time, "tzset")
    if has_tzset:
        monkeypatch.setenv("TZ", "Etc/GMT-14")  # POSIX sign: UTC+14
        time.tzset()
    try:
        assert web.day_key(late) == {"pk": {"S": "day#2026-11-30"}}
        assert web.month_key(late) == {"pk": {"S": "month#2026-11"}}
    finally:
        if has_tzset:
            monkeypatch.undo()
            time.tzset()


# --- Key creation event ---------------------------------------------------------

def test_store_reports_the_creation_without_the_value():
    events = []
    store = web.FingerprintKeyStore(FakeSSM(), "dev", token_bytes=lambda n: KEY, on_event=events.append)
    store.key()
    store.key()
    assert events == ["fingerprint_key_created"] == [web.EVENT_FINGERPRINT_KEY_CREATED]


def test_store_logs_the_creation_by_default(caplog):
    with caplog.at_level("WARNING", logger="mapit.public_web"):
        web.FingerprintKeyStore(FakeSSM(), "dev", token_bytes=lambda n: KEY).key()
    assert [(r.name, r.levelname, r.getMessage()) for r in caplog.records] == [
        ("mapit.public_web", "WARNING", "fingerprint_key_created")]
    assert base64.b64encode(KEY).decode() not in caplog.text


def test_store_does_not_report_an_existing_or_raced_key(caplog):
    events = []
    with caplog.at_level("DEBUG", logger="mapit.public_web"):
        web.FingerprintKeyStore(FakeSSM(stored=STORED), "dev", on_event=events.append).key()
        web.FingerprintKeyStore(FakeSSM(race_value=STORED), "dev", token_bytes=lambda n: KEY,
                                on_event=events.append).key()
    assert events == [] and caplog.records == []


# --- Breaker ---------------------------------------------------------------------

def test_breaker_trips_at_n():
    assert not web.breaker_tripped(web.BREAKER_REJECTIONS - 1)
    assert web.breaker_tripped(web.BREAKER_REJECTIONS)
    assert web.breaker_tripped(web.BREAKER_REJECTIONS + 1)
    for bad in (-1, 1.0, True, "20"):
        with pytest.raises(web.PublicWebError, match="^count_invalid$"):
            web.breaker_tripped(bad)


# --- Config read -------------------------------------------------------------------

class FakeDynamo:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


def test_load_config_reads_consistently():
    dynamo = FakeDynamo({"Item": {"pk": {"S": "config"}, "cap": {"N": "3"}},
                         "ResponseMetadata": {"HTTPStatusCode": 200}})
    assert web.load_web_config(dynamo, TABLE).cap == 3
    assert dynamo.calls == [{"TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True}]


def test_load_config_without_item_uses_the_defaults():
    config = web.load_web_config(FakeDynamo({"ResponseMetadata": {"HTTPStatusCode": 200}}), TABLE)
    assert config == web.DEFAULT_WEB_CONFIG


@pytest.mark.parametrize("dynamo", [
    FakeDynamo(error=ClientError("ProvisionedThroughputExceededException", "GetItem")),
    FakeDynamo(error=ClientError("AccessDeniedException", "GetItem")),
    FakeDynamo(error=ClientError("ResourceNotFoundException", "GetItem")),
    FakeDynamo(error=TimeoutError("read timeout")),
    FakeDynamo(response=None),
    FakeDynamo(response=[]),
])
def test_load_config_read_failure_is_closed_never_default(dynamo):
    config = web.load_web_config(dynamo, TABLE)
    assert config == web.READ_FAILED_WEB_CONFIG
    assert (config.open, config.pass_required, config.source) == (False, True, "read_failed")
    assert not config.accepting(NOW)


def test_load_config_null_or_malformed_item_is_closed():
    assert web.load_web_config(FakeDynamo({"Item": None}), TABLE) == web.CLOSED_WEB_CONFIG
    assert web.load_web_config(FakeDynamo({"Item": {"pk": {"S": "config"}, "cap": {"S": "1"}}}),
                               TABLE) == web.CLOSED_WEB_CONFIG


# --- Seat claim condition ------------------------------------------------------------
# A small reference evaluator of the DynamoDB condition grammar used here
# (attribute_exists/attribute_not_exists, =, <, >, AND, OR, parentheses), with
# DynamoDB semantics: a comparison with a missing attribute or between different
# types is false.

_TOKEN = re.compile(r"\s*(attribute_not_exists|attribute_exists|AND|OR|\(|\)|<=|>=|<|>|=|#\w+|:\w+)")


def _evaluate(expression, names, values, item):
    tokens = []
    pos = 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        assert match, expression[pos:]
        tokens.append(match.group(1))
        pos = match.end()
    tokens.append(None)
    index = 0

    def peek():
        return tokens[index]

    def take(expected=None):
        nonlocal index
        token = tokens[index]
        assert expected is None or token == expected, (token, expected)
        index += 1
        return token

    def operand(token):
        return item.get(names[token]) if token.startswith("#") else values[token]

    def compare(left, op, right):
        if left is None or right is None or set(left) != {"N"} or set(right) != {"N"}:
            return False
        a, b = float(left["N"]), float(right["N"])
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "=": a == b}[op]

    def primary():
        token = take()
        if token == "(":
            result = disjunction()
            take(")")
            return result
        if token in ("attribute_exists", "attribute_not_exists"):
            take("(")
            name = names[take()]
            take(")")
            return (name in item) == (token == "attribute_exists")
        op = take()
        return compare(operand(token), op, operand(take()))

    def conjunction():
        result = primary()
        while peek() == "AND":
            take()
            result = primary() and result
        return result

    def disjunction():
        result = conjunction()
        while peek() == "OR":
            take()
            result = conjunction() or result
        return result

    result = disjunction()
    assert peek() is None
    return result


def _claims(item):
    update = web.claim_seat_update(TABLE)
    return _evaluate(update["ConditionExpression"], update["ExpressionAttributeNames"],
                     update["ExpressionAttributeValues"], item)


def _row(**attributes):
    row = {"pk": {"S": "config"}}
    row.update({k: v if isinstance(v, dict) else {"N": str(v)} for k, v in attributes.items()})
    return row


def test_reference_evaluator_semantics():
    names, values = {"#a": "a"}, {":one": {"N": "1"}}
    assert _evaluate("#a < :one", names, values, {"a": {"N": "0"}})
    assert not _evaluate("#a < :one", names, values, {})
    assert not _evaluate("#a < :one", names, values, {"a": {"S": "0"}})
    assert _evaluate("attribute_not_exists(#a) OR #a = :one", names, values, {"a": {"N": "1"}})


@pytest.mark.parametrize(("item", "admitted"), [
    ({}, True),                                  # row absent: default cap, nobody yet
    (_row(occupied=99), True),                   # default cap 100
    (_row(occupied=100), False),
    (_row(cap=0, occupied=5000), True),          # 0 = no cap
    (_row(cap=0), True),
    (_row(cap=2), True),                         # occupied absent = 0
    (_row(cap=2, occupied=1), True),
    (_row(cap=2, occupied=2), False),
    (_row(cap=2, occupied=3), False),
    (_row(cap={"S": "0"}, occupied=1), False),   # wrong types fail closed
    (_row(cap=2, occupied={"S": "0"}), False),
    (_row(cap={"S": "2"}), False),
    (_row(occupied={"S": "1"}), False),
])
def test_claim_seat_condition(item, admitted):
    assert _claims(item) is admitted
    # The condition agrees with WebConfig.has_room on every well-typed row.
    parsed = web.parse_web_config(item or None)
    if parsed.source != web.CONFIG_SOURCE_MALFORMED:
        assert parsed.has_room() is admitted


def test_claim_seat_update_shape():
    update = web.claim_seat_update(TABLE)
    assert update["TableName"] == TABLE and update["Key"] == {"pk": {"S": "config"}}
    assert update["UpdateExpression"] == "ADD #occupied :one"
    assert update["ExpressionAttributeValues"][":default_cap"] == {"N": "100"}
    assert set(update) == {"TableName", "Key", "UpdateExpression", "ConditionExpression",
                           "ExpressionAttributeNames", "ExpressionAttributeValues"}
