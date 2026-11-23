"""``vehicle-stats``: one read-only Logs Insights query per MCP log group, counts only."""

from __future__ import annotations

import json
import re

import pytest

from tests import multi_vehicle_fixtures as fx
from mapit.client import metered_tool_call, set_read_meter_sink
from mapit.services import MapitServices, ServiceError
from scripts import mcp_users, mcp_users_logs as log_stats

NOW = 1_800_000_000


class NotFound(Exception):
    response = {"Error": {"Code": "ResourceNotFoundException", "Message": "/aws/lambda/secret-group"}}


class Denied(Exception):
    response = {"Error": {"Code": "AccessDeniedException", "Message": "arn:aws:iam::000000000000:user/x"}}


def _row(events, **fields):
    values = {"vehicles": "1", "excluded": "0", "cancelled": "0", "basis": "dashboard_filter", "outcome": "ok",
              "vehicle_id_given": "false", **fields}
    return [{"field": name, "value": value} for name, value in values.items()] + [{"field": "events", "value": str(events)}]


class FakeLogs:
    """Only StartQuery and GetQueryResults exist: any other call fails the test."""

    def __init__(self, results=None, *, missing=(), statuses=("Running", "Complete"), start_error=None):
        self.results = results or {}
        self.missing = set(missing)
        self.statuses = list(statuses)
        self.start_error = start_error
        self.started = []
        self.polls = 0

    def start_query(self, **kwargs):
        if self.start_error is not None:
            raise self.start_error
        if kwargs["logGroupName"] in self.missing:
            raise NotFound()
        self.started.append(kwargs)
        return {"queryId": kwargs["logGroupName"]}

    def get_query_results(self, *, queryId):
        self.polls += 1
        status = self.statuses[min(self.polls - 1, len(self.statuses) - 1)] if self.polls <= len(self.statuses) else "Complete"
        response = {"status": status}
        if status == "Complete":
            response["results"] = self.results.get(queryId, [])
            self.polls = 0
        return response


def run(argv, logs):
    out: list[str] = []
    clients = mcp_users.Clients(None, None, None, None, logs)
    code = mcp_users.main(["--env", "prod", *argv], clients=clients, out=out.append, clock=lambda: NOW)
    return code, out


def test_log_groups_are_the_two_mcp_functions():
    assert log_stats.mcp_log_groups("prod") == [
        ("multiuser", "/aws/lambda/honda-mapit-mcp-prod-mcp"),
        ("public web", "/aws/lambda/honda-mapit-mcp-prod-web-mcp"),
    ]


def test_vehicle_stats_prints_only_aggregated_counts(monkeypatch):
    monkeypatch.setattr(log_stats.time, "sleep", lambda _s: None)
    logs = FakeLogs({
        "/aws/lambda/honda-mapit-mcp-prod-mcp": [
            _row(5), _row(2, vehicles="2", outcome="selection_required"),
            _row(1, vehicles="2", excluded="1", vehicle_id_given="true"),
        ],
        "/aws/lambda/honda-mapit-mcp-prod-web-mcp": [_row(3, basis="legacy_fallback", excluded="2+")],
    })
    code, out = run(["vehicle-stats", "--days", "7"], logs)
    assert code == 0
    assert [call["logGroupName"] for call in logs.started] == [
        "/aws/lambda/honda-mapit-mcp-prod-mcp", "/aws/lambda/honda-mapit-mcp-prod-web-mcp"]
    for call in logs.started:
        assert call["queryString"] == log_stats.QUERY
        assert (call["startTime"], call["endTime"]) == (NOW - 7 * 86400, NOW)
    text = "\n".join(out)
    assert "multiuser: 8 vehicle_selection events in the last 7 days" in text
    assert "vehicles          1=5, 2=3" in text
    assert "outcome           ok=6, selection_required=2" in text
    assert "excluded          0=7, 1=1" in text
    assert "public web: 3 vehicle_selection events" in text
    assert "basis             legacy_fallback=3" in text
    assert "excluded          2+=3" in text


def test_unknown_values_are_counted_as_other_not_printed():
    total, totals = log_stats.summarize([{**{name: None for name in log_stats.DIMENSIONS},
                                          "vehicles": "veh-raw", "events": "4"}])
    assert total == 4 and totals["vehicles"] == {"other": 4}


def test_missing_log_group_is_reported_and_not_an_error(monkeypatch):
    monkeypatch.setattr(log_stats.time, "sleep", lambda _s: None)
    logs = FakeLogs(missing={"/aws/lambda/honda-mapit-mcp-prod-web-mcp"})
    code, out = run(["vehicle-stats"], logs)
    assert code == 0
    assert "public web: log group not present" in out
    assert "multiuser: 0 vehicle_selection events in the last 7 days" in out


@pytest.mark.parametrize("days", ["0", "15"])
def test_days_are_bounded_by_log_retention(days, capsys):
    logs = FakeLogs()
    code, _ = run(["vehicle-stats", "--days", days], logs)
    assert code == 1 and logs.started == []
    assert "--days must be between 1 and 14" in capsys.readouterr().err


def test_aws_failure_prints_only_the_code(capsys):
    code, out = run(["vehicle-stats"], FakeLogs(start_error=Denied()))
    assert code == 1 and out == []
    err = capsys.readouterr().err
    assert err == "error: vehicle_stats_failed: AccessDeniedException\n"


def test_failed_query_status_is_an_error(capsys, monkeypatch):
    monkeypatch.setattr(log_stats.time, "sleep", lambda _s: None)
    code, _ = run(["vehicle-stats"], FakeLogs(statuses=("Failed",)))
    assert code == 1 and "query ended with status Failed" in capsys.readouterr().err


def test_documented_query_is_the_one_the_command_runs():
    from pathlib import Path

    doc = (Path(__file__).resolve().parents[1] / "docs" / "phase-1-mcp-contracts.md").read_text(encoding="utf-8")
    section = doc.split("## Vehicle selection log", 1)[1]
    blocks = re.findall(r"```text\n(.*?)\n```", section, flags=re.S)
    # The first text block of the section is exactly the query the command runs.
    assert blocks and blocks[0] == log_stats.QUERY


SECRET = "arn:aws:iam::000000000000:role/private-profile token=abc123"


class LeakyClientError(Exception):
    """Shaped like botocore's ClientError: a code plus a message with private text."""

    def __init__(self, code):
        super().__init__(f"An error occurred ({code}): {SECRET}")
        self.response = {"Error": {"Code": code, "Message": SECRET}}


@pytest.mark.parametrize(("error", "label"), [
    (ValueError(f"Invalid endpoint {SECRET}"), "ValueError"),
    (RuntimeError(SECRET), "RuntimeError"),
    (LeakyClientError("AccessDeniedException"), "AccessDeniedException"),
    (LeakyClientError(f"bad code {SECRET}"), "LeakyClientError"),
])
def test_external_errors_print_only_a_fixed_category(error, label, capsys):
    code, out = run(["vehicle-stats"], FakeLogs(start_error=error))
    assert code == 1 and out == []
    err = capsys.readouterr().err
    assert err == f"error: vehicle_stats_failed: {label}\n"
    assert "private-profile" not in err and "abc123" not in err


def test_unknown_query_status_is_not_echoed(capsys, monkeypatch):
    monkeypatch.setattr(log_stats.time, "sleep", lambda _s: None)
    code, _ = run(["vehicle-stats"], FakeLogs(statuses=(SECRET,)))
    err = capsys.readouterr().err
    assert code == 1 and err == "error: query ended with status ?\n"


def test_query_parses_the_line_the_service_writes():
    """The Logs Insights regular expression matches the real line, field by field."""
    lines: list[str] = []
    set_read_meter_sink(lines.append)
    try:
        with metered_tool_call("list_vehicles"):
            MapitServices(fx.FakeClient(fx.SOLD_AND_ACTIVE)).list_vehicles()
        with pytest.raises(ServiceError):
            with metered_tool_call("get_distance"):
                MapitServices(fx.FakeClient(fx.TWO_ACTIVE)).get_distance("2026-03-01", "2026-04-01", vehicle_id="x")
    finally:
        set_read_meter_sink(None)
    filter_line, parse_line, _ = log_stats.QUERY.split("\n")
    parse = re.compile(parse_line.split("parse @message /", 1)[1].rsplit("/", 1)[0].replace("(?<", "(?P<"))
    marker = filter_line.split("/", 1)[1].rsplit("/", 1)[0]
    parsed = []
    for line in lines:
        record = json.loads(line)
        assert (marker in line) == (record["event"] == "vehicle_selection")
        if marker in line:
            match = parse.search(line)
            assert match is not None
            parsed.append(match.groupdict())
            assert match["vehicles"] == record["vehicles"] and match["outcome"] == record["outcome"]
            assert match["vehicle_id_given"] == json.dumps(record["vehicle_id_given"])
    assert parsed == [
        {"vehicles": "1", "cancelled": "0", "excluded": "1", "basis": "dashboard_filter",
         "vehicle_id_given": "false", "outcome": "ok"},
        {"vehicles": "2", "cancelled": "0", "excluded": "0", "basis": "dashboard_filter",
         "vehicle_id_given": "true", "outcome": "not_found"},
    ]
