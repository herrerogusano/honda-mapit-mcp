import json
from unittest.mock import Mock

from scripts.dev_multiuser_e2e import TOOLS, run_http_acceptance
from scripts.dev_multiuser_managed_login import HttpResponse


class _FakeClock:
    def __init__(self):
        self.value = 100.0
        self.sleeps = []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def test_bounded_http_protocol_and_isolation_receipt():
    revoked = False
    calls = []
    clock = _FakeClock()

    def revoke():
        nonlocal revoked
        revoked = True
        return True

    def transport(method, url, headers, body, timeout):
        request = json.loads(body)
        calls.append(request)
        token = headers.get("Authorization")
        if token is None:
            return HttpResponse(401, url, {}, b"{}")
        params = request["params"]
        rpc = request["method"]
        if rpc == "initialize":
            result = {"protocolVersion": "2025-03-26"}
        elif rpc == "tools/list":
            result = {"tools": [{"name": name} for name in TOOLS]}
        elif params["name"] == "get_route_detail" or token == "Bearer a" and revoked:
            result = {"isError": True}
        else:
            data = {"status": "synthetic-A" if token == "Bearer a" else "synthetic-B"}
            if params["name"] == "get_distance":
                data = {"distance_km": 11 if token == "Bearer a" else 22, "route_count": 1}
            result = {"isError": False, "structuredContent": data}
        return HttpResponse(200, url, {}, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=revoke,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["success"] is True
    assert result["calls"] == 10 and len(calls) == 10
    assert len(clock.sleeps) == 10 and clock.sleeps[0] == 3.0
    assert all(value >= 1.1 - 1e-9 for value in clock.sleeps[1:])
    assert "Bearer" not in repr(result)


def test_failed_revocation_does_not_issue_more_business_calls():
    from unittest.mock import Mock
    clock = _FakeClock()
    transport = Mock(return_value=HttpResponse(503, "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp", {}, b"{}"))
    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: False,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["success"] is False
    assert result["calls"] <= 12


def test_invalid_api_binding_calls_nothing():
    from unittest.mock import Mock
    transport = Mock()
    result = run_http_acceptance(api_id="prod.invalid", token_a="a", token_b="b", revoke_a=lambda: True, transport=transport)
    assert result["success"] is False
    transport.assert_not_called()


def test_clock_regression_fails_closed_without_retry():
    values = iter((10.0, 10.0, 9.9))
    transport = Mock(return_value=HttpResponse(200, "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp", {}, b"{}"))
    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=lambda: next(values), sleeper=lambda _: None)
    assert result["success"] is False
    assert result["category"] == "clock_invalid"
    assert result["failure_stage"] == "after_settling"
    assert result["calls"] == 0
    transport.assert_not_called()


def test_sleep_that_does_not_advance_clock_fails_closed():
    transport = Mock()
    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=lambda: 1.0, sleeper=lambda _: None)
    assert result["success"] is False
    assert result["category"] == "pacing_failed"
    assert result["failure_stage"] == "after_settling"
    transport.assert_not_called()


def test_initialize_failure_stops_before_tools_or_business_calls():
    clock = _FakeClock()
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append(json.loads(body)["method"])
        return HttpResponse(401, url, {}, b"{}")

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["category"] == "http_acceptance_failed"
    assert result["failure_stage"] == "initialize"
    assert result["http_status"] == 401
    assert result["calls"] == 1 and calls == ["initialize"]
    assert "Bearer" not in repr(result)


def test_tools_failure_stops_before_business_calls():
    clock = _FakeClock()
    calls = []

    def transport(method, url, headers, body, timeout):
        request = json.loads(body)
        calls.append(request["method"])
        if request["method"] == "initialize":
            value = {"protocolVersion": "2025-03-26"}
        else:
            value = {"tools": []}
        return HttpResponse(200, url, {}, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": value}).encode())

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["failure_stage"] == "tools_list"
    assert result["calls"] == 2 and calls == ["initialize", "tools/list"]


def test_late_transport_is_budgeted_after_response_without_retry():
    clock = _FakeClock()
    calls = []

    def transport(method, url, headers, body, timeout):
        calls.append(1)
        clock.value += 121.0
        return HttpResponse(200, url, {}, b"{}")

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["category"] == "budget_exhausted", result
    assert result["failure_stage"] == "after_transport"
    assert result["calls"] == 1 and len(calls) == 1


def test_late_revocation_is_budgeted_before_followup_calls():
    clock = _FakeClock()
    revoked = False

    def transport(method, url, headers, body, timeout):
        request = json.loads(body)
        if headers.get("Authorization") is None:
            status, result = 401, {}
        elif request["method"] == "initialize":
            status, result = 200, {"protocolVersion": "2025-03-26"}
        elif request["method"] == "tools/list":
            status, result = 200, {"tools": [{"name": name} for name in TOOLS]}
        elif request["params"]["name"] == "get_route_detail" or (request["params"]["name"] == "get_vehicle_status" and revoked):
            status, result = 200, {"isError": True}
        else:
            token = headers["Authorization"]
            data = {"status": "synthetic-A" if token == "Bearer a" else "synthetic-B"}
            if request["params"]["name"] == "get_distance":
                data = {"distance_km": 11 if token == "Bearer a" else 22, "route_count": 1}
            status, result = 200, {"isError": False, "structuredContent": data}
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode() if status == 200 else b"{}"
        return HttpResponse(status, url, {}, body)

    def revoke():
        nonlocal revoked
        revoked = True
        clock.value = 220.0
        return True

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=revoke,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["category"] == "budget_exhausted", result
    assert result["failure_stage"] == "after_revocation"
    assert result["calls"] == 8


def test_max_call_guard_is_strict(monkeypatch):
    import scripts.dev_multiuser_e2e as e2e
    clock = _FakeClock()
    monkeypatch.setattr(e2e, "_MAX_CALLS", 1)

    def transport(method, url, headers, body, timeout):
        request = json.loads(body)
        result = {"protocolVersion": "2025-03-26"} if request["method"] == "initialize" else {}
        return HttpResponse(200, url, {}, json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: True,
                                 transport=transport, clock=clock, sleeper=clock.sleep)
    assert result["category"] == "budget_exhausted"
    assert result["failure_stage"] == "before_rpc"
    assert result["calls"] == 1


def test_transport_exception_and_body_are_never_projected():
    clock = _FakeClock()

    def transport(method, url, headers, body, timeout):
        raise RuntimeError("secret-token https://private.invalid/body")

    result = run_http_acceptance(api_id="abcdefghij", token_a="secret-token", token_b="other-secret",
                                 revoke_a=lambda: True, transport=transport,
                                 clock=clock, sleeper=clock.sleep)
    assert result["category"] == "transport_failed"
    assert result["failure_stage"] == "transport"
    assert "secret-token" not in repr(result)
    assert "private.invalid" not in repr(result)
