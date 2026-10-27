"""Bounded real HTTP MCP acceptance checks for synthetic two-tenant DEV.

Tokens and response payloads stay in memory. The returned receipt is boolean
only. The injected revoker must commit and verify terminal A revocation before
returning True; a stub revoker is not hosted acceptance.
"""
from __future__ import annotations

import json
import math
import re
import time

from scripts.dev_multiuser_managed_login import direct_https_transport

TOOLS = frozenset({"get_vehicle_status", "get_vehicle_details", "list_routes",
    "get_route_detail", "get_distance", "compare_distance_periods", "get_route_statistics",
    "get_distance_breakdown", "get_route_extremes", "compare_route_periods"})


_ATTEMPT_INTERVAL = 1.1
_INITIAL_SETTLE = 3.0
_TOTAL_BUDGET = 120.0
_MAX_CALLS = 12
_MAX_RESPONSE_BYTES = 64 * 1024


class _E2EFailure(Exception):
    def __init__(self, category: str, stage: str, status: int | None = None):
        self.category = category
        self.stage = stage
        self.status = status


def run_http_acceptance(*, api_id, token_a, token_b, revoke_a,
                        transport=direct_https_transport, clock=time.monotonic,
                        sleeper=time.sleep):
    if (type(api_id) is not str or re.fullmatch(r"[a-z0-9]{10}", api_id) is None
        or any(type(token) is not str or not 0 < len(token) <= 8192 for token in (token_a, token_b))
        or not callable(revoke_a) or not callable(transport)
        or not callable(clock) or not callable(sleeper)):
        return {"success": False, "category": "binding_invalid"}
    try:
        began = clock()
        if type(began) not in (int, float) or isinstance(began, bool) or not math.isfinite(began):
            raise _E2EFailure("clock_invalid", "before_start")
    except _E2EFailure as exc:
        return {"success": False, "category": exc.category, "failure_stage": exc.stage, "calls": 0, "checks": {}}
    except Exception:
        return {"success": False, "category": "clock_invalid", "failure_stage": "before_start", "calls": 0, "checks": {}}
    calls = 0
    checks = {}
    last_clock = began
    last_attempt = None
    settled = False
    last_http_status = None

    def now(stage):
        nonlocal last_clock
        try:
            value = clock()
        except Exception as exc:
            raise _E2EFailure("clock_invalid", stage) from exc
        if (type(value) not in (int, float) or isinstance(value, bool)
                or not math.isfinite(value) or value < last_clock):
            raise _E2EFailure("clock_invalid", stage)
        last_clock = value
        return value

    def bounded_failure(category, stage, status=None):
        raise _E2EFailure(category, stage, status)

    def rpc(token, method, params=None):
        nonlocal calls, last_attempt, last_http_status, settled
        current = now("before_rpc")
        if current - began >= _TOTAL_BUDGET or calls >= _MAX_CALLS:
            bounded_failure("budget_exhausted", "before_rpc")
        if not settled:
            try:
                sleeper(_INITIAL_SETTLE)
            except Exception as exc:
                raise _E2EFailure("pacing_failed", "initial_settling") from exc
            current = now("after_settling")
            if current - began >= _TOTAL_BUDGET:
                bounded_failure("budget_exhausted", "after_settling")
            if current < began + _INITIAL_SETTLE:
                bounded_failure("pacing_failed", "after_settling")
            settled = True
        if last_attempt is not None:
            target = last_attempt + _ATTEMPT_INTERVAL
            if current < target:
                try:
                    sleeper(target - current)
                except Exception as exc:
                    raise _E2EFailure("pacing_failed", "before_rpc") from exc
                current = now("after_pacing")
                if current - began >= _TOTAL_BUDGET:
                    bounded_failure("budget_exhausted", "after_pacing")
                if current < target:
                    bounded_failure("pacing_failed", "after_pacing")
        # This timestamp is the attempt start.  A slow transport therefore
        # naturally contributes to the next interval and to the total budget.
        last_attempt = current
        calls += 1
        body = json.dumps({"jsonrpc": "2.0", "id": calls, "method": method,
                           "params": params or {}}, separators=(",", ":")).encode()
        url = f"https://{api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        try:
            response = transport("POST", url, headers, body, 10)
        except Exception as exc:
            raise _E2EFailure("transport_failed", "transport") from exc
        if now("after_transport") - began >= _TOTAL_BUDGET:
            bounded_failure("budget_exhausted", "after_transport")
        if response.url != url:
            bounded_failure("endpoint_mismatch", "response_endpoint")
        if type(response.status) is not int or not 100 <= response.status <= 599:
            bounded_failure("protocol_invalid", "response_status")
        last_http_status = response.status
        if response.status != 200:
            return response.status, {}
        if not isinstance(response.body, (bytes, bytearray)) or len(response.body) > _MAX_RESPONSE_BYTES:
            bounded_failure("protocol_invalid", "response_body")
        try:
            value = json.loads(response.body)
        except Exception as exc:
            raise _E2EFailure("protocol_invalid", "response_body") from exc
        if type(value) is not dict or value.get("jsonrpc") != "2.0" or value.get("id") != calls:
            bounded_failure("protocol_invalid", "response_jsonrpc")
        return response.status, value.get("result", {})

    def tool(token, name, args=None):
        return rpc(token, "tools/call", {"name": name, "arguments": args or {}})

    def content(result, stage):
        if (type(result) is not dict or result.get("isError") is not False
                or type(result.get("structuredContent")) is not dict):
            bounded_failure("http_acceptance_failed", stage, last_http_status)
        return result["structuredContent"]

    try:
        status, result = rpc(token_a, "initialize", {"protocolVersion": "2025-03-26",
            "capabilities": {}, "clientInfo": {"name": "dev-two-user-e2e", "version": "1"}})
        checks["initialize"] = status == 200 and type(result) is dict and result.get("protocolVersion") == "2025-03-26"
        if not checks["initialize"]:
            bounded_failure("http_acceptance_failed", "initialize", status)
        status, result = rpc(token_a, "tools/list")
        tools = result.get("tools") if type(result) is dict else None
        names = [row.get("name") for row in tools] if isinstance(tools, list) and all(type(row) is dict for row in tools) else []
        checks["tools_exact"] = status == 200 and isinstance(tools, list) and len(names) == 10 and set(names) == TOOLS
        if not checks["tools_exact"]:
            bounded_failure("http_acceptance_failed", "tools_list", status)
        for slot, token, label, km in (("a", token_a, "synthetic-A", 11), ("b", token_b, "synthetic-B", 22)):
            status, result = tool(token, "get_vehicle_status")
            checks[f"tenant_{slot}_status"] = status == 200 and content(result, f"tenant_{slot}_status").get("status") == label
            if not checks[f"tenant_{slot}_status"]:
                bounded_failure("http_acceptance_failed", f"tenant_{slot}_status", status)
            status, result = tool(token, "get_distance", {"from_time": "2026-01-01T00:00:00Z", "to_time": "2026-01-02T00:00:00Z"})
            data = content(result, f"tenant_{slot}_distance")
            checks[f"tenant_{slot}_distance"] = status == 200 and data.get("distance_km") == km and data.get("route_count") == 1
            if not checks[f"tenant_{slot}_distance"]:
                bounded_failure("http_acceptance_failed", f"tenant_{slot}_distance", status)
        status, result = tool(token_a, "get_route_detail", {"route_id": "synthetic-B-route"})
        checks["foreign_route_denied"] = status in {401, 403} or (status == 200 and type(result) is dict and result.get("isError") is True)
        if not checks["foreign_route_denied"]:
            bounded_failure("http_acceptance_failed", "foreign_route", status)
        status, _ = rpc(None, "tools/list")
        checks["anonymous_denied"] = status in {401, 403}
        if not checks["anonymous_denied"]:
            bounded_failure("http_acceptance_failed", "anonymous_access", status)
        checks["revocation_committed"] = revoke_a() is True
        if now("after_revocation") - began >= _TOTAL_BUDGET:
            bounded_failure("budget_exhausted", "after_revocation")
        if not checks["revocation_committed"]:
            bounded_failure("http_acceptance_failed", "revocation")
        status, result = tool(token_a, "get_vehicle_status")
        checks["revoked_a_denied"] = status in {401, 403} or (status == 200 and type(result) is dict and result.get("isError") is True)
        if not checks["revoked_a_denied"]:
            bounded_failure("http_acceptance_failed", "revoked_a_access", status)
        status, result = tool(token_b, "get_vehicle_status")
        checks["b_after_a_revocation"] = status == 200 and content(result, "tenant_b_after_revocation").get("status") == "synthetic-B"
        if not checks["b_after_a_revocation"]:
            bounded_failure("http_acceptance_failed", "tenant_b_after_revocation", status)
        return {"success": all(checks.values()), "category": "http_acceptance_verified" if all(checks.values()) else "http_acceptance_failed", "calls": calls, "checks": checks}
    except _E2EFailure as exc:
        result = {"success": False, "category": exc.category, "failure_stage": exc.stage,
                  "calls": calls, "checks": checks}
        if exc.status is not None:
            result["http_status"] = exc.status
        return result
    except Exception:
        # Never return exception text: transports may include URLs, token
        # fragments, provider diagnostics, or response bodies.
        result = {"success": False, "category": "http_acceptance_failed",
                  "failure_stage": "unexpected", "calls": calls, "checks": checks}
        if last_http_status is not None:
            result["http_status"] = last_http_status
        return result
