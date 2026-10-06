"""Bounded real HTTP MCP acceptance checks for synthetic two-tenant DEV.

Tokens and response payloads stay in memory. The returned receipt is boolean
only. The injected revoker must commit and verify terminal A revocation before
returning True; a stub revoker is not hosted acceptance.
"""
from __future__ import annotations

import json
import re
import time

from scripts.dev_multiuser_managed_login import direct_https_transport

TOOLS = frozenset({"get_vehicle_status", "get_vehicle_details", "list_routes",
    "get_route_detail", "get_distance", "compare_distance_periods", "get_route_statistics",
    "get_distance_breakdown", "get_route_extremes", "compare_route_periods"})


def run_http_acceptance(*, api_id, token_a, token_b, revoke_a,
                        transport=direct_https_transport, clock=time.monotonic):
    if (type(api_id) is not str or re.fullmatch(r"[a-z0-9]{10}", api_id) is None
        or any(type(token) is not str or not 0 < len(token) <= 8192 for token in (token_a, token_b))
        or not callable(revoke_a)):
        return {"success": False, "category": "binding_invalid"}
    began = clock()
    calls = 0
    checks = {}

    def rpc(token, method, params=None):
        nonlocal calls
        elapsed = clock() - began
        if not 0 <= elapsed < 120 or calls >= 12:
            raise ValueError("budget_exhausted")
        calls += 1
        body = json.dumps({"jsonrpc": "2.0", "id": calls, "method": method,
                           "params": params or {}}, separators=(",", ":")).encode()
        url = f"https://{api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        response = transport("POST", url, headers, body, 10)
        if response.url != url:
            raise ValueError("endpoint_mismatch")
        if response.status != 200:
            return response.status, {}
        value = json.loads(response.body)
        if type(value) is not dict or value.get("jsonrpc") != "2.0" or value.get("id") != calls:
            raise ValueError("protocol_invalid")
        return response.status, value.get("result", {})

    def tool(token, name, args=None):
        return rpc(token, "tools/call", {"name": name, "arguments": args or {}})

    def content(result):
        if result.get("isError") is not False or type(result.get("structuredContent")) is not dict:
            raise ValueError("tool_failed")
        return result["structuredContent"]

    try:
        status, result = rpc(token_a, "initialize", {"protocolVersion": "2025-03-26",
            "capabilities": {}, "clientInfo": {"name": "dev-two-user-e2e", "version": "1"}})
        checks["initialize"] = status == 200 and result.get("protocolVersion") == "2025-03-26"
        status, result = rpc(token_a, "tools/list")
        names = [row.get("name") for row in result.get("tools", [])]
        checks["tools_exact"] = status == 200 and len(names) == 10 and set(names) == TOOLS
        for slot, token, label, km in (("a", token_a, "synthetic-A", 11), ("b", token_b, "synthetic-B", 22)):
            status, result = tool(token, "get_vehicle_status")
            checks[f"tenant_{slot}_status"] = status == 200 and content(result).get("status") == label
            status, result = tool(token, "get_distance", {"from_time": "2026-01-01T00:00:00Z", "to_time": "2026-01-02T00:00:00Z"})
            data = content(result)
            checks[f"tenant_{slot}_distance"] = status == 200 and data.get("distance_km") == km and data.get("route_count") == 1
        status, result = tool(token_a, "get_route_detail", {"route_id": "synthetic-B-route"})
        checks["foreign_route_denied"] = status in {401, 403} or status == 200 and result.get("isError") is True
        status, _ = rpc(None, "tools/list")
        checks["anonymous_denied"] = status in {401, 403}
        checks["revocation_committed"] = revoke_a() is True
        if not checks["revocation_committed"]:
            raise ValueError("revocation_unverified")
        status, result = tool(token_a, "get_vehicle_status")
        checks["revoked_a_denied"] = status in {401, 403} or status == 200 and result.get("isError") is True
        status, result = tool(token_b, "get_vehicle_status")
        checks["b_after_a_revocation"] = status == 200 and content(result).get("status") == "synthetic-B"
        return {"success": all(checks.values()), "category": "http_acceptance_verified" if all(checks.values()) else "http_acceptance_failed", "calls": calls, "checks": checks}
    except Exception:
        return {"success": False, "category": "http_acceptance_failed", "calls": calls, "checks": checks}
