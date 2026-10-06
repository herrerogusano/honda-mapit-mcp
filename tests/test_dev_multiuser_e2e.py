import json

from scripts.dev_multiuser_e2e import TOOLS, run_http_acceptance
from scripts.dev_multiuser_managed_login import HttpResponse


def test_bounded_http_protocol_and_isolation_receipt():
    revoked = False
    calls = []

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

    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=revoke, transport=transport)
    assert result["success"] is True
    assert result["calls"] == 10 and len(calls) == 10
    assert "Bearer" not in repr(result)


def test_failed_revocation_does_not_issue_more_business_calls():
    from unittest.mock import Mock
    transport = Mock(return_value=HttpResponse(503, "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp", {}, b"{}"))
    result = run_http_acceptance(api_id="abcdefghij", token_a="a", token_b="b", revoke_a=lambda: False, transport=transport)
    assert result["success"] is False
    assert result["calls"] <= 12


def test_invalid_api_binding_calls_nothing():
    from unittest.mock import Mock
    transport = Mock()
    result = run_http_acceptance(api_id="prod.invalid", token_a="a", token_b="b", revoke_a=lambda: True, transport=transport)
    assert result["success"] is False
    transport.assert_not_called()
