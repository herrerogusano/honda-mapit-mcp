from __future__ import annotations

import json
import pytest

from scripts import probe_codex_app_server as probe
from test_probe_codex_app_server import FakeProtocol


class DiscoveryProtocol(FakeProtocol):
    def __init__(self, names):
        super().__init__()
        self.names = names
    def send(self, raw):
        request = json.loads(raw)
        if request.get("method") == "mcpServerStatus/list":
            self.requests.append(request)
            self.incoming.append(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {
                "data": [{"name": probe.SERVER_NAME, "authStatus": "oAuth", "runtimeStatus": "connected",
                          "tools": {name: {} for name in self.names}}], "nextCursor": None,
            }}).encode())
        else:
            super().send(raw)


def test_discovery_requires_exact_twelve_and_never_calls_a_tool_or_model():
    protocol = DiscoveryProtocol(probe._GEOGRAPHIC_DISCOVERY_TOOLS)
    result = probe.run_protocol(protocol.send, protocol.receive, discovery_only=True)
    assert result.success is True and result.tool_call_count == 0
    methods = [request["method"] for request in protocol.requests]
    assert methods == ["initialize", "initialized", "thread/start", "mcpServerStatus/list"]


@pytest.mark.parametrize("names", [
    {"get_vehicle_status", "get_distance"},
    probe._GEOGRAPHIC_DISCOVERY_TOOLS | {"unexpected"},
    probe._GEOGRAPHIC_DISCOVERY_TOOLS - {"summer_geographic_summary"},
])
def test_discovery_rejects_old_incomplete_or_expanded_catalog_without_calls(names):
    protocol = DiscoveryProtocol(names)
    result = probe.run_protocol(protocol.send, protocol.receive, discovery_only=True)
    assert result.success is False and result.category == "tools_unavailable"
    assert not any(request["method"] == "mcpServer/tool/call" for request in protocol.requests)


def test_discovery_mode_cannot_be_truthy_nonboolean():
    result = probe.run_protocol(lambda _: pytest.fail("write"), lambda _: None, discovery_only=1)
    assert result.success is False and result.request_count == 0
