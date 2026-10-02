from __future__ import annotations

import json

import pytest

from scripts.probe_codex_app_server import (
    SERVER_NAME,
    SmokeError,
    build_command,
    read_configured_server_names,
    run_protocol,
    run_smoke,
    validate_server_url,
)


URL = "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp"
TOOLS = {"get_vehicle_status": {}, "get_distance": {}}


class FakeProtocol:
    def __init__(self, *, ephemeral=True, bad_tool=False):
        self.ephemeral = ephemeral
        self.bad_tool = bad_tool
        self.requests = []
        self.incoming = []

    def send(self, raw):
        request = json.loads(raw)
        self.requests.append(request)
        if "id" not in request:
            assert request == {"jsonrpc": "2.0", "method": "initialized", "params": {}}
            return
        method = request["method"]
        if method == "initialize":
            result = {
                "userAgent": "codex-cli/0.159.2",
                "platformOs": "windows",
                "platformFamily": "windows",
                "codexHome": "C:/private/codex-home",
            }
        elif method == "thread/start":
            result = {"thread": {"id": "ephemeral-private-id", "ephemeral": self.ephemeral}}
        elif method == "mcpServerStatus/list":
            assert request["params"] == {
                "serverName": SERVER_NAME,
                "threadId": "ephemeral-private-id",
                "limit": 1,
                "detail": "toolsAndAuthOnly",
            }
            result = {
                "data": [{"name": SERVER_NAME, "authStatus": "oAuth", "runtimeStatus": "connected", "tools": TOOLS}],
                "nextCursor": None,
            }
        elif method == "mcpServer/tool/call":
            self_call = request["params"]
            expected = ["get_vehicle_status", "get_distance"]
            prior_calls = sum(item["method"] == method for item in self.requests[:-1])
            assert self_call["tool"] == expected[prior_calls]
            result = {"isError": False, "structuredContent": {"synthetic": True}}
        elif method == "turn/start" or method == "turn/steer":
            raise AssertionError("model inference method must never be sent")
        else:
            raise AssertionError(f"unexpected method {method}")
        self.incoming.append(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())

    def receive(self, deadline):
        return self.incoming.pop(0) if self.incoming else None


def test_model_free_protocol_uses_only_fixed_methods_and_ephemeral_thread():
    peer = FakeProtocol()
    result = run_protocol(peer.send, peer.receive)
    assert result.safe_dict() == {
        "success": True,
        "category": "success",
        "request_count": 6,
        "tool_call_count": 2,
    }
    methods = [item["method"] for item in peer.requests]
    assert methods == [
        "initialize", "initialized", "thread/start", "mcpServerStatus/list",
        "mcpServer/tool/call", "mcpServer/tool/call",
    ]
    assert "turn/start" not in methods
    start = peer.requests[2]
    assert start["params"] == {"ephemeral": True}
    calls = [request["params"] for request in peer.requests if request["method"] == "mcpServer/tool/call"]
    assert calls == [
        {"server": SERVER_NAME, "threadId": "ephemeral-private-id", "tool": "get_vehicle_status", "arguments": {}},
        {
            "server": SERVER_NAME,
            "threadId": "ephemeral-private-id",
            "tool": "get_distance",
            "arguments": {"from_time": "2026-01-01", "to_time": "2026-02-01"},
        },
    ]
    assert "ephemeral-private-id" not in json.dumps(result.safe_dict())


def test_non_ephemeral_response_fails_before_any_tool_dispatch():
    peer = FakeProtocol(ephemeral=False)
    result = run_protocol(peer.send, peer.receive)
    assert result.category == "ephemeral_thread_unconfirmed"
    assert result.tool_call_count == 0
    assert not any(request["method"] == "mcpServer/tool/call" for request in peer.requests)


def test_initialize_requires_installed_schema_fields_without_returning_codex_home():
    peer = FakeProtocol()
    original = peer.send

    def send_missing_platform(raw):
        request = json.loads(raw)
        original(raw)
        if request.get("method") == "initialize":
            response = json.loads(peer.incoming[-1])
            response["result"].pop("platformFamily")
            peer.incoming[-1] = json.dumps(response).encode()

    peer.send = send_missing_platform
    result = run_protocol(peer.send, peer.receive)
    assert result.category == "protocol_failed"
    assert result.tool_call_count == 0
    assert "private" not in json.dumps(result.safe_dict())


def test_status_requires_both_fixed_tools_and_no_next_page():
    peer = FakeProtocol()
    original = peer.send

    def send_without_tool(raw):
        request = json.loads(raw)
        original(raw)
        if request.get("method") == "mcpServerStatus/list":
            response = json.loads(peer.incoming[-1])
            response["result"]["data"][0]["tools"] = {"get_vehicle_status": {}}
            peer.incoming[-1] = json.dumps(response).encode()

    peer.send = send_without_tool
    result = run_protocol(peer.send, peer.receive)
    assert result.category == "tools_unavailable"
    assert result.tool_call_count == 0

    peer = FakeProtocol()
    original = peer.send

    def send_with_cursor(raw):
        request = json.loads(raw)
        original(raw)
        if request.get("method") == "mcpServerStatus/list":
            response = json.loads(peer.incoming[-1])
            response["result"]["nextCursor"] = "must-not-page"
            peer.incoming[-1] = json.dumps(response).encode()

    peer.send = send_with_cursor
    assert run_protocol(peer.send, peer.receive).category == "server_unavailable"


def test_tool_failure_is_redacted_and_does_not_call_next_tool():
    peer = FakeProtocol()
    original = peer.send

    def send_error(raw):
        request = json.loads(raw)
        original(raw)
        if request.get("method") == "mcpServer/tool/call":
            response = json.loads(peer.incoming[-1])
            response["result"]["isError"] = True
            response["result"]["structuredContent"] = {"private": "canary"}
            peer.incoming[-1] = json.dumps(response).encode()

    peer.send = send_error
    result = run_protocol(peer.send, peer.receive)
    assert result.category == "tool_call_failed"
    assert result.tool_call_count == 0
    assert "canary" not in json.dumps(result.safe_dict())


def test_command_disables_every_other_named_server_and_plugins():
    command = build_command("codex", URL, ("another-server", SERVER_NAME, "local"))
    assert command[:5] == ["codex", "app-server", "--listen", "stdio://", "--disable"]
    assert command[5] == "plugins"
    config = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "-c"]
    assert "mcp_servers.another-server.enabled=false" in config
    assert "mcp_servers.local.enabled=false" in config
    assert f"mcp_servers.{SERVER_NAME}.enabled=true" in config
    assert f"mcp_servers.{SERVER_NAME}.required=true" in config
    assert not any(item.startswith(f"mcp_servers.{SERVER_NAME}.url=") for item in config)
    assert all("turn/start" not in part for part in command)


def test_config_name_reader_returns_only_names_not_values(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        '[mcp_servers."honda-mapit-dev-e2e"]\nurl="' + URL + '"\n'
        '[mcp_servers."unrelated"]\nurl="https://secret.invalid/?canary"\n',
        encoding="utf-8",
    )
    names = read_configured_server_names(URL, path)
    assert names == (SERVER_NAME, "unrelated")
    assert "secret" not in repr(names)


def test_configured_target_url_must_match_explicit_url_before_launch(tmp_path, monkeypatch):
    config_home = tmp_path / "codex-home"
    config_home.mkdir()
    config = config_home / "config.toml"
    config.write_text(
        '[mcp_servers."honda-mapit-dev-e2e"]\nurl="https://f6e5d4c3b2.execute-api.eu-west-1.amazonaws.com/mcp"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(config_home))
    launched = []
    monkeypatch.setattr("scripts.probe_codex_app_server._launch", lambda *args: launched.append(args))
    result = run_smoke(URL, executable="codex")
    assert result.category == "configuration_unavailable"
    assert launched == []


def test_matching_configured_url_is_passed_unchanged_to_fixed_server_launcher(tmp_path, monkeypatch):
    config_home = tmp_path / "codex-home"
    config_home.mkdir()
    (config_home / "config.toml").write_text(
        '[mcp_servers."honda-mapit-dev-e2e"]\nurl="' + URL + '"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(config_home))
    from scripts import probe_codex_app_server

    launched = []
    expected = probe_codex_app_server.SmokeResult(True, "success", 6, 2)
    monkeypatch.setattr(probe_codex_app_server, "_launch", lambda *args: launched.append(args) or expected)
    result = probe_codex_app_server.run_smoke(URL, executable="codex")
    assert result is expected
    assert launched == [("codex", URL, (SERVER_NAME,))]


@pytest.mark.parametrize("value", [
    "http://a.example/mcp",
    "https://a.example/mcp",
    "https://user:pass@a.example/mcp",
    "https://a.example/mcp?token=x",
    "https://a.example/mcp#frag",
    "https://a.example/other",
    "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com:443/mcp",
    "https://a.example/mcp\r\nInjected: yes",
    "\\\\host\\path",
])
def test_url_rejects_non_https_credentials_query_fragment_and_header_injection(value):
    with pytest.raises(SmokeError):
        validate_server_url(value)
