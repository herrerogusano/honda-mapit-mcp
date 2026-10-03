"""Model-free smoke check for the fixed synthetic Codex MCP server.

This helper speaks only app-server JSON-RPC. It starts one ephemeral thread,
checks the target server's advertised tools, and directly calls two fixed
synthetic tools. It never sends turn/start and never prints IDs, URLs, results,
tokens, or raw process output.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.smoke_codex_mcp_phase4 import scrub_child_environment

SERVER_NAME = "honda-mapit-dev-e2e"
MAX_SECONDS = 60.0
MAX_REQUESTS = 20
MAX_LINE_BYTES = 256 * 1024
MAX_STDOUT_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CONFIG_SERVERS = 64
_SERVER_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_DEV_API_HOST = re.compile(r"^[a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com$")
_SAFE_CATEGORIES = frozenset({
    "success", "invalid_server_url", "codex_missing", "configuration_unavailable",
    "app_server_failed", "protocol_failed", "ephemeral_thread_unconfirmed",
    "server_unavailable", "tools_unavailable", "tool_call_failed", "deadline_exceeded",
})
_CALLS = (
    ("get_vehicle_status", {}),
    ("get_distance", {"from_time": "2026-01-01", "to_time": "2026-02-01"}),
)
_GEOGRAPHIC_DISCOVERY_TOOLS = frozenset({
    "get_vehicle_status", "get_vehicle_details", "list_routes", "get_route_detail",
    "get_distance", "compare_distance_periods", "get_route_statistics",
    "get_distance_breakdown", "get_route_extremes", "compare_route_periods",
    "geographic_summary", "summer_geographic_summary",
})


class SmokeError(RuntimeError):
    """A fixed, output-safe failure category."""


@dataclass(frozen=True)
class SmokeResult:
    success: bool
    category: str
    request_count: int
    tool_call_count: int

    def safe_dict(self) -> dict[str, object]:
        category = self.category if self.category in _SAFE_CATEGORIES else "app_server_failed"
        return {
            "success": category == "success" and self.success is True,
            "category": category,
            "request_count": self.request_count,
            "tool_call_count": self.tool_call_count,
        }


def validate_server_url(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise SmokeError("invalid_server_url")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in value) or "\\" in value:
        raise SmokeError("invalid_server_url")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise SmokeError("invalid_server_url") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not _DEV_API_HOST.fullmatch(parsed.hostname)
        or parsed.port is not None
        or parsed.netloc != parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp"
    ):
        raise SmokeError("invalid_server_url")
    return value


def read_configured_server_names(
    expected_server_url: str,
    config_path: Path | None = None,
) -> tuple[str, ...]:
    """Read bounded MCP names and require the fixed target's literal URL match."""
    expected_url = validate_server_url(expected_server_url)
    if config_path is None:
        codex_home = os.environ.get("CODEX_HOME")
        root = Path(codex_home) if codex_home else Path.home() / ".codex"
        config_path = root / "config.toml"
    try:
        if config_path.is_symlink() or config_path.stat().st_size > MAX_CONFIG_BYTES:
            raise SmokeError("configuration_unavailable")
        with config_path.open("rb") as source:
            raw = source.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise SmokeError("configuration_unavailable")
        config = tomllib.loads(raw.decode("utf-8"))
    except SmokeError:
        raise
    except Exception:
        raise SmokeError("configuration_unavailable") from None
    servers = config.get("mcp_servers", {})
    if not isinstance(servers, dict) or len(servers) > MAX_CONFIG_SERVERS:
        raise SmokeError("configuration_unavailable")
    target_config = servers.get(SERVER_NAME)
    if (
        not isinstance(target_config, dict)
        or type(target_config.get("url")) is not str
        or target_config.get("url") != expected_url
    ):
        raise SmokeError("configuration_unavailable")
    names = set(servers)
    if any(not isinstance(name, str) or not _SERVER_KEY.fullmatch(name) for name in names):
        raise SmokeError("configuration_unavailable")
    return tuple(sorted(names))


def build_command(executable: str, server_url: str, configured_names: tuple[str, ...]) -> list[str]:
    """Build command-local overrides: disable all configured MCPs except target."""
    validate_server_url(server_url)
    if not isinstance(executable, str) or not executable or len(executable) > 4096:
        raise SmokeError("codex_missing")
    if not isinstance(configured_names, tuple) or len(configured_names) > MAX_CONFIG_SERVERS + 1:
        raise SmokeError("configuration_unavailable")
    if (
        any(not isinstance(name, str) or not _SERVER_KEY.fullmatch(name) for name in configured_names)
        or SERVER_NAME not in configured_names
    ):
        raise SmokeError("configuration_unavailable")
    args = [executable, "app-server", "--listen", "stdio://", "--disable", "plugins"]
    for name in configured_names:
        if name != SERVER_NAME:
            args.extend(("-c", f"mcp_servers.{name}.enabled=false"))
    args.extend((
        "-c", f"mcp_servers.{SERVER_NAME}.enabled=true",
        "-c", f"mcp_servers.{SERVER_NAME}.required=true",
    ))
    return args


def _rpc(method: str, params: Mapping[str, Any] | None = None, request_id: int | None = None) -> bytes:
    request: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        request["id"] = request_id
    if params is not None:
        request["params"] = dict(params)
    encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
    if len(encoded) > MAX_LINE_BYTES:
        raise SmokeError("protocol_failed")
    return encoded


def run_protocol(
    send: Callable[[bytes], None],
    receive: Callable[[float], bytes | None],
    *,
    deadline: float | None = None,
    discovery_only: bool = False,
) -> SmokeResult:
    """Run exactly initialize, ephemeral start, filtered status, and two fixed calls."""
    deadline = time.monotonic() + MAX_SECONDS if deadline is None else deadline
    count = 0
    successful_calls = 0
    if type(discovery_only) is not bool:
        return SmokeResult(False, "protocol_failed", 0, 0)

    def exchange(method: str, params: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        nonlocal count
        if count >= MAX_REQUESTS or time.monotonic() >= deadline:
            raise SmokeError("deadline_exceeded")
        count += 1
        request_id = count
        send(_rpc(method, params, request_id))
        while time.monotonic() < deadline:
            line = receive(deadline)
            if line is None:
                raise SmokeError("deadline_exceeded")
            if not isinstance(line, bytes) or len(line) > MAX_LINE_BYTES:
                raise SmokeError("protocol_failed")
            try:
                message = json.loads(line)
            except (UnicodeError, json.JSONDecodeError, TypeError):
                raise SmokeError("protocol_failed") from None
            if not isinstance(message, dict):
                raise SmokeError("protocol_failed")
            # App-server notifications may interleave. Server-initiated requests
            # are outside this fixed protocol and are rejected, never answered.
            if "method" in message and "id" in message:
                raise SmokeError("protocol_failed")
            if "id" not in message:
                continue
            if message.get("id") != request_id:
                raise SmokeError("protocol_failed")
            if "error" in message or not isinstance(message.get("result"), dict):
                raise SmokeError("protocol_failed")
            return message["result"]
        raise SmokeError("deadline_exceeded")

    try:
        initialized = exchange("initialize", {
            "clientInfo": {"name": "honda-mapit-smoke", "title": "Honda MAPIT smoke", "version": "1"},
            "capabilities": {},
        })
        # The installed v1 InitializeResponse has these four required fields;
        # codexHome is validated but never included in the safe result.
        if any(
            not isinstance(initialized.get(name), str) or not initialized[name]
            for name in ("userAgent", "platformOs", "platformFamily", "codexHome")
        ):
            raise SmokeError("protocol_failed")
        # A JSON-RPC notification (no request id) completes the handshake.
        if count >= MAX_REQUESTS or time.monotonic() >= deadline:
            raise SmokeError("deadline_exceeded")
        count += 1
        send(_rpc("initialized", {}))

        started = exchange("thread/start", {"ephemeral": True})
        thread = started.get("thread")
        if not isinstance(thread, dict) or thread.get("ephemeral") is not True:
            raise SmokeError("ephemeral_thread_unconfirmed")
        thread_id = thread.get("id")
        if not isinstance(thread_id, str) or not thread_id or len(thread_id) > 256:
            raise SmokeError("protocol_failed")

        status_result = exchange("mcpServerStatus/list", {
            "serverName": SERVER_NAME,
            "threadId": thread_id,
            "limit": 1,
            "detail": "toolsAndAuthOnly",
        })
        data = status_result.get("data")
        if (
            not isinstance(data, list)
            or len(data) != 1
            or not isinstance(data[0], dict)
            or status_result.get("nextCursor") is not None
        ):
            raise SmokeError("server_unavailable")
        server = data[0]
        tools = server.get("tools")
        if (
            server.get("name") != SERVER_NAME
            or server.get("authStatus") != "oAuth"
            or server.get("runtimeStatus") != "connected"
            or not isinstance(tools, dict)
            or any(name not in tools for name, _args in _CALLS)
            or (discovery_only and set(tools) != _GEOGRAPHIC_DISCOVERY_TOOLS)
        ):
            raise SmokeError("tools_unavailable")

        if discovery_only:
            return SmokeResult(True, "success", count, 0)
        for name, arguments in _CALLS:
            result = exchange("mcpServer/tool/call", {
                "server": SERVER_NAME,
                "threadId": thread_id,
                "tool": name,
                "arguments": arguments,
            })
            structured = result.get("structuredContent")
            if result.get("isError") is not False or not isinstance(structured, dict):
                raise SmokeError("tool_call_failed")
            successful_calls += 1
        return SmokeResult(True, "success", count, successful_calls)
    except SmokeError as exc:
        category = str(exc) if str(exc) in _SAFE_CATEGORIES else "protocol_failed"
        return SmokeResult(False, category, count, successful_calls)
    except Exception:
        return SmokeResult(False, "app_server_failed", count, successful_calls)


class _ProcessChannel:
    """Small bounded JSON-lines adapter around one local app-server process."""

    def __init__(self, process: subprocess.Popen[bytes], deadline: float):
        self.process = process
        self.deadline = deadline
        self.messages: queue.Queue[bytes | None] = queue.Queue(maxsize=MAX_REQUESTS * 2)
        self.total_read = 0
        self.overflow = False
        self._reader = threading.Thread(target=self._read_stdout, daemon=True)
        self._reader.start()

    def _read_stdout(self) -> None:
        try:
            assert self.process.stdout is not None
            while True:
                line = self.process.stdout.readline(MAX_LINE_BYTES + 1)
                if not line:
                    self.messages.put(None)
                    return
                self.total_read += len(line)
                if len(line) > MAX_LINE_BYTES or self.total_read > MAX_STDOUT_BYTES:
                    self.overflow = True
                    self.messages.put(None)
                    return
                self.messages.put(line)
        except Exception:
            try:
                self.messages.put_nowait(None)
            except queue.Full:
                pass

    def send(self, raw: bytes) -> None:
        if self.process.stdin is None or time.monotonic() >= self.deadline:
            raise SmokeError("deadline_exceeded")
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def receive(self, deadline: float) -> bytes | None:
        if self.overflow:
            raise SmokeError("protocol_failed")
        remaining = min(deadline, self.deadline) - time.monotonic()
        if remaining <= 0:
            return None
        try:
            value = self.messages.get(timeout=remaining)
        except queue.Empty:
            return None
        if self.overflow:
            raise SmokeError("protocol_failed")
        return value


def _launch(executable: str, server_url: str, config_names: tuple[str, ...], *, discovery_only: bool = False) -> SmokeResult:
    command = build_command(executable, server_url, config_names)
    env = scrub_child_environment()
    deadline = time.monotonic() + MAX_SECONDS
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=str(Path(tempfile.gettempdir()).resolve()),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        channel = _ProcessChannel(process, deadline)
        return run_protocol(channel.send, channel.receive, deadline=deadline, discovery_only=discovery_only)
    except FileNotFoundError:
        return SmokeResult(False, "codex_missing", 0, 0)
    except Exception:
        return SmokeResult(False, "app_server_failed", 0, 0)
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=2)
                except Exception:
                    pass


def run_smoke(server_url: str, *, executable: str | None = None) -> SmokeResult:
    try:
        validate_server_url(server_url)
        names = read_configured_server_names(server_url)
        codex = executable or shutil.which("codex")
        if not codex:
            return SmokeResult(False, "codex_missing", 0, 0)
        return _launch(codex, server_url, names)
    except SmokeError as exc:
        category = str(exc) if str(exc) in _SAFE_CATEGORIES else "configuration_unavailable"
        return SmokeResult(False, category, 0, 0)
    except Exception:
        return SmokeResult(False, "app_server_failed", 0, 0)


def run_geographic_discovery(server_url: str, *, executable: str | None = None) -> SmokeResult:
    """Verify exactly twelve advertised tools without invoking any tool/model."""
    try:
        validate_server_url(server_url)
        names = read_configured_server_names(server_url)
        codex = executable or shutil.which("codex")
        if not codex:
            return SmokeResult(False, "codex_missing", 0, 0)
        return _launch(codex, server_url, names, discovery_only=True)
    except SmokeError as exc:
        category = str(exc) if str(exc) in _SAFE_CATEGORIES else "configuration_unavailable"
        return SmokeResult(False, category, 0, 0)
    except Exception:
        return SmokeResult(False, "app_server_failed", 0, 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-url", required=True)
    args = parser.parse_args(argv)
    result = run_smoke(args.server_url).safe_dict()
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
