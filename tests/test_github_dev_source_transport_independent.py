from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.github_dev_source_gate import MAX_OUTPUT_BYTES
from scripts.github_dev_source_transport import SourceReadTransport, SourceTransportError


class _Response:
    def __init__(self, body: bytes, *, status: int = 200, headers: dict[str, str] | None = None):
        self.body = body
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.closed = False

    def getheader(self, name: str, default=None):
        return self.headers.get(name.lower(), default)

    def read1(self, size: int = -1) -> bytes:
        if not self.body:
            return b""
        chunk, self.body = self.body[:size], self.body[size:]
        return chunk

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response):
        self.response = response
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.closed = False
        self.sock = None

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.requests.append((method, path, headers))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


class _Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self) -> float:
        self.value += 0.01
        return self.value


def _reader(tmp_path: Path, response: _Response):
    clock = _Clock()
    made: list[tuple[_Connection, dict]] = []

    def factory(*args, **kwargs):
        connection = _Connection(response)
        made.append((connection, kwargs))
        return connection

    return SourceReadTransport(
        "token-value",
        tmp_path,
        monotonic=clock,
        connection_factory=factory,
    ), made


def test_remote_happy_path_uses_fixed_direct_tls_route_and_redacts_token(tmp_path: Path):
    reader, made = _reader(tmp_path, _Response(json.dumps({"id": 123}).encode()))

    result = reader.remote("repository")

    assert result == {"id": 123}
    connection, kwargs = made[0]
    assert kwargs["timeout"] <= 8.0
    assert kwargs["context"].check_hostname is True
    assert connection.requests[0][0:2] == ("GET", "/repos/herrerogusano/honda-mapit-mcp")
    headers = connection.requests[0][2]
    assert headers["Authorization"] == "Bearer token-value"
    assert connection.closed is True
    assert "token-value" not in repr(reader)


def test_remote_rejects_redirect_encoding_and_duplicate_json_keys(tmp_path: Path):
    for response in (
        _Response(b"{}", status=302, headers={"Location": "https://evil.invalid"}),
        _Response(b"{}", headers={"Content-Encoding": "gzip"}),
        _Response(b'{"x":1,"x":2}'),
    ):
        reader, made = _reader(tmp_path, response)
        with pytest.raises(SourceTransportError):
            reader.remote("repository")
        assert made[0][0].closed is True


def test_denied_response_retains_only_status_without_reading_private_body(tmp_path: Path):
    response = _Response(b"private-provider-payload", status=403)
    reader, made = _reader(tmp_path, response)
    with pytest.raises(SourceTransportError) as raised:
        reader.diagnostic_remote("branches/develop/protection")
    assert raised.value.http_status == 403
    assert str(raised.value) == "source_transport_failed"
    assert response.body == b"private-provider-payload"
    assert made[0][0].closed is True


def test_remote_rejects_body_over_limit(tmp_path: Path):
    reader, _ = _reader(tmp_path, _Response(b"{" + b"a" * MAX_OUTPUT_BYTES + b"}"))

    with pytest.raises(SourceTransportError):
        reader.remote("repository")


def test_remote_rejects_oversized_declared_content_length_even_if_body_is_small(tmp_path: Path):
    reader, _ = _reader(
        tmp_path,
        _Response(b"{}", headers={"Content-Length": str(MAX_OUTPUT_BYTES + 1)}),
    )

    with pytest.raises(SourceTransportError):
        reader.remote("repository")


@pytest.mark.parametrize(
    "body, declared",
    [(b"{}", "1"), (b"{}", "3"), (b"{}", "2, 2")],
)
def test_remote_rejects_short_long_or_duplicate_content_length(tmp_path: Path, body: bytes, declared: str):
    reader, _ = _reader(tmp_path, _Response(body, headers={"Content-Length": declared}))

    with pytest.raises(SourceTransportError):
        reader.remote("repository")


def test_chunked_without_content_length_is_allowed_but_other_transfer_encoding_is_not(tmp_path: Path):
    reader, _ = _reader(tmp_path, _Response(b"{}", headers={"Transfer-Encoding": "chunked"}))
    assert reader.remote("repository") == {}

    reader, _ = _reader(tmp_path, _Response(b"{}", headers={"Transfer-Encoding": "gzip"}))
    with pytest.raises(SourceTransportError):
        reader.remote("repository")


def test_routes_are_allowlisted_and_ids_are_bounded(tmp_path: Path):
    reader, _ = _reader(tmp_path, _Response(b"{}"))
    assert reader._route("ref/heads/develop").endswith("/git/ref/heads/develop")
    assert reader._route("actions/runs/123/jobs").endswith("/actions/runs/123/jobs?per_page=100")
    with pytest.raises(SourceTransportError):
        reader._route("branches/develop/protection")
    assert reader._route("branches/develop/protection", diagnostic=True).endswith("/branches/develop/protection")
    for endpoint in (
        "users/other",
        "actions/runs/0",
        "actions/runs/1/jobs/extra",
        "actions/workflows/1/jobs",
        "actions/runs/99999999999999999999999",
    ):
        with pytest.raises(SourceTransportError):
            reader._route(endpoint)


def test_local_allows_only_read_commands_and_bounds_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    calls = []

    class Result:
        returncode = 0
        stdout = b"abc\n"

    def runner(*args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    reader = SourceReadTransport("token", tmp_path, process_runner=runner)
    monkeypatch.setenv("GIT_DIR", "attacker-controlled")
    assert reader.local(["git", "rev-parse", "--verify", "HEAD"]) == (0, "abc\n")
    assert calls[0][1]["cwd"] == tmp_path.resolve()
    assert calls[0][1]["capture_output"] is True
    assert calls[0][1]["check"] is False
    env = calls[0][1]["env"]
    assert all(not key.upper().startswith("GIT_") or key in {"GIT_OPTIONAL_LOCKS", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"} for key in env)
    assert env["GIT_OPTIONAL_LOCKS"] == "0"
    assert env["GIT_CONFIG_KEY_0"] == "core.fsmonitor"
    with pytest.raises(SourceTransportError):
        reader.local(["git", "push"])
    assert len(calls) == 1


def test_local_rejects_oversized_stdout_and_errors_are_redacted(tmp_path: Path):
    class Result:
        returncode = 0
        stdout = b"x" * (MAX_OUTPUT_BYTES + 1)

    reader = SourceReadTransport("super-secret-token", tmp_path, process_runner=lambda *a, **k: Result())
    with pytest.raises(SourceTransportError) as exc:
        reader.local(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    assert "super-secret-token" not in str(exc.value)
    assert "super-secret-token" not in repr(reader)
