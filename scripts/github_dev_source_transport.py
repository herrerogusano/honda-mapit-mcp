"""Bounded read-only GitHub/local-git adapters for the retained-dev source gate.

No workflow, token acquisition, output-file writer or AWS client is provided.
The caller supplies one temporary GitHub token and an already bound CI run.
"""
from __future__ import annotations

import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import subprocess
import time
from typing import Any, Callable

from scripts.github_dev_source_gate import MAX_OUTPUT_BYTES, REPOSITORY, validate_source_gate


class SourceTransportError(ValueError):
    def __init__(self, *, http_status: int | None = None) -> None:
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        super().__init__("source_transport_failed")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceTransportError()
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise SourceTransportError()


class SourceReadTransport:
    """One-use gate reader with an overall monotonic deadline and fixed routes."""

    def __init__(self, token: str, root: Path, *, monotonic: Callable[[], float] = time.monotonic,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 process_runner: Callable[..., Any] = subprocess.run) -> None:
        if (type(token) is not str or not token or len(token) > 4096
                or any(ord(char) < 33 or ord(char) > 126 for char in token)
                or not isinstance(root, Path) or not root.is_dir()):
            raise SourceTransportError()
        self._token = token
        self._root = root.resolve()
        self._clock = monotonic
        self._connection_factory = connection_factory
        self._process_runner = process_runner
        self._last = self._now()
        self._deadline = self._last + 45.0
        self._calls = 0

    def __repr__(self) -> str:
        return "SourceReadTransport(redacted)"

    def _now(self) -> float:
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value):
            raise SourceTransportError()
        return float(value)

    def _remaining(self) -> float:
        now = self._now()
        if now < self._last or now >= self._deadline:
            raise SourceTransportError()
        self._last = now
        return min(8.0, self._deadline - now)

    def _call(self) -> None:
        self._remaining()
        self._calls += 1
        if self._calls > 16:
            raise SourceTransportError()

    def local(self, command: list[str]) -> tuple[int, str]:
        allowed = (
            ["git", "rev-parse", "--verify", "HEAD"],
            ["git", "branch", "--show-current"],
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        )
        if command not in allowed:
            raise SourceTransportError()
        self._call()
        try:
            environment = {key: value for key, value in os.environ.items()
                           if not key.upper().startswith("GIT_")}
            environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_COUNT": "1",
                                "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "false"})
            result = self._process_runner(command, cwd=self._root, capture_output=True,
                                          timeout=self._remaining(), check=False, env=environment)
            self._remaining()
            if (type(result.returncode) is not int or type(result.stdout) is not bytes
                    or len(result.stdout) > MAX_OUTPUT_BYTES):
                raise SourceTransportError()
            return result.returncode, result.stdout.decode("utf-8", errors="strict")
        except Exception:
            raise SourceTransportError() from None

    @staticmethod
    def _route(endpoint: str, *, diagnostic: bool = False) -> str:
        fixed = {
            "repository": "",
            "ref/heads/develop": "/git/ref/heads/develop",
        }
        if diagnostic:
            fixed.update({
                "branches/develop/protection": "/branches/develop/protection",
                "environments/dev": "/environments/dev",
                "environments/dev/deployment-branch-policy": "/environments/dev/deployment-branch-policies?per_page=100",
            })
        if endpoint in fixed:
            return "/repos/" + REPOSITORY + fixed[endpoint]
        match = re.fullmatch(r"actions/(runs|workflows)/([1-9][0-9]*)(/jobs)?", endpoint)
        if match is None or len(match[2]) > 20 or (match[3] and match[1] != "runs"):
            raise SourceTransportError()
        return "/repos/" + REPOSITORY + "/" + endpoint + ("?per_page=100" if match[3] else "")

    def _remote(self, endpoint: str, *, diagnostic: bool = False) -> Any:
        path = self._route(endpoint, diagnostic=diagnostic)
        self._call()
        connection = response = None
        try:
            connection = self._connection_factory("api.github.com", port=443,
                timeout=self._remaining(), context=ssl.create_default_context())
            connection.request("GET", path, headers={
                "Authorization": "Bearer " + self._token,
                "Accept": "application/vnd.github+json", "Accept-Encoding": "identity",
                "User-Agent": "honda-mapit-retained-dev-source-gate",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            self._remaining()
            response = connection.getresponse()
            self._remaining()
            if response.status != 200:
                raise SourceTransportError(http_status=response.status)
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise SourceTransportError()
            declared = response.getheader("Content-Length")
            transfer = response.getheader("Transfer-Encoding")
            if transfer is not None and (transfer != "chunked" or declared is not None):
                raise SourceTransportError()
            length = None
            if declared is not None:
                if type(declared) is not str or re.fullmatch(r"[0-9]{1,7}", declared) is None:
                    raise SourceTransportError()
                length = int(declared)
                if length > MAX_OUTPUT_BYTES:
                    raise SourceTransportError()
            # No redirects, retries or pagination. Chunked HTTPS is bounded by
            # decoded bytes, with the overall deadline debited after each read.
            payload = bytearray()
            while len(payload) <= MAX_OUTPUT_BYTES:
                remaining = self._remaining()
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, MAX_OUTPUT_BYTES + 1 - len(payload)))
                self._remaining()
                if not chunk:
                    break
                payload.extend(chunk)
            if len(payload) > MAX_OUTPUT_BYTES:
                raise SourceTransportError()
            if length is not None and len(payload) != length:
                raise SourceTransportError()
            value = json.loads(payload.decode("utf-8", errors="strict"),
                               object_pairs_hook=_object, parse_constant=_constant)
            if not isinstance(value, (dict, list)):
                raise SourceTransportError()
            return value
        except SourceTransportError:
            raise
        except Exception:
            raise SourceTransportError() from None
        finally:
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        pass

    def remote(self, endpoint: str) -> Any:
        """Read only source/CI data used by the normal promotion gate."""
        return self._remote(endpoint)

    def diagnostic_remote(self, endpoint: str) -> Any:
        """Read protection metadata for the separate capability probe only."""
        return self._remote(endpoint, diagnostic=True)


def run_bound_source_gate(binding: dict[str, Any], *, token: str, root: Path) -> dict[str, Any]:
    """Use direct verified TLS, fixed read-only routes and no ambient gh auth."""
    try:
        reader = SourceReadTransport(token, root)
        return validate_source_gate(binding, git_reader=reader.local, github_reader=reader.remote)
    except Exception:
        return {"ok": False, "category": "source_gate_internal_error", "read_only": True}
