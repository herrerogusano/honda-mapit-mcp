from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from mapit.aws_dev_multiuser_entrypoint import parse_manifest
from scripts import probe_aws_dev_multiuser_arm as probe


def test_fixture_is_synthetic_two_tenant_manifest_and_bounded_window():
    manifest_raw, jwks_raw, tokens, hashes = probe._fixture()
    value = json.loads(manifest_raw)
    assert set(value) == {
        "schema", "builder", "environment", "synthetic", "source_sha", "api_id",
        "user_pool_id", "client_id", "jwks_sha256", "table_arn", "tenants",
    }
    assert value["schema"] == 1 and value["builder"] == "build_retained_dev_multiuser_archive"
    assert value["environment"] == "dev" and value["synthetic"] is True
    assert len(value["tenants"]) == 2
    assert parse_manifest(manifest_raw, expected_digest=hashes["manifest_sha256"], account_id=probe.ACCOUNT_ID)["tenants"] == value["tenants"]
    assert hashes["jwks_sha256"] == value["jwks_sha256"]
    assert len(jwks_raw) < 32 * 1024
    assert set(tokens) == {"a", "b"}
    assert all(isinstance(item, str) and item.count(".") == 2 for item in tokens.values())
    assert 0 < probe.END - probe.START <= 300


def test_container_command_is_arm_network_none_and_memory_bounded(tmp_path: Path):
    command = probe._docker_command(tmp_path / "runtime.zip", context="desktop-linux", name="synthetic", cidfile=tmp_path / "cid", run_id="run-1")
    assert "--platform" in command and command[command.index("--platform") + 1] == "linux/arm64"
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--memory" in command and command[command.index("--memory") + 1] == "256m"
    assert "--pull=never" in command
    assert "--entrypoint" in command and command[command.index("--entrypoint") + 1] == "python3"
    assert "com.honda-mapit.arm-probe.owner=honda-mapit-mcp" in command
    assert "com.honda-mapit.arm-probe.run=run-1" in command


def test_output_parser_is_fixed_boolean_schema():
    checks = {name: True for name in probe.CHECKS}
    assert probe._parse_output(json.dumps({"checks": checks})) == checks
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_output(json.dumps({"checks": {**checks, "unexpected": True}}))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_output(json.dumps({"checks": {**checks, "tenant_a_success": 1}}))


def test_bounded_runner_timeout_covers_child_that_does_not_read_stdin():
    started = time.monotonic()
    with pytest.raises(probe.ProbeError, match="arm_probe_execution_failed"):
        probe._run_bounded(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            "x" * (2 * 1024 * 1024),
            timeout=0.05,
        )
    assert time.monotonic() - started < 5


def test_no_private_values_are_in_safe_categories():
    assert all("tenant-" not in category and "token" not in category for category in probe.SAFE_FAILURES)
    assert "multiuser_arm_probe_passed" not in probe.SAFE_FAILURES


def test_injected_entrypoint_composes_and_reads_two_fake_dynamodb_tenants(monkeypatch):
    from mapit import aws_dev_multiuser_entrypoint as entrypoint
    manifest_raw, jwks_raw, tokens, hashes = probe._fixture()

    class Reader:
        def __init__(self):
            self.status = {probe.TENANT_KEYS[0]: "active", probe.TENANT_KEYS[1]: "active"}

        def get_item(self, **request):
            key = request["Key"]["key"]["S"]
            result = {"ResponseMetadata": {"HTTPStatusCode": 200}}
            if key in self.status:
                result["Item"] = {"key": {"S": key}, "status": {"S": self.status[key]}, "revision": {"N": "1"}}
            return result

    reader = Reader()
    runtime = entrypoint.compose_runtime(
        manifest_raw, jwks_raw, manifest_digest=hashes["manifest_sha256"],
        account_id=probe.ACCOUNT_ID, dynamodb_reader=reader,
    )
    monkeypatch.setattr(entrypoint.time, "time", lambda: float(probe.START + 60))
    monkeypatch.setenv("MAPIT_MCP_ENV", "dev")
    monkeypatch.setenv("MAPIT_DEV_MULTIUSER_MODE", "synthetic")
    monkeypatch.setenv("AWS_REGION", probe.REGION)
    monkeypatch.setenv("MAPIT_DEV_MULTIUSER_MANIFEST_SHA256", hashes["manifest_sha256"])
    monkeypatch.setenv("MAPIT_DEV_EXPECTED_ACCOUNT_ID", probe.ACCOUNT_ID)
    monkeypatch.setenv("MAPIT_DEV_EXECUTION_START_EPOCH", str(probe.START))
    monkeypatch.setenv("MAPIT_DEV_EXECUTION_END_EPOCH", str(probe.END))

    class Context:
        def get_remaining_time_in_millis(self):
            return 30000

    def invoke(token, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}, separators=(",", ":"))
        event = {"version": "2.0", "rawPath": "/mcp", "rawQueryString": "", "headers": {
            "host": probe.API_ID + ".execute-api.eu-west-1.amazonaws.com", "content-type": "application/json",
            "content-length": str(len(body)), "accept": "application/json, text/event-stream", "authorization": "Bearer " + token,
        }, "requestContext": {"stage": "$default", "http": {"method": "POST", "path": "/mcp"}}, "body": body, "isBase64Encoded": False}
        response = runtime.handler(event, Context())
        return json.loads(response["body"])

    assert invoke(tokens["a"], "tools/list")["result"]["tools"]
    assert invoke(tokens["a"], "tools/call", {"name": "get_vehicle_status", "arguments": {}})["result"]["isError"] is False
    assert invoke(tokens["b"], "tools/call", {"name": "get_vehicle_status", "arguments": {}})["result"]["isError"] is False
    reader.status[probe.TENANT_KEYS[0]] = "revoked"
    assert invoke(tokens["a"], "tools/call", {"name": "get_vehicle_status", "arguments": {}})["result"]["isError"] is True
