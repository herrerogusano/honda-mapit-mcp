from __future__ import annotations

import json
import sys

import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy, parse_cognito_jwks
from scripts import probe_aws_prod_runtime_arm as probe


POLICY = CognitoProdPolicy(
    user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
    client_id="SyntheticProdClient012345",
    owner_subject="18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
)


def test_synthetic_fixture_is_public_only_and_produces_signed_prod_claims():
    snapshot, tokens = probe._fixture(POLICY, 1_800_000_000)
    assert len(parse_cognito_jwks(snapshot)) == 1
    token = tokens["valid"]
    header, body, signature = token.split(".")
    assert header and signature
    import base64
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    assert claims == {
        "iss": POLICY.issuer_url,
        "aud": POLICY.audience,
        "sub": POLICY.owner_subject,
        "client_id": POLICY.client_id,
        "token_use": "access",
        "iat": 1_800_000_000,
        "exp": 1_800_000_240,
        "scope": POLICY.required_scope,
    }
    assert b'"d"' not in snapshot and b'"p"' not in snapshot


def test_result_parser_accepts_only_fixed_boolean_matrix():
    matrix = {name: True for name in probe._CHECKS}
    statuses = {name: 200 for name in (
        "initialize", "tools_list", "first_tool_call", "missing_auth", "unknown_kid",
        "wrong_audience", "wrong_scope", "dev_isolation", "missing_config",
    )}
    assert probe._parse_checks(json.dumps({"checks": matrix, "statuses": statuses})) == (matrix, statuses)
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_checks(json.dumps({"checks": {**matrix, "extra": False}, "statuses": statuses}))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_checks(json.dumps({"checks": {**matrix, "initialize": 1}, "statuses": statuses}))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_checks('{"checks":{"initialize":true,"initialize":false},"statuses":{}}')


def test_docker_command_is_pinned_arm_networkless_and_mounts_archive_readonly(tmp_path):
    archive = tmp_path / "runtime.zip"
    command = probe._command(archive, "default", "honda-mapit-prod-arm-probe-run", "a" * 32, tmp_path / "cid")
    assert "--network" in command and command[command.index("--network") + 1] == "none"
    assert "--pull=never" in command and "--platform" in command
    assert command[command.index("--platform") + 1] == "linux/arm64"
    assert probe.IMAGE in command
    mount = command[command.index("--mount") + 1]
    assert str(archive) in mount and mount.endswith(",readonly")
    assert "-e" not in command and "--env" not in command


def test_container_probe_uses_only_synthetic_ssm_and_transport_fakes():
    assert "ep._ssm_client_factory=lambda:ssm" in probe._CONTAINER_PROBE
    assert "ep.CloudDirectTransport=FakeTransport" in probe._CONTAINER_PROBE
    assert "--network" not in probe._CONTAINER_PROBE
    assert "123456789012" in probe._CONTAINER_PROBE
    assert "tools/call" in probe._CONTAINER_PROBE


def test_bounded_process_accepts_small_output_without_exposing_stderr():
    code, stdout = probe._run_bounded_process(
        [sys.executable, "-c", "import sys; print('{\\\"ok\\\":true}'); print('private-canary', file=sys.stderr)"],
        "{}",
        timeout=5,
    )
    assert code == 0 and stdout.strip() == '{"ok":true}'
    assert "private-canary" not in stdout


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_process_kills_child_when_either_output_exceeds_cap(stream):
    code = "import sys; getattr(sys, %r).write('x' * %d); getattr(sys, %r).flush()" % (
        stream, probe._MAX_OUTPUT + 1, stream,
    )
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._run_bounded_process([sys.executable, "-c", code], "{}", timeout=5)


def test_bounded_process_timeout_is_safe_and_bounded():
    with pytest.raises(probe.ProbeError, match="arm_probe_execution_failed"):
        probe._run_bounded_process([sys.executable, "-c", "import time; time.sleep(5)"], "{}", timeout=0.1)
