from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

import scripts.run_aws_retained_dev_bootstrap as runner


def test_client_factory_uses_only_fixed_direct_tls_single_attempt_clients(monkeypatch):
    configs = []
    config_objects = []
    clients = []

    class FakeConfig:
        def __init__(self, **kwargs):
            configs.append(kwargs)
            config_objects.append(self)

    class FakeSession:
        def __init__(self, **kwargs):
            assert kwargs == {"region_name": runner.REGION}

        def client(self, name, **kwargs):
            clients.append((name, kwargs))
            return object()

    boto3 = types.ModuleType("boto3")
    boto3.Session = FakeSession
    botocore = types.ModuleType("botocore")
    botocore_config = types.ModuleType("botocore.config")
    botocore_config.Config = FakeConfig
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", botocore_config)
    for key in runner._PROXY_ENV:
        monkeypatch.delenv(key, raising=False)

    result = runner._build_clients()
    assert set(result) == {"sts", "cloudformation", "lambda", "apigatewayv2", "logs", "iam"}
    assert len(configs) == 2
    for config in configs:
        assert config["connect_timeout"] == 2
        assert config["read_timeout"] == 3
        assert config["retries"] == {"total_max_attempts": 1, "mode": "standard"}
        assert config["proxies"] == {}
        assert config["signature_version"] == "v4"
    assert len(clients) == 6
    for name, kwargs in clients:
        assert kwargs["verify"] is True
        assert kwargs["endpoint_url"].startswith("https://")
        assert "proxy" not in kwargs["endpoint_url"].casefold()
        assert kwargs["region_name"] == ("us-east-1" if name == "iam" else runner.REGION)
        assert kwargs["config"] is config_objects[1 if name == "iam" else 0]


def test_bounded_commands_are_shell_free_repo_bound_and_have_finite_timeout():
    calls = []

    class Result:
        returncode = 0
        stdout = b"ok"

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Result()

    assert runner._bounded_command(["git", "status"], runner=fake_run) == (0, "ok")
    command, kwargs = calls[0]
    assert command == ["git", "status"]
    assert kwargs["cwd"] == runner._ROOT
    assert kwargs["shell"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is False
    assert kwargs["timeout"] == 20

    class Huge:
        returncode = 0
        stdout = b"x" * (runner.MAX_COMMAND_OUTPUT_BYTES + 1)

    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner._bounded_command(["gh"], runner=lambda *_args, **_kwargs: Huge())
    assert exc.value.category == "verification_output_too_large"


def test_windows_acl_rejects_unlisted_named_principal_even_when_owner_and_system_exist(monkeypatch):
    class Result:
        returncode = 0
        stdout = "C:\\private owner:(F)\nC:\\private NT AUTHORITY\\SYSTEM:(F)\nC:\\private AnotherUser:(R)\n"

    def fake_run(command, **kwargs):
        if command[0].casefold() == "whoami":
            return types.SimpleNamespace(returncode=0, stdout="owner\n")
        return Result()

    # Replace this module's OS facade, not the shared os.name used by pathlib
    # and pytest itself (Python 3.11 otherwise selects WindowsPath on Linux).
    monkeypatch.setattr(runner, "os", types.SimpleNamespace(name="nt", environ=runner.os.environ))
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    assert runner._windows_acl_exact(Path("C:/private")) is False
