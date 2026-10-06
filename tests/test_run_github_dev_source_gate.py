from pathlib import Path

import pytest

from scripts.run_github_dev_source_gate import run


def context():
    return {"GITHUB_SHA": "a" * 40, "CHECKED_OUT_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/develop", "GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp",
            "GITHUB_REPOSITORY_OWNER_ID": "1", "GITHUB_REPOSITORY_ID": "2",
            "GITHUB_CI_RUN_ID": "3", "GH_TOKEN": "private-fixture"}


def test_context_and_success_projection(tmp_path):
    calls = []
    def gate(binding, **kwargs):
        calls.append((binding, kwargs))
        return {"ok": True, "category": "source_gate_verified", "ci_jobs": 8,
                "read_only": True, "private": "must-not-escape"}
    result = run(context(), root=tmp_path, gate=gate)
    assert result == {"ok": True, "category": "source_gate_verified", "ci_jobs": 8, "read_only": True}
    assert calls[0][0]["source_sha"] == "a" * 40
    assert calls[0][0]["ci_run_id"] == 3
    assert calls[0][1]["root"] == tmp_path
    assert "private" not in repr(result)


@pytest.mark.parametrize("key,value", [
    ("GITHUB_REF", "refs/heads/main"), ("GITHUB_REPOSITORY", "other/repo"),
    ("GITHUB_SHA", "0" * 40), ("CHECKED_OUT_SHA", "b" * 40),
    ("GITHUB_CI_RUN_ID", "0"), ("GITHUB_CI_RUN_ID", "01"),
    ("GITHUB_REPOSITORY_OWNER_ID", "True"), ("GH_TOKEN", ""),
])
def test_bad_context_never_calls_transport(tmp_path, key, value):
    env = context(); env[key] = value
    def gate(*args, **kwargs):
        pytest.fail("transport called")
    assert run(env, root=tmp_path, gate=gate)["category"] == "runner_context_invalid"


def test_raw_failure_and_exception_are_never_emitted(tmp_path):
    for gate in (lambda *args, **kwargs: {"ok": False, "category": "secret-value", "read_only": True},
                 lambda *args, **kwargs: {"private": "secret-value"}):
        assert "secret-value" not in repr(run(context(), root=tmp_path, gate=gate))
