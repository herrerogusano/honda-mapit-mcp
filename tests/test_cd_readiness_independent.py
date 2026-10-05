"""Independent shell-gate tests; no workflow dispatch or external credentials."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import pytest


WORKFLOW = Path(".github/workflows/cd-readiness.yml")


def _script_for_step(text: str, step_name: str) -> str:
    lines = text.splitlines()
    marker = f"- name: {step_name}"
    start = next(i for i, line in enumerate(lines) if line.strip() == marker)
    run_line = next(i for i in range(start, len(lines)) if lines[i].strip() == "run: |" )
    code: list[str] = []
    for line in lines[run_line + 1 :]:
        if line.startswith("          "):
            code.append(line[10:])
        elif not line.strip():
            code.append("")
        else:
            break
    return "\n".join(code)


def _run(script: str, values: dict[str, str]) -> subprocess.CompletedProcess[str]:
    if os.name == "nt":
        pytest.skip("requires POSIX bash; this Windows host has no usable local POSIX shell")
    with tempfile.TemporaryDirectory(prefix="cd-readiness-home-") as home:
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": home}
        env.update(values)
        return subprocess.run(
            ["bash", "-e", "-c", script],
            env=env,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )


@pytest.fixture(scope="module")
def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_extracted_branch_gate_accepts_only_exact_target_branch_and_full_sha(workflow_text: str) -> None:
    gate = _script_for_step(workflow_text, "Enforce target branch")
    good = "a" * 40
    for target, ref in (("dev", "refs/heads/develop"), ("prod", "refs/heads/main")):
        result = _run(gate, {"TARGET": target, "SOURCE_REF": ref, "SOURCE_SHA": good})
        assert result.returncode == 0, result.stderr

    for target, ref, sha in (
        ("dev", "refs/heads/main", good),
        ("prod", "refs/heads/develop", good),
        ("other", "refs/heads/main", good),
        ("dev$(printf shell_canary)", "refs/heads/develop", good),
        ("dev", "../refs/heads/develop", good),
    ):
        result = _run(gate, {"TARGET": target, "SOURCE_REF": ref, "SOURCE_SHA": sha})
        assert result.returncode != 0
        assert "not allowed" in result.stdout
        assert "shell_canary" not in result.stdout + result.stderr
        if sha:
            assert sha not in result.stdout + result.stderr


def test_precheckout_gate_rejects_malformed_sha_before_checkout(workflow_text: str) -> None:
    gate = _script_for_step(workflow_text, "Enforce target branch")
    for sha in ("", "b" * 39, "g" * 40, "B" * 40, "../refs/heads/main"):
        result = _run(
            gate,
            {"TARGET": "dev", "SOURCE_REF": "refs/heads/develop", "SOURCE_SHA": sha},
        )
        assert result.returncode != 0
        assert "source identity is invalid" in result.stdout
        if sha:
            assert sha not in result.stdout + result.stderr


def test_checkout_identity_gate_requires_canonical_sha_equal_to_head(workflow_text: str) -> None:
    gate = _script_for_step(workflow_text, "Verify checkout identity")
    good = "b" * 40
    # A shell function avoids invoking Git or changing repository state.
    script = 'git() { printf "%s" "$MOCK_GIT_HEAD"; }\n' + gate
    accepted = _run(script, {"SOURCE_SHA": good, "MOCK_GIT_HEAD": good})
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    for sha, head in (
        ("", good), ("b" * 39, good), ("g" * 40, "g" * 40),
        ("B" * 40, "B" * 40), (good, "c" * 40),
    ):
        result = _run(script, {"SOURCE_SHA": sha, "MOCK_GIT_HEAD": head})
        assert result.returncode != 0
        assert "does not match" in result.stdout
        assert sha not in result.stdout + result.stderr if sha else True


def test_credential_gate_rejects_aws_bearer_source_without_echoing_value(workflow_text: str) -> None:
    gate = _script_for_step(workflow_text, "Reject provider credentials and AWS credential sources")
    canary = "synthetic-aws-bearer-canary"
    result = _run(gate, {"AWS_BEARER_TOKEN_BEDROCK": canary})
    assert result.returncode != 0
    assert canary not in result.stdout + result.stderr
    assert "credential sources" in result.stdout


def test_credential_gate_accepts_clean_temporary_home_and_rejects_even_empty_key(workflow_text: str) -> None:
    gate = _script_for_step(workflow_text, "Reject provider credentials and AWS credential sources")
    clean = _run(gate, {})
    assert clean.returncode == 0, clean.stdout + clean.stderr
    empty = _run(gate, {"AWS_ACCESS_KEY_ID": ""})
    assert empty.returncode != 0
    assert "AWS_ACCESS_KEY_ID" not in empty.stdout + empty.stderr


def test_workflow_is_readiness_only_and_checks_out_the_dispatched_sha(workflow_text: str) -> None:
    assert re.search(r"(?m)^permissions:\s*\n  contents: read\s*$", workflow_text)
    assert "id-token:" not in workflow_text
    assert "ref: ${{ github.sha }}" in workflow_text
    assert "Verify checkout identity" in workflow_text
    assert '[[ ! "${SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]' in workflow_text
    assert '"$(git rev-parse HEAD)" != "${SOURCE_SHA}"' in workflow_text
    assert "persist-credentials: false" in workflow_text
    assert "cancel-in-progress: false" in workflow_text
    assert "timeout-minutes: 10" in workflow_text
    for forbidden in (
        "configure-aws-credentials", "aws-actions/", "upload-artifact",
        "cloudformation deploy", "sam deploy", "id-token: write",
    ):
        assert forbidden not in workflow_text
    assert "AWS_BEARER_TOKEN_BEDROCK" in workflow_text
