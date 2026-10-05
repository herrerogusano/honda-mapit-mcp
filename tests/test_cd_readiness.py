from pathlib import Path
import re


WORKFLOW = Path(".github/workflows/cd-readiness.yml")


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_is_manual_and_target_is_closed_choice() -> None:
    text = _workflow()
    assert re.search(r"(?m)^on:\s*$", text)
    assert re.search(r"(?m)^  workflow_dispatch:\s*$", text)
    assert re.search(r"(?m)^        type: choice\s*$", text)
    assert re.search(r"(?m)^          - dev\s*$", text)
    assert re.search(r"(?m)^          - prod\s*$", text)
    assert "push:" not in text
    assert "pull_request:" not in text


def test_target_must_match_exact_protected_branch_and_commit_is_pinned() -> None:
    text = _workflow()
    assert 'case "${TARGET}:${SOURCE_REF}" in' in text
    assert "dev:refs/heads/develop|prod:refs/heads/main" in text
    assert text.index('[[ ! "${SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]') < text.index("Checkout exact dispatched commit")
    assert "ref: ${{ github.sha }}" in text
    assert '[[ ! "${SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]' in text
    assert '"$(git rev-parse HEAD)" != "${SOURCE_SHA}"' in text
    assert "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in text
    assert "persist-credentials: false" in text
    assert "uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97" in text


def test_workflow_has_read_only_permissions_serializes_and_is_bounded() -> None:
    text = _workflow()
    assert re.search(r"(?ms)^permissions:\s*\n  contents: read\s*$", text)
    assert "id-token:" not in text
    assert "cancel-in-progress: false" in text
    assert "group: honda-mapit-cd-readiness-${{ inputs.target }}" in text
    assert "timeout-minutes: 10" in text
    assert "persist-credentials: false" in text


def test_workflow_rejects_ambient_credentials_and_runs_only_readiness_gates() -> None:
    text = _workflow()
    for name in (
        "AWS_PROFILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_BEARER_TOKEN_BEDROCK",
        "AWS_SECRET_ACCESS_KEY",
        "MAPIT_PASSWORD",
        "TELEGRAM_BOT_TOKEN",
    ):
        assert name in text
    assert '".[test,agent,realtime]"' in text
    assert "python -m compileall -q src tests scripts" in text
    assert "python -m pytest -q" in text
    assert "python scripts/evaluate_agent_dataset.py" in text
    assert "GITHUB_STEP_SUMMARY" in text
    for forbidden in (
        "id-token: write",
        "configure-aws-credentials",
        "aws-actions/",
        "sam deploy",
        "cloudformation deploy",
        "upload-artifact",
        "AWS_ACCESS_KEY_ID:",
        "secrets.",
    ):
        assert forbidden not in text
    assert "no artifact built or deployed" in text
