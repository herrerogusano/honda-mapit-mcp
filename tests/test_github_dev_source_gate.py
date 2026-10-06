from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.github_cd_protections import GITHUB_ACTIONS_APP_ID, REQUIRED_CHECKS
from scripts.github_dev_source_gate import REPOSITORY, SourceGateBinding, validate_source_gate


SHA = "a" * 40
OWNER_ID = 1234567
REPOSITORY_ID = 7654321
RUN_ID = 37341041504


def _binding(**changes):
    value = {
        "owner_id": OWNER_ID, "repository_id": REPOSITORY_ID,
        "source_sha": SHA, "ci_run_id": RUN_ID,
        "owner": "herrerogusano", "repository": REPOSITORY,
        "branch": "develop", "environment": "dev", "readonly": True,
    }
    value.update(changes)
    return value


def _branch_protection():
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": list(REQUIRED_CHECKS),
            "checks": [{"context": name, "app_id": GITHUB_ACTIONS_APP_ID} for name in REQUIRED_CHECKS],
        },
        "enforce_admins": {"enabled": True},
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True, "require_code_owner_reviews": False,
            "required_approving_review_count": 0, "require_last_push_approval": False,
            "dismissal_restrictions": {"users": [], "teams": [], "apps": []},
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "restrictions": None,
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False},
        "required_linear_history": {"enabled": False}, "lock_branch": {"enabled": False},
    }


def _environment():
    return {
        "name": "dev", "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        "protection_rules": [
            {"type": "required_reviewers", "prevent_self_review": False, "reviewers": [{"type": "User", "id": OWNER_ID}]},
            {"type": "branch_policy"},
        ],
    }


def _documents():
    jobs = [{"name": name, "status": "completed", "conclusion": "success", "head_sha": SHA} for name in REQUIRED_CHECKS]
    return {
        "repository": {"full_name": REPOSITORY, "id": REPOSITORY_ID, "owner": {"login": "herrerogusano", "id": OWNER_ID}},
        "ref/heads/develop": {"ref": "refs/heads/develop", "object": {"sha": SHA}},
        f"actions/runs/{RUN_ID}": {"id": RUN_ID, "status": "completed", "conclusion": "success", "head_sha": SHA, "head_branch": "develop", "event": "push", "workflow_id": 9911},
        "actions/workflows/9911": {"id": 9911, "name": "CI", "path": ".github/workflows/ci.yml", "state": "active"},
        f"actions/runs/{RUN_ID}/jobs": {"total_count": 8, "jobs": jobs},
        "branches/develop/protection": _branch_protection(),
        "environments/dev": _environment(),
        "environments/dev/deployment-branch-policy": [{"name": "develop", "type": "branch"}],
    }


def _run(documents=None, *, git=None):
    documents = documents or _documents()
    git = git or {
        ("git", "rev-parse", "--verify", "HEAD"): (0, SHA + "\n"),
        ("git", "branch", "--show-current"): (0, "develop\n"),
        ("git", "status", "--porcelain=v1", "--untracked-files=all"): (0, ""),
    }
    return validate_source_gate(
        _binding(),
        git_reader=lambda command: git[tuple(command)],
        github_reader=lambda endpoint: deepcopy(documents[endpoint]),
    )


def test_source_gate_success_is_redacted_and_read_only():
    result = _run()
    assert result == {"ok": True, "category": "source_gate_verified", "ci_jobs": 8, "read_only": True}
    assert SHA not in str(result) and str(RUN_ID) not in str(result)


@pytest.mark.parametrize("mutation,category", [
    (lambda docs: docs["repository"].update(id=999), "repository_readback_failed"),
    (lambda docs: docs["ref/heads/develop"]["object"].update(sha="b" * 40), "branch_head_mismatch"),
    (lambda docs: docs[f"actions/runs/{RUN_ID}"]["conclusion"] == "failure", "ci_readback_failed"),
    (lambda docs: docs["actions/workflows/9911"].update(state="disabled"), "workflow_readback_failed"),
    (lambda docs: docs[f"actions/runs/{RUN_ID}/jobs"]["jobs"].pop(), "ci_jobs_mismatch"),
    (lambda docs: docs["environments/dev"].update(can_admins_bypass=True), "administrator_bypass_mismatch"),
])
def test_source_gate_rejects_readback_mutations(mutation, category):
    docs = _documents()
    if category == "ci_readback_failed":
        docs[f"actions/runs/{RUN_ID}"]["conclusion"] = "failure"
    else:
        mutation(docs)
    result = _run(docs)
    assert result["ok"] is False and result["category"] == category
    assert SHA not in str(result) and str(RUN_ID) not in str(result)


def test_dirty_checkout_stops_before_github_reads():
    calls = []
    git = {
        ("git", "rev-parse", "--verify", "HEAD"): (0, SHA + "\n"),
        ("git", "branch", "--show-current"): (0, "develop\n"),
        ("git", "status", "--porcelain=v1", "--untracked-files=all"): (0, "?? private.json\n"),
    }
    result = validate_source_gate(_binding(), git_reader=lambda command: git[tuple(command)], github_reader=lambda endpoint: calls.append(endpoint))
    assert result["category"] == "local_checkout_dirty" and calls == []


@pytest.mark.parametrize("field,value", [("branch", "main"), ("readonly", False), ("source_sha", "0" * 40), ("repository", "evil/example")])
def test_binding_is_fixed_and_typed(field, value):
    payload = _binding(**{field: value})
    result = validate_source_gate(payload, git_reader=lambda _: (0, ""), github_reader=lambda _: {})
    assert result["category"] == "binding_invalid"


def test_binding_constructor_rejects_extra_fields():
    with pytest.raises(ValueError):
        SourceGateBinding.from_payload({**_binding(), "extra": True})
