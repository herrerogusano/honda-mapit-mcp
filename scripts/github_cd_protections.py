"""Pure payload/readback helpers for this repository's future GitHub CD gates.

This module does not construct an API client, read credentials, or make writes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


REPOSITORY = "herrerogusano/honda-mapit-mcp"
TARGET_BRANCH = {"dev": "develop", "prod": "main"}
GITHUB_ACTIONS_APP_ID = 15368
REQUIRED_CHECKS = (
    "Offline geographic queries and public boundary",
    "Offline CloudFormation schemas",
    "Offline shutdown SDK contract",
    "ubuntu-latest / Python 3.11",
    "ubuntu-latest / Python 3.12",
    "ubuntu-latest / Python 3.13",
    "windows-latest / Python 3.13",
    "Known dependency advisories",
)


class GitHubProtectionError(ValueError):
    """A bounded validation failure with no user-supplied values in its text."""

    def __init__(self, category: str) -> None:
        if category not in {
            "invalid_target",
            "invalid_branch",
            "invalid_owner_id",
            "branch_protection_mismatch",
            "environment_protection_mismatch",
            "branch_policy_mismatch",
        }:
            category = "invalid_configuration"
        self.category = category
        super().__init__(category)


def _target_branch(branch: str) -> str:
    if type(branch) is not str or branch not in {"main", "develop"}:
        raise GitHubProtectionError("invalid_branch")
    return branch


def _target_environment(target: str) -> str:
    if type(target) is not str or target not in TARGET_BRANCH:
        raise GitHubProtectionError("invalid_target")
    return target


def _positive_owner_id(owner_id: int) -> int:
    if type(owner_id) is not int or owner_id <= 0:
        raise GitHubProtectionError("invalid_owner_id")
    return owner_id


def build_branch_protection_payload(branch: str) -> dict[str, Any]:
    """Return the exact required settings for main or develop."""
    _target_branch(branch)
    checks = list(REQUIRED_CHECKS)
    return {
        "required_status_checks": {
            "strict": True,
            "checks": [
                {"context": context, "app_id": GITHUB_ACTIONS_APP_ID}
                for context in checks
            ],
        },
        "enforce_admins": True,
        "required_pull_request_reviews": {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            # Explicitly 0: the repository currently has a sole owner; this
            # setting does not represent independent human review.
            "required_approving_review_count": 0,
            "require_last_push_approval": False,
        },
        "restrictions": None,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "required_linear_history": False,
        "lock_branch": False,
    }


def build_environment_payload(owner_id: int, target: str) -> dict[str, Any]:
    """Build a single-owner deployment environment request body."""
    owner_id = _positive_owner_id(owner_id)
    _target_environment(target)
    return {
        "wait_timer": 0,
        "prevent_self_review": False,
        "can_admins_bypass": False,
        "reviewers": [{"type": "User", "id": owner_id}],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def build_environment_branch_policy(target: str) -> dict[str, str]:
    """Return the exact deployment-branch policy rule for an environment."""
    target = _target_environment(target)
    return {"name": TARGET_BRANCH[target], "type": "branch"}


def validate_admin_bypass_disabled(attestation: Any) -> bool:
    """Validate a separate manual UI/API attestation; REST environment readback
    does not expose whether administrators may bypass environment protections.
    """
    return _strict_bool(attestation, False)


def _mapping(value: Any) -> bool:
    return isinstance(value, Mapping)


def _strict_bool(value: Any, expected: bool) -> bool:
    return type(value) is bool and value is expected


def _empty_optional_restrictions(value: Any) -> bool:
    if value is None:
        return True
    if not _mapping(value):
        return False
    if any(key not in {"url", "users_url", "teams_url", "apps_url", "users", "teams", "apps"} for key in value):
        return False
    return all(
        type(value.get(key, [])) is list and not value.get(key, [])
        for key in ("users", "teams", "apps")
    ) and all(
        type(value[key]) is str
        for key in ("url", "users_url", "teams_url", "apps_url")
        if key in value
    )


def _allowed_keys(value: Mapping[str, Any], expected: set[str], metadata: set[str] = frozenset()) -> bool:
    return set(value).issubset(expected | metadata)


def _checks_match(value: Any) -> bool:
    if not _mapping(value) or not _allowed_keys(
        value, {"strict", "contexts", "checks"}, {"url", "contexts_url"}
    ):
        return False
    if not _strict_bool(value.get("strict"), True):
        return False
    if any(type(value.get(key)) is not str for key in ("url", "contexts_url") if key in value):
        return False
    contexts = value.get("contexts")
    checks = value.get("checks")
    if type(contexts) is not list or any(type(item) is not str for item in contexts):
        return False
    if len(contexts) != len(REQUIRED_CHECKS) or set(contexts) != set(REQUIRED_CHECKS):
        return False
    if type(checks) is not list or len(checks) != len(REQUIRED_CHECKS):
        return False
    actual: list[tuple[str, int]] = []
    for item in checks:
        if not _mapping(item) or not _allowed_keys(item, {"context", "app_id"}):
            return False
        context = item.get("context")
        app_id = item.get("app_id")
        if type(context) is not str or type(app_id) is not int:
            return False
        actual.append((context, app_id))
    expected = {(context, GITHUB_ACTIONS_APP_ID) for context in REQUIRED_CHECKS}
    return len(set(actual)) == len(REQUIRED_CHECKS) and set(actual) == expected


def validate_branch_protection_readback(branch: str, response: Any) -> bool:
    """Validate branch protections; tolerate only non-control URL metadata."""
    try:
        _target_branch(branch)
        if not _mapping(response):
            return False
        allowed = {
            "url", "required_status_checks", "enforce_admins",
            "required_pull_request_reviews", "restrictions",
            "required_conversation_resolution", "allow_force_pushes",
            "allow_deletions", "required_linear_history", "lock_branch",
            # GitHub may return these neutral/default controls in a GET shape.
            "required_signatures", "block_creations", "allow_fork_syncing",
        }
        if not set(response).issubset(allowed):
            return False
        if "url" in response and type(response["url"]) is not str:
            return False
        if not _checks_match(response.get("required_status_checks")):
            return False
        admins = response.get("enforce_admins")
        if not _mapping(admins) or not _allowed_keys(admins, {"enabled"}, {"url"}):
            return False
        if not _strict_bool(admins.get("enabled"), True):
            return False
        if "url" in admins and type(admins["url"]) is not str:
            return False
        reviews = response.get("required_pull_request_reviews")
        review_keys = {
            "dismiss_stale_reviews", "require_code_owner_reviews",
            "required_approving_review_count", "require_last_push_approval",
            "dismissal_restrictions", "bypass_pull_request_allowances",
        }
        if not _mapping(reviews) or not _allowed_keys(reviews, review_keys, {"url"}):
            return False
        if any(
            not _strict_bool(reviews.get(key), expected)
            for key, expected in (
                ("dismiss_stale_reviews", True),
                ("require_code_owner_reviews", False),
                ("require_last_push_approval", False),
            )
        ):
            return False
        approvals = reviews.get("required_approving_review_count")
        if type(approvals) is not int or approvals != 0:
            return False
        if "url" in reviews and type(reviews["url"]) is not str:
            return False
        if not _empty_optional_restrictions(reviews.get("dismissal_restrictions")):
            return False
        if not _empty_optional_restrictions(reviews.get("bypass_pull_request_allowances")):
            return False
        # For an unrestricted personal repository GitHub may omit this
        # response field entirely; absence has the same neutral meaning as
        # null/empty, but any configured restriction still fails closed.
        if not _empty_optional_restrictions(response.get("restrictions")):
            return False
        for key, expected in (
            ("required_conversation_resolution", True),
            ("allow_force_pushes", False),
            ("allow_deletions", False),
            ("required_linear_history", False),
            ("lock_branch", False),
        ):
            wrapper = response.get(key)
            if not _mapping(wrapper) or not _allowed_keys(wrapper, {"enabled"}, {"url"}):
                return False
            if not _strict_bool(wrapper.get("enabled"), expected):
                return False
            if "url" in wrapper and type(wrapper["url"]) is not str:
                return False
        for optional in ("required_signatures", "block_creations", "allow_fork_syncing"):
            if optional in response:
                wrapper = response[optional]
                if not _mapping(wrapper) or not _allowed_keys(wrapper, {"enabled"}, {"url"}):
                    return False
                # These settings are outside this policy; accept only their
                # neutral/default state, never an unreviewed extra restriction.
                if not _strict_bool(wrapper.get("enabled"), False):
                    return False
        return True
    except (GitHubProtectionError, TypeError, ValueError):
        return False


def validate_environment_readback(
    target: str,
    owner_id: int,
    response: Any,
    branch_rules: Any,
) -> bool:
    """Validate exactly one owner reviewer and the single target branch rule."""
    try:
        target = _target_environment(target)
        owner_id = _positive_owner_id(owner_id)
        if not _mapping(response):
            return False
        expected_name = target
        if response.get("name") != expected_name or type(response.get("name")) is not str:
            return False
        # GitHub GET includes metadata fields; only fixed metadata may be extra.
        allowed = {
            "id", "node_id", "name", "url", "html_url", "created_at", "updated_at",
            "protection_rules", "deployment_branch_policy", "can_admins_bypass",
        }
        if not set(response).issubset(allowed):
            return False
        for key in ("url", "html_url", "created_at", "updated_at", "node_id"):
            if key in response and type(response[key]) is not str:
                return False
        if "id" in response and (type(response["id"]) is not int or response["id"] <= 0):
            return False
        if "can_admins_bypass" in response and type(response["can_admins_bypass"]) is not bool:
            return False
        branch_policy = response.get("deployment_branch_policy")
        if not _mapping(branch_policy) or not _allowed_keys(
            branch_policy, {"protected_branches", "custom_branch_policies"}
        ):
            return False
        if not _strict_bool(branch_policy.get("protected_branches"), False):
            return False
        if not _strict_bool(branch_policy.get("custom_branch_policies"), True):
            return False

        rules = response.get("protection_rules")
        if type(rules) is not list or len(rules) not in (2, 3):
            return False
        wait_rules = [rule for rule in rules if _mapping(rule) and rule.get("type") == "wait_timer"]
        reviewer_rules = [rule for rule in rules if _mapping(rule) and rule.get("type") == "required_reviewers"]
        branch_policy_rules = [rule for rule in rules if _mapping(rule) and rule.get("type") == "branch_policy"]
        if any(
            not _mapping(rule) or rule.get("type") not in {"wait_timer", "required_reviewers", "branch_policy"}
            for rule in rules
        ):
            return False
        if len(wait_rules) not in (0, 1) or len(reviewer_rules) != 1 or len(branch_policy_rules) != 1:
            return False
        if not _allowed_keys(branch_policy_rules[0], {"type"}, {"id", "node_id"}):
            return False
        if "id" in branch_policy_rules[0] and (type(branch_policy_rules[0]["id"]) is not int or branch_policy_rules[0]["id"] <= 0):
            return False
        if "node_id" in branch_policy_rules[0] and type(branch_policy_rules[0]["node_id"]) is not str:
            return False
        # GitHub can omit a wait-timer protection rule when the configured
        # delay is zero. If it returns the rule, require the exact zero value.
        if wait_rules:
            wait_rule = wait_rules[0]
            if not _allowed_keys(wait_rule, {"type", "wait_timer"}, {"id", "node_id"}):
                return False
            if "id" in wait_rule and (type(wait_rule["id"]) is not int or wait_rule["id"] <= 0):
                return False
            if "node_id" in wait_rule and type(wait_rule["node_id"]) is not str:
                return False
            if type(wait_rule.get("wait_timer")) is not int or wait_rule["wait_timer"] != 0:
                return False
        reviewer_rule = reviewer_rules[0]
        if not _allowed_keys(
            reviewer_rule,
            {"type", "prevent_self_review", "reviewers"},
            {"id", "node_id"},
        ):
            return False
        if not _strict_bool(reviewer_rule.get("prevent_self_review"), False):
            return False
        if "id" in reviewer_rule and (type(reviewer_rule["id"]) is not int or reviewer_rule["id"] <= 0):
            return False
        if "node_id" in reviewer_rule and type(reviewer_rule["node_id"]) is not str:
            return False
        if type(reviewer_rule.get("reviewers")) is not list or len(reviewer_rule["reviewers"]) != 1:
            return False
        reviewer = reviewer_rule["reviewers"][0]
        if not _mapping(reviewer) or reviewer.get("type") != "User":
            return False
        if not _allowed_keys(reviewer, {"type", "id", "reviewer"}, {"login", "name"}):
            return False
        # Create/update payloads carry id directly. GET shapes may nest full
        # reviewer identity under `reviewer`; either shape must bind exactly.
        direct_id = reviewer.get("id")
        nested = reviewer.get("reviewer")
        if direct_id is not None:
            if type(direct_id) is not int or direct_id != owner_id:
                return False
        elif _mapping(nested):
            if type(nested.get("id")) is not int or nested["id"] != owner_id:
                return False
            user_fields = {
                "id", "node_id", "login", "avatar_url", "gravatar_id", "url", "html_url",
                "followers_url", "following_url", "gists_url", "starred_url", "subscriptions_url",
                "organizations_url", "repos_url", "events_url", "received_events_url", "type",
                "site_admin", "name", "company", "blog", "location", "email", "hireable", "bio",
                "twitter_username", "public_repos", "public_gists", "followers", "following",
                "created_at", "updated_at",
                "user_view_type",
            }
            if not set(nested).issubset(user_fields):
                return False
            user_string_fields = {
                "node_id", "login", "avatar_url", "url", "html_url", "followers_url",
                "following_url", "gists_url", "starred_url", "subscriptions_url",
                "organizations_url", "repos_url", "events_url", "received_events_url",
                "created_at", "updated_at",
            }
            nullable_string_fields = {
                "gravatar_id", "name", "company", "blog", "location", "email", "bio",
                "twitter_username",
            }
            nullable_bool_fields = {"hireable"}
            nonnegative_int_fields = {"public_repos", "public_gists", "followers", "following"}
            for key, item in nested.items():
                if key in user_string_fields and type(item) is not str:
                    return False
                if key in nullable_string_fields and item is not None and type(item) is not str:
                    return False
                if key in nullable_bool_fields and item is not None and type(item) is not bool:
                    return False
                if key in nonnegative_int_fields and (type(item) is not int or item < 0):
                    return False
                if key == "user_view_type" and (
                    type(item) is not str or item not in {"public", "private"}
                ):
                    return False
        else:
            return False
        if _mapping(nested) and direct_id is not None:
            if type(nested.get("id")) is not int or nested.get("id") != owner_id:
                return False
        if _mapping(nested):
            if "type" in nested and nested["type"] != "User":
                return False
            if "site_admin" in nested and type(nested["site_admin"]) is not bool:
                return False
            for key, item in nested.items():
                if key.endswith("_url") or key in {"url", "html_url"}:
                    if type(item) is not str:
                        return False
        if "login" in reviewer and type(reviewer["login"]) is not str:
            return False
        if "name" in reviewer and reviewer["name"] is not None and type(reviewer["name"]) is not str:
            return False

        if type(branch_rules) not in (list, tuple) or len(branch_rules) != 1:
            return False
        rule = branch_rules[0]
        expected_rule = build_environment_branch_policy(target)
        if not _mapping(rule) or rule.get("name") != expected_rule["name"] or rule.get("type") != "branch":
            return False
        if set(rule) - {"name", "type", "id", "node_id", "created_at", "updated_at"}:
            return False
        if "id" in rule and (type(rule["id"]) is not int or rule["id"] <= 0):
            return False
        if any(key in rule and type(rule[key]) is not str for key in ("node_id", "created_at", "updated_at")):
            return False
        return True
    except (GitHubProtectionError, TypeError, ValueError):
        return False
