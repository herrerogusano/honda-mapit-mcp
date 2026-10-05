from copy import deepcopy

import pytest

from scripts.github_cd_protections import (
    GITHUB_ACTIONS_APP_ID,
    REQUIRED_CHECKS,
    GitHubProtectionError,
    build_branch_protection_payload,
    build_environment_branch_policy,
    build_environment_payload,
    validate_admin_bypass_disabled,
    validate_branch_protection_readback,
    validate_environment_readback,
)


OWNER_ID = 445566  # Synthetic fixture only.


def _branch_readback():
    expected = build_branch_protection_payload("main")
    checks = expected["required_status_checks"]
    reviews = expected["required_pull_request_reviews"]
    return {
        "url": "https://api.github.com/repos/example/example/branches/main/protection",
        "required_status_checks": {
            **checks,
            # The GET/readback schema returns both contexts and checks even
            # though the PUT body must send only the app-bound `checks` field.
            "contexts": list(REQUIRED_CHECKS),
            "url": "https://api.github.com/required_status_checks",
            "contexts_url": "https://api.github.com/contexts",
        },
        "enforce_admins": {"url": "https://api.github.com/enforce_admins", "enabled": True},
        "required_pull_request_reviews": {
            **reviews,
            "url": "https://api.github.com/reviews",
            "dismissal_restrictions": {"users": [], "teams": [], "apps": []},
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "restrictions": None,
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "required_linear_history": {"enabled": False},
        "lock_branch": {"enabled": False},
        "required_signatures": {"enabled": False},
    }


def _environment_readback(target="dev", *, owner_id=OWNER_ID):
    return {
        "id": 123456,
        "node_id": "MDExOkVudmlyb25tZW50MTIzNDU2",
        "name": target,
        "url": f"https://api.github.com/repos/example/example/environments/{target}",
        "html_url": f"https://github.com/example/example/deployments/activity_log?environments_filter={target}",
        "created_at": "2026-10-05T12:00:00Z",
        "updated_at": "2026-10-05T12:01:00Z",
        "can_admins_bypass": False,
        "protection_rules": [
            {"id": 501, "node_id": "MDQ6R2F0ZTUwMQ==", "type": "wait_timer", "wait_timer": 0},
            {
                "id": 502,
                "node_id": "MDQ6R2F0ZTUwMg==",
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {
                            "id": owner_id,
                            "node_id": "MDQ6VXNlcjQ0NTU2Ng==",
                            "login": "synthetic-owner",
                            "url": "https://api.github.com/users/synthetic-owner",
                            "html_url": "https://github.com/synthetic-owner",
                            "type": "User",
                            "site_admin": False,
                            "user_view_type": "public",
                        },
                    }
                ],
            },
            {"id": 503, "node_id": "MDQ6R2F0ZTUwMw==", "type": "branch_policy"},
        ],
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
    }


def test_branch_payload_is_exact_and_pins_checks_to_github_actions() -> None:
    for branch in ("main", "develop"):
        payload = build_branch_protection_payload(branch)
        checks = payload["required_status_checks"]
        assert checks["strict"] is True
        assert "contexts" not in checks
        assert checks["checks"] == [
            {"context": name, "app_id": GITHUB_ACTIONS_APP_ID} for name in REQUIRED_CHECKS
        ]
        assert payload["enforce_admins"] is True
        reviews = payload["required_pull_request_reviews"]
        assert reviews == {
            "dismiss_stale_reviews": True,
            "require_code_owner_reviews": False,
            "required_approving_review_count": 0,
            "require_last_push_approval": False,
        }
        assert payload["restrictions"] is None
        assert payload["required_conversation_resolution"] is True
        assert payload["allow_force_pushes"] is False
        assert payload["allow_deletions"] is False
        assert payload["required_linear_history"] is False
        assert payload["lock_branch"] is False


def test_branch_payload_uses_only_app_bound_checks_not_deprecated_contexts() -> None:
    payload = build_branch_protection_payload("main")
    status_checks = payload["required_status_checks"]
    assert set(status_checks) == {"strict", "checks"}
    assert len(status_checks["checks"]) == 8
    assert all(item["app_id"] == GITHUB_ACTIONS_APP_ID for item in status_checks["checks"])


@pytest.mark.parametrize("branch", ["release", "refs/heads/main", "", None, True])
def test_branch_payload_rejects_nonfixed_branches(branch) -> None:
    with pytest.raises(GitHubProtectionError) as error:
        build_branch_protection_payload(branch)
    assert error.value.category == "invalid_branch"


def test_branch_readback_accepts_only_exact_controls_and_metadata_urls() -> None:
    assert validate_branch_protection_readback("main", _branch_readback())
    assert validate_branch_protection_readback("develop", _branch_readback())


def test_branch_readback_accepts_omitted_restrictions_as_unrestricted() -> None:
    response = _branch_readback()
    del response["restrictions"]
    assert validate_branch_protection_readback("main", response)

    response["restrictions"] = {"users": [{"id": 445566}]}
    assert not validate_branch_protection_readback("main", response)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("required_status_checks", "strict"), 1),
        (("required_status_checks", "checks", 0, "app_id"), None),
        (("required_pull_request_reviews", "required_approving_review_count"), True),
        (("required_pull_request_reviews", "bypass_pull_request_allowances"), {"users": [{"id": 9}]}),
        (("required_pull_request_reviews", "dismissal_restrictions"), {"teams": [{"id": 8}]}),
        (("enforce_admins", "enabled"), False),
        (("allow_force_pushes", "enabled"), True),
        (("allow_deletions", "enabled"), True),
        (("required_conversation_resolution", "enabled"), False),
        (("lock_branch", "enabled"), True),
    ],
)
def test_branch_readback_rejects_wrong_or_weakened_security_fields(path, value) -> None:
    response = deepcopy(_branch_readback())
    current = response
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value
    assert not validate_branch_protection_readback("main", response)


def test_branch_readback_rejects_missing_checks_duplicates_and_unexpected_controls() -> None:
    response = _branch_readback()
    del response["required_status_checks"]["checks"]
    assert not validate_branch_protection_readback("main", response)

    response = _branch_readback()
    response["required_status_checks"]["contexts"][0] = response["required_status_checks"]["contexts"][1]
    assert not validate_branch_protection_readback("main", response)

    response = _branch_readback()
    response["bypass_actors"] = []
    assert not validate_branch_protection_readback("main", response)


def test_branch_payload_copy_is_fresh_and_environment_policy_is_fixed() -> None:
    one = build_branch_protection_payload("develop")
    one["required_status_checks"]["checks"].clear()
    assert len(build_branch_protection_payload("develop")["required_status_checks"]["checks"]) == 8
    assert build_environment_branch_policy("dev") == {"name": "develop", "type": "branch"}
    assert build_environment_branch_policy("prod") == {"name": "main", "type": "branch"}


def test_environment_payload_requires_positive_exact_owner_id_and_has_no_extra_reviewer() -> None:
    payload = build_environment_payload(OWNER_ID, "dev")
    assert payload == {
        "wait_timer": 0,
        "prevent_self_review": False,
        "can_admins_bypass": False,
        "reviewers": [{"type": "User", "id": OWNER_ID}],
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
    }
    assert build_environment_payload(OWNER_ID, "prod")["reviewers"] == [{"type": "User", "id": OWNER_ID}]


@pytest.mark.parametrize("owner_id", [0, -1, True, 1.0, "445566", None])
def test_environment_payload_rejects_nonpositive_or_noninteger_owner_id(owner_id) -> None:
    with pytest.raises(GitHubProtectionError) as error:
        build_environment_payload(owner_id, "dev")
    assert error.value.category == "invalid_owner_id"


@pytest.mark.parametrize("target", ["stage", "main", "", None, True])
def test_environment_payload_rejects_unknown_target(target) -> None:
    with pytest.raises(GitHubProtectionError) as error:
        build_environment_payload(OWNER_ID, target)
    assert error.value.category == "invalid_target"


def test_environment_readback_accepts_exact_owner_policy_and_external_branch_rule() -> None:
    assert validate_environment_readback(
        "dev", OWNER_ID, _environment_readback("dev"), [{"name": "develop", "type": "branch", "id": 701}]
    )
    assert validate_environment_readback(
        "prod", OWNER_ID, _environment_readback("prod"), [{"name": "main", "type": "branch"}]
    )


@pytest.mark.parametrize("bypass", [False, True])
def test_environment_readback_accepts_optional_strict_admin_bypass_boolean(bypass) -> None:
    response = _environment_readback()
    response["can_admins_bypass"] = bypass
    assert validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])


def test_environment_readback_does_not_infer_bypass_when_field_is_absent() -> None:
    response = _environment_readback()
    del response["can_admins_bypass"]
    assert validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])
    assert not validate_admin_bypass_disabled(response.get("can_admins_bypass"))


@pytest.mark.parametrize("mutate", [
    lambda data: data.update(name="prod"),
    lambda data: data["protection_rules"].append({"type": "custom_rules", "id": 9}),
    lambda data: data["protection_rules"][0].update(wait_timer=True),
    lambda data: data["protection_rules"][1].update(prevent_self_review=0),
    lambda data: data["protection_rules"][1]["reviewers"].append({"type": "Team", "id": 12}),
    lambda data: data["protection_rules"][1]["reviewers"][0]["reviewer"].update(id=OWNER_ID + 1),
    lambda data: data["protection_rules"][1]["reviewers"][0]["reviewer"].update(type="Team"),
    lambda data: data["deployment_branch_policy"].update(protected_branches=True),
    lambda data: data.update(can_admins_bypass="false"),
    lambda data: data["protection_rules"][1]["reviewers"][0]["reviewer"].update(user_view_type=[]),
])
def test_environment_readback_rejects_drift_extra_reviewers_and_unmodeled_bypass(mutate) -> None:
    response = deepcopy(_environment_readback())
    mutate(response)
    assert not validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])


@pytest.mark.parametrize("rules", [
    [],
    [{"name": "develop", "type": "branch"}, {"name": "main", "type": "branch"}],
    [{"name": "main", "type": "branch"}],
    [{"name": "develop/*", "type": "branch"}],
    [None],
])
def test_environment_branch_rule_readback_requires_one_exact_literal_rule(rules) -> None:
    assert not validate_environment_readback("dev", OWNER_ID, _environment_readback(), rules)


def test_environment_readback_allows_omitted_zero_wait_rule_but_no_extra_rules() -> None:
    response = _environment_readback()
    response["protection_rules"] = [rule for rule in response["protection_rules"] if rule["type"] != "wait_timer"]
    assert validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])

    response["protection_rules"].append({"type": "custom_rules", "id": 701})
    assert not validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("login", 123),
        ("node_id", 123),
        ("public_repos", "4"),
        ("followers", True),
        ("email", []),
        ("hireable", "false"),
    ],
)
def test_environment_readback_rejects_malformed_nested_user_metadata(field, value) -> None:
    response = _environment_readback()
    user = response["protection_rules"][1]["reviewers"][0]["reviewer"]
    user[field] = value
    assert not validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])


def test_environment_readback_accepts_documented_nullable_user_metadata() -> None:
    response = _environment_readback()
    user = response["protection_rules"][1]["reviewers"][0]["reviewer"]
    user.update(gravatar_id=None, name=None, company=None, email=None, hireable=None)
    assert validate_environment_readback("dev", OWNER_ID, response, [{"name": "develop", "type": "branch"}])


@pytest.mark.parametrize("attestation", [None, 0, 1, "false", {}, True])
def test_admin_bypass_manual_attestation_fails_closed_unless_false(attestation) -> None:
    assert not validate_admin_bypass_disabled(attestation)


def test_admin_bypass_manual_attestation_requires_explicit_false() -> None:
    assert validate_admin_bypass_disabled(False)


def test_admin_bypass_can_be_checked_from_actual_environment_readback() -> None:
    response = _environment_readback()
    assert validate_admin_bypass_disabled(response["can_admins_bypass"])
    response["can_admins_bypass"] = True
    assert not validate_admin_bypass_disabled(response["can_admins_bypass"])
