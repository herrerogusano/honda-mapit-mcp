"""Independent fail-closed regressions for hosted login diagnostics."""

from __future__ import annotations

import pytest

from scripts.dev_multiuser_managed_login import (
    ManagedLoginClient,
    ManagedLoginError,
    provision_and_login_pair,
)
from scripts.run_dev_multiuser_hosted_acceptance import HostedAcceptanceError


@pytest.mark.parametrize("value", [{"secret": "https://private/token"}, ["secret"]])
def test_diagnostic_error_allowlists_reject_unhashable_values(value):
    managed = ManagedLoginError(value, stage=value)
    assert managed.category == "response_invalid"
    assert managed.stage is None

    hosted = HostedAcceptanceError(value, stage=value, login_category=value)
    assert hosted.category == "runner_failed"
    assert hosted.stage is None
    assert hosted.login_category is None


def test_pair_bridge_resanitizes_mutated_managed_error_fields():
    class FailedClient(ManagedLoginClient):
        def login(self, *, username, password):
            error = ManagedLoginError("callback_invalid", stage="login_post")
            error.category = {"secret": "token"}
            error.stage = {"secret": "private-url"}
            raise error

    class Operator:
        def provision(self, *, on_confirmed_user):
            with pytest.raises(ManagedLoginError):
                on_confirmed_user("synthetic-a", "password-never-output")
            return {"success": False, "category": "login_failed"}

    result = provision_and_login_pair(Operator(), lambda: FailedClient.__new__(FailedClient))
    assert result == {
        "success": False,
        "category": "login_failed",
        "login_category": "response_invalid",
        "stage": "client_factory",
        "users": 0,
    }
    assert "token" not in repr(result)
    assert "private-url" not in repr(result)


def test_pair_bridge_does_not_propagate_arbitrary_operator_category():
    class Operator:
        def provision(self, *, on_confirmed_user):
            return {"success": False, "category": "https://private/token?secret=1"}

    result = provision_and_login_pair(Operator(), lambda: None)
    assert result == {"success": False, "category": "response_invalid", "users": 0}
    assert "private/token" not in repr(result)
