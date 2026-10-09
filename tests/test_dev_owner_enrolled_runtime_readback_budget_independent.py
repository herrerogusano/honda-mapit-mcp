from __future__ import annotations

import pytest

from scripts.dev_owner_enrolled_runtime_readback import (
    OwnerEnrolledReadbackError,
    _ReadBudget,
)


OWNER_KEY = "owner-key-" + "a" * 64
EXPECTED_PATH = (
    f"/honda-mapit-mcp/dev/tenants/{OWNER_KEY}/mapit-refresh-token"
)


class ProviderError(Exception):
    def __init__(self, code="ParameterNotFound", status=400):
        # Deliberately include sensitive-looking provider text: callers should
        # see it only on the exact expected absence path, where the namespace
        # verifier converts it to a fixed result.
        super().__init__("provider detail must not escape")
        self.response = {
            "Error": {"Code": code, "Message": "provider detail must not escape"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class FakeSsm:
    def __init__(self, error):
        self.error = error
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        raise self.error


def make_budget(error, *, path=EXPECTED_PATH, decrypt=False, clock=None,
                monotonic=None):
    authority = {
        "authorized_from_epoch": 100,
        "authorized_until_epoch": 200,
        "owner_tenant_key": OWNER_KEY,
    }
    ssm = FakeSsm(error)
    budget = _ReadBudget(
        authority=authority,
        clock=clock or (lambda: 110),
        monotonic=monotonic or (lambda: 1),
        max_calls=3,
    )
    budget.clients = {"ssm": ssm}
    return budget, ssm, {"Name": path, "WithDecryption": decrypt}


def test_only_exact_owner_refresh_token_absence_is_passthrough():
    error = ProviderError()
    budget, ssm, kwargs = make_budget(error)

    with pytest.raises(ProviderError) as caught:
        budget.call("ssm", "get_parameter", **kwargs)

    assert caught.value is error
    assert ssm.calls == [kwargs]
    assert budget.calls == 1


@pytest.mark.parametrize(
    "kwargs,error",
    [
        ({"Name": EXPECTED_PATH + "/extra", "WithDecryption": False}, ProviderError()),
        ({"Name": EXPECTED_PATH, "WithDecryption": True}, ProviderError()),
        ({"Name": EXPECTED_PATH, "WithDecryption": False}, ProviderError("AccessDenied", 400)),
        ({"Name": EXPECTED_PATH, "WithDecryption": False}, ProviderError("ParameterNotFound", 403)),
        ({"Name": EXPECTED_PATH, "WithDecryption": False}, ProviderError("ParameterNotFound", True)),
    ],
)
def test_near_miss_absence_errors_become_fixed_safe_failure(kwargs, error):
    budget, ssm, _ = make_budget(error)

    with pytest.raises(OwnerEnrolledReadbackError) as caught:
        budget.call("ssm", "get_parameter", **kwargs)

    assert caught.value.category == "current_state_unverified"
    assert str(caught.value) == "current_state_unverified"
    assert "provider detail" not in str(caught.value)
    assert ssm.calls == [kwargs]
    assert budget.calls == 1


def test_expected_absence_is_not_passthrough_after_clock_rollback():
    clock_values = iter((110, 110, 109))
    budget, ssm, kwargs = make_budget(
        ProviderError(), clock=lambda: next(clock_values)
    )

    with pytest.raises(OwnerEnrolledReadbackError) as caught:
        budget.call("ssm", "get_parameter", **kwargs)

    assert caught.value.category == "current_state_unverified"
    assert ssm.calls == [kwargs]
    assert budget.calls == 1


def test_expected_absence_is_not_passthrough_at_exclusive_deadline():
    wall_values = iter((110, 110, 110))
    mono_values = iter((1, 1, 91))
    budget, ssm, kwargs = make_budget(
        ProviderError(), clock=lambda: next(wall_values),
        monotonic=lambda: next(mono_values),
    )

    with pytest.raises(OwnerEnrolledReadbackError) as caught:
        budget.call("ssm", "get_parameter", **kwargs)

    assert caught.value.category == "current_state_unverified"
    assert ssm.calls == [kwargs]
    assert budget.calls == 1
