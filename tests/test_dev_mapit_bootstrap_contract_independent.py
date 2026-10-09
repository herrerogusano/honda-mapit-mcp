from __future__ import annotations

import copy

import pytest

from scripts.dev_mapit_bootstrap_contract import (
    ExclusiveWindow,
    MapitBootstrapContractError,
    build_plan,
    create_only_intent,
    validate_intent,
)
from tests.test_dev_mapit_bootstrap_contract import Clock, authority


def test_intent_schema_and_integer_fields_do_not_accept_json_booleans():
    auth = authority(run_id=1)
    plan = build_plan(auth)
    clock = Clock()
    intent = create_only_intent(auth, plan, journal_state=None,
        window=ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic))

    for key in ("schema", "run_id", "authorized_from_epoch", "authorized_until_epoch"):
        tampered = copy.deepcopy(intent)
        tampered[key] = True
        assert validate_intent(tampered, auth, plan) is False


def test_authority_rejects_nonpositive_unix_window_epochs():
    with pytest.raises(MapitBootstrapContractError):
        authority(authorized_from_epoch=-600, authorized_until_epoch=0)


def test_rollback_is_a_sticky_window_failure():
    auth = authority()
    clock = Clock(wall=auth.authorized_from_epoch + 1, mono=10.0)
    guard = ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic)
    guard.check(auth)
    clock.wall -= 1.0
    clock.mono += 1.0
    with pytest.raises(MapitBootstrapContractError, match="clock_rollback"):
        guard.check(auth)

    clock.wall = auth.authorized_from_epoch + 2
    clock.mono += 1.0
    with pytest.raises(MapitBootstrapContractError):
        guard.check(auth)


def test_create_intent_rejects_duck_typed_window_objects():
    auth = authority()
    plan = build_plan(auth)

    class UnboundWindow:
        def check(self, _authority):
            return float(auth.authorized_from_epoch + 1), 1.0

    with pytest.raises(MapitBootstrapContractError):
        create_only_intent(auth, plan, journal_state=None, window=UnboundWindow())
