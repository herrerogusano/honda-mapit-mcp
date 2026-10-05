import copy
import pytest

from mapit.aws_prod_geography_upgrade import ProdDeliveryAuthorization, ProdGeographyUpgradeError
from test_aws_prod_geography_upgrade import ACCOUNT, make_core


START = 1_791_220_000
ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-cfn-update"


def authorization(**changes):
    fields = dict(source_sha="a" * 40, authorized_from_epoch=START,
                  authorized_until_epoch=START + 900, service_role_arn=ROLE)
    fields.update(changes)
    return ProdDeliveryAuthorization(**fields)


def fresh_core(auth=None, **changes):
    auth = auth or authorization()
    values = dict(authorized_from_epoch=auth.authorized_from_epoch,
                  authorized_until_epoch=auth.authorized_until_epoch,
                  delivery_authorization=auth, wall_clock=lambda: START + 1)
    values.update(changes)
    return make_core(**values)


def test_fresh_cd_journal_is_distinct_and_binds_source_and_role():
    core, journal = fresh_core()
    core._step_started = core.monotonic()
    state = core._save_new_state()
    assert state["kind"] == "prod_cd_delivery"
    assert state["delivery_binding"] == {"source_sha": "a" * 40, "service_role_arn": ROLE}
    assert core._state() == state
    journal.value["kind"] = "prod_geography_upgrade"
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        core._state()


@pytest.mark.parametrize("changes", [
    {"source_sha": "0" * 40}, {"source_sha": "a" * 39}, {"source_sha": True},
    {"authorized_from_epoch": True}, {"authorized_from_epoch": 0},
    {"authorized_until_epoch": START}, {"authorized_until_epoch": START + 3601},
    {"service_role_arn": ROLE.replace(ACCOUNT, "999999999999")},
    {"service_role_arn": ROLE + "/extra"}, {"service_role_arn": None},
])
def test_invalid_authorization_denied_before_any_call(changes):
    with pytest.raises(ProdGeographyUpgradeError, match="inputs_invalid"):
        fresh_core(authorization(**changes))


def test_fresh_window_requires_explicit_opt_in_and_exact_both_bounds():
    with pytest.raises(ProdGeographyUpgradeError, match="inputs_invalid"):
        make_core(authorized_from_epoch=START, authorized_until_epoch=START + 900)
    with pytest.raises(ProdGeographyUpgradeError, match="inputs_invalid"):
        fresh_core(authorized_until_epoch=START + 901)


@pytest.mark.parametrize("field", ["source_sha", "service_role_arn"])
def test_altered_cd_journal_binding_cannot_be_reused(field):
    core, journal = fresh_core()
    core._step_started = core.monotonic()
    core._save_new_state()
    journal.value["delivery_binding"][field] = "wrong"
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        core._state()


def test_historical_journal_cannot_be_loaded_by_cd_core():
    old, old_journal = make_core()
    old._step_started = old.monotonic()
    state = old._save_new_state()
    new, journal = fresh_core()
    journal.value = copy.deepcopy(state)
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        new._state()


@pytest.mark.parametrize("clock,category", [
    (START - 1, "authorization_not_started"), (START + 900, "authorization_expired"),
])
def test_fresh_window_enforces_start_and_deadline(clock, category):
    core, _ = fresh_core(wall_clock=lambda: clock)
    core._step_started = core.monotonic()
    with pytest.raises(ProdGeographyUpgradeError, match=category):
        core._guard()
