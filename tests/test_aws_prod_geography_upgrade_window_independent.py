"""Independent regression checks for fixed, non-extendable upgrade windows."""

import pytest

from mapit.aws_prod_geography_upgrade import (
    AUTHORIZATION_CUTOFF_EPOCH,
    AUTHORIZATION_NEW_CUTOFF_EPOCH,
    AUTHORIZATION_START_EPOCH,
    ProdGeographyUpgradeError,
)
from test_aws_prod_geography_upgrade import make_core


def test_window_pair_accepts_only_exact_historic_or_renewed_epochs():
    legacy, _ = make_core()
    assert legacy.authorized_from is None
    renewed, _ = make_core(
        authorized_from_epoch=AUTHORIZATION_START_EPOCH,
        authorized_until_epoch=AUTHORIZATION_NEW_CUTOFF_EPOCH,
    )
    assert renewed.authorized_from == AUTHORIZATION_START_EPOCH
    assert renewed.authorized_until == AUTHORIZATION_NEW_CUTOFF_EPOCH

    for start, end in (
        (AUTHORIZATION_START_EPOCH - 1, AUTHORIZATION_NEW_CUTOFF_EPOCH),
        (AUTHORIZATION_START_EPOCH, AUTHORIZATION_NEW_CUTOFF_EPOCH + 1),
        (AUTHORIZATION_CUTOFF_EPOCH, AUTHORIZATION_NEW_CUTOFF_EPOCH),
        (True, AUTHORIZATION_NEW_CUTOFF_EPOCH),
    ):
        with pytest.raises(ProdGeographyUpgradeError, match="inputs_invalid"):
            make_core(authorized_from_epoch=start, authorized_until_epoch=end)


def test_journal_created_for_old_window_cannot_be_reused_or_extended():
    old_core, journal = make_core()
    old_state = old_core._save_new_state()
    assert old_state["authorization_cutoff_epoch"] == AUTHORIZATION_CUTOFF_EPOCH
    assert old_state["authorization_start_epoch"] is None

    new_core, _ = make_core(
        authorized_from_epoch=AUTHORIZATION_START_EPOCH,
        authorized_until_epoch=AUTHORIZATION_NEW_CUTOFF_EPOCH,
    )
    new_core.journal = journal
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        new_core._state()

    # Mutating persisted window metadata also invalidates the old journal.
    old_state["authorization_cutoff_epoch"] = AUTHORIZATION_NEW_CUTOFF_EPOCH
    old_state["authorization_start_epoch"] = AUTHORIZATION_START_EPOCH
    with journal.locked():
        journal.save(old_state)
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        old_core._state()
