from __future__ import annotations

import copy

import pytest

from scripts.dev_owner_enrolled_delivery import OwnerEnrolledDeliveryError, _validate_accepted
from test_dev_owner_enrolled_delivery import Harness, _accepted


@pytest.mark.parametrize("receipt,field", [
    ("invitation", "revision"),
    ("key_publication", "version"),
])
def test_accepted_receipt_integer_fields_reject_json_boolean(receipt, field):
    harness = Harness()
    accepted = copy.deepcopy(_accepted(harness.auth))
    accepted[receipt][field] = True

    with pytest.raises(OwnerEnrolledDeliveryError, match="accepted_evidence_invalid"):
        _validate_accepted(accepted, harness.auth)
