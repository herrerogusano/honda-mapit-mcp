from __future__ import annotations

from dataclasses import fields
import pytest

from scripts.cd_retained_dev_delivery_contract import DeliveryContractError, RetainedDevDeliveryBinding, _thaw
from test_cd_retained_dev_delivery_contract import _binding


@pytest.mark.parametrize(
    "field,kind",
    [
        ("controls_receipt", "artifact"),
        ("artifact_receipt", "controls"),
        ("prior_template_receipt", "prior-code"),
        ("prior_code_receipt", "prior-template"),
        ("lambda_receipt", "api"),
        ("api_receipt", "lambda"),
        ("iam_receipt", "controls"),
    ],
)
def test_receipt_kind_must_match_its_binding_slot(field, kind):
    receipt = {"kind": kind, "observed_at_epoch": 1900000001, "source": "aws-readback", "resource": {"name": "private"}, "closure": {"state": "closed", "checks": {"complete": True}}, "permissions": {"mode": "read_only", "checks": {"bounded": True}}}
    binding = _binding()
    values = {key: _thaw(value) for key, value in binding.__dict__.items()}
    values[field] = receipt
    with pytest.raises(DeliveryContractError):
        RetainedDevDeliveryBinding(**values)


def test_binding_keeps_controls_stack_identity_separate_from_application_stack():
    # The delivery read map has separate application, controls, and artifact
    # stacks.  A controls receipt alone cannot safely bind which stack was read.
    assert "controls_stack_arn" in {field.name for field in fields(RetainedDevDeliveryBinding)}
