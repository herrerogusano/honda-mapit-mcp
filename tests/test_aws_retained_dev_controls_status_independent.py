from __future__ import annotations

import pytest

from scripts.aws_retained_dev_controls_bootstrap import RetainedDevControlsError, _resolve_internal_template
from tests.test_aws_retained_dev_controls_bootstrap import ACCOUNT, STACK_ID, _coordinator, _ok


def test_absence_read_rejects_float_http_status():
    coordinator = _coordinator()
    coordinator._started = coordinator._last_mono = 1.0

    class FloatStatusCloudFormation:
        def describe_stacks(self, **kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200.0}}

    coordinator.clients["cloudformation"] = FloatStatusCloudFormation()
    with pytest.raises(RetainedDevControlsError, match="aws_response_invalid"):
        coordinator._call_absent("describe_stacks", StackName="honda-mapit-mcp-dev-retained-controls")


def test_create_ack_rejects_float_http_status():
    coordinator = _coordinator()
    coordinator._started = coordinator._last_mono = 1.0
    coordinator._verify_app_binding = lambda: None
    coordinator._save = lambda **kwargs: None

    class FloatStatusCloudFormation:
        def create_stack(self, **kwargs):
            return _ok(StackId=STACK_ID) | {"ResponseMetadata": {"HTTPStatusCode": 200.0}}

    coordinator.clients["cloudformation"] = FloatStatusCloudFormation()
    with pytest.raises(RetainedDevControlsError, match="create_outcome_unknown"):
        coordinator._create({"preflight": True, "intent": None, "acknowledged": False})


@pytest.mark.parametrize(
    "intrinsic",
    [
        {"Fn::If": ["Always", "unexpected", "also-unexpected"]},
        {"Fn::Join": ["", ["unexpected"]]},
        {"Ref": "UnexpectedResource"},
    ],
)
def test_resolver_rejects_unknown_intrinsics(intrinsic):
    with pytest.raises(RetainedDevControlsError, match="stack_readback_mismatch"):
        _resolve_internal_template(intrinsic, ACCOUNT)
