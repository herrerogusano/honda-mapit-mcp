"""Independent botocore-shape coverage for CloudFormation template readback."""

from __future__ import annotations

from collections import OrderedDict
import json

import pytest

from scripts.dev_multiuser_closed_update import ClosedUpdateError
from test_dev_multiuser_closed_update import _core


def test_cloudformation_stubber_template_json_roundtrips_as_plain_mapping():
    botocore_session = pytest.importorskip("botocore.session")
    stubber_module = pytest.importorskip("botocore.stub")

    core, _, _ = _core()
    expected = core.prior
    session = botocore_session.Session()
    session.set_credentials("synthetic-access", "synthetic-secret")
    client = session.create_client(
        "cloudformation", region_name="eu-west-1",
        endpoint_url="https://cloudformation.eu-west-1.amazonaws.com",
    )
    stubber = stubber_module.Stubber(client)
    stubber.add_response(
        "get_template",
        {"TemplateBody": json.dumps(expected)},
        {"StackName": core.stack, "TemplateStage": "Original"},
    )
    core.clients["cloudformation"] = client

    with stubber:
        observed = core._template()

    assert observed == expected
    assert type(observed) is dict
    assert type(observed["Resources"]) is dict


def test_ordered_sdk_mapping_and_non_json_values_are_normalized_or_rejected():
    core, _, _ = _core()
    expected = core.prior
    ordered = OrderedDict((key, OrderedDict(value.items()) if type(value) is dict else value)
                          for key, value in expected.items())

    class CloudFormation:
        def get_template(self, **_kwargs):
            return {"TemplateBody": ordered}

    core.clients["cloudformation"] = CloudFormation()
    normalized = core._template()
    assert normalized == expected
    assert type(normalized["Resources"]) is dict

    class InvalidCloudFormation:
        def get_template(self, **_kwargs):
            return {"TemplateBody": OrderedDict((("Resources", {"bad": object()}),))}

    core.clients["cloudformation"] = InvalidCloudFormation()
    with pytest.raises(ClosedUpdateError, match="template_invalid"):
        core._template()
