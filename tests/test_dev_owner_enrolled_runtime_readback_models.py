"""Pinned SDK request models and bounded first-page completion semantics."""
from datetime import datetime, timezone

import pytest

from scripts import dev_owner_enrolled_runtime_readback as readback


def test_readonly_operation_argument_allowlist_matches_pinned_sdk_models():
    session_module = pytest.importorskip("botocore.session")
    from botocore import xform_name
    session = session_module.get_session()
    for service, operations in readback._OPS.items():
        model = session.get_service_model({"cognito": "cognito-idp"}.get(service, service))
        by_method = {xform_name(name): model.operation_model(name) for name in model.operation_names}
        for method, fields in operations.items():
            assert method.startswith(("get_", "describe_", "list_")) or (service, method) == ("s3", "head_object")
            operation = by_method[method]
            supported = set(operation.input_shape.members) if operation.input_shape else set()
            assert fields <= supported, (service, method, fields - supported)


@pytest.mark.parametrize("node,expected", [
    ({"Ref": "McpResourceIdentifier"}, "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp"),
    ({"Fn::Sub": "${McpResourceIdentifier}/use"}, "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp/use"),
    ({"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${McpUserPool}"},
     "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Fixture123"),
])
def test_supported_fixed_parameter_and_pool_refs_use_observed_bound_resources(node, expected):
    rows = {"McpApi": {"PhysicalResourceId": "a1b2c3d4e5"},
            "McpUserPool": {"PhysicalResourceId": "eu-west-1_Fixture123"}}
    assert readback._resolve(node, account="123456789012", rows=rows, table_arn="table") == expected


@pytest.mark.parametrize("node", [{"Ref": "UnreviewedParameter"}, {"Fn::Sub": "${UnreviewedParameter}"}])
def test_unknown_parameter_resolution_stays_closed(node):
    rows = {"McpApi": {"PhysicalResourceId": "a1b2c3d4e5"},
            "McpUserPool": {"PhysicalResourceId": "eu-west-1_Fixture123"}}
    with pytest.raises(ValueError):
        readback._resolve(node, account="123456789012", rows=rows, table_arn="table")


@pytest.mark.parametrize("operation,method", [("GetIntegrations", "get_integrations"),
    ("GetRoutes", "get_routes"), ("GetAuthorizers", "get_authorizers")])
def test_complete_api_fixture_uses_actual_pinned_sdk_output_shapes(tmp_path, operation, method):
    session_module = pytest.importorskip("botocore.session")
    from botocore.validate import validate_parameters
    from tests.test_dev_owner_enrolled_runtime_readback import _build_owner_enrolled_current_state_fixture
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    scenario = fixture["scenario"]
    response = scenario._api(method, {"ApiId": scenario.api_id, "MaxResults": "100"})
    output = session_module.get_session().get_service_model("apigatewayv2").operation_model(operation).output_shape
    validate_parameters({name: value for name, value in response.items() if name != "ResponseMetadata"}, output)


def _completion_fixture():
    authority = {"stack_id": "private-fixture-stack", "run_id": "a" * 32,
                 "execution_start_epoch": 1900000000, "execution_end_epoch": 1900000300}
    event = {"StackId": authority["stack_id"], "StackName": readback._STACK_NAME,
        "LogicalResourceId": readback._STACK_NAME, "PhysicalResourceId": authority["stack_id"],
        "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "UPDATE_COMPLETE",
        "ClientRequestToken": f"owner-enrolled-{authority['run_id']}",
        "Timestamp": datetime.fromtimestamp(1900000010, timezone.utc)}
    class Client:
        def __init__(self):
            self.calls = []
            self.events = [event]
        def describe_stack_events(self, **kwargs):
            assert kwargs == {"StackName": authority["stack_id"]}
            self.calls.append(kwargs)
            return {"ResponseMetadata": {"HTTPStatusCode": 200},
                    "StackEvents": self.events, "NextToken": "must-not-follow-or-persist"}
    return authority, Client(), event


def test_completion_accepts_unique_first_page_event_without_following_or_persisting_token():
    authority, client, _event = _completion_fixture()
    result = readback._verify_completion({"cloudformation": client}, authority, {})
    assert result["matching_completion_events"] == 1
    assert len(client.calls) == 1
    assert "must-not-follow" not in repr(result)


@pytest.mark.parametrize("mutation", ["duplicate", "exclusive_end", "wrong_token", "missing"])
def test_completion_rejects_unbound_or_ambiguous_first_page(mutation):
    authority, client, event = _completion_fixture()
    if mutation == "duplicate":
        client.events.append(dict(event))
    elif mutation == "exclusive_end":
        event["Timestamp"] = datetime.fromtimestamp(authority["execution_end_epoch"], timezone.utc)
    elif mutation == "wrong_token":
        event["ClientRequestToken"] = "other-intent"
    else:
        client.events.clear()
    with pytest.raises(readback.OwnerEnrolledReadbackError):
        readback._verify_completion({"cloudformation": client}, authority, {})
    assert len(client.calls) == 1
