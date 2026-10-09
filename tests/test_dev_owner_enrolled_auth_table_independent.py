import pytest

from scripts.dev_owner_enrolled_runtime_readback import (
    _AUTH_TABLE, _REGION, OwnerEnrolledReadbackError, _verify_authorization_table,
)


ACCOUNT = "123456789012"
RUN_ID = 7
TABLE_ARN = f"arn:aws:dynamodb:{_REGION}:{ACCOUNT}:table/{_AUTH_TABLE}"
EXPECTED_TAGS = [
    {"Key": "Project", "Value": "honda-mapit-mcp"},
    {"Key": "Environment", "Value": "dev"},
    {"Key": "Purpose", "Value": "multiuser-authorization"},
    {"Key": "OperatorRunId", "Value": str(RUN_ID)},
]


def _case(deletion_protection=False, *, include_response=True):
    props = {
        "TableName": _AUTH_TABLE,
        "BillingMode": "PAY_PER_REQUEST",
        "OnDemandThroughput": {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1},
        "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
    }
    if deletion_protection is not None:
        props["DeletionProtectionEnabled"] = deletion_protection
    table = {
        "TableName": _AUTH_TABLE,
        "TableArn": TABLE_ARN,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {"BillingMode": props["BillingMode"]},
        "OnDemandThroughput": props["OnDemandThroughput"],
        "KeySchema": props["KeySchema"],
        "AttributeDefinitions": props["AttributeDefinitions"],
        "TableId": "33333333-3333-4333-8333-333333333333",
        "GlobalSecondaryIndexes": [],
        "LocalSecondaryIndexes": [],
    }
    if include_response:
        table["DeletionProtectionEnabled"] = deletion_protection

    class Dynamo:
        def describe_table(self, **kwargs):
            assert kwargs == {"TableName": _AUTH_TABLE}
            return {"Table": table}

        def list_tags_of_resource(self, **kwargs):
            assert kwargs == {"ResourceArn": TABLE_ARN}
            return {"Tags": EXPECTED_TAGS}

    return (
        {"dynamodb": Dynamo()},
        {"account_id": ACCOUNT, "stack_id": f"arn:aws:cloudformation:{_REGION}:{ACCOUNT}:stack/x/y"},
        {"Resources": {"McpTenantsTable": {"Properties": props}}},
        {"McpTenantsTable": {"PhysicalResourceId": _AUTH_TABLE}},
    )


def test_template_omission_means_sdk_false_and_exact_table_readback_passes():
    view, authority, template, rows = _case(False)
    template["Resources"]["McpTenantsTable"]["Properties"].pop("DeletionProtectionEnabled", None)
    assert _verify_authorization_table(
        view, authority, template, rows, expected_run_id=RUN_ID
    ) == "33333333-3333-4333-8333-333333333333"


@pytest.mark.parametrize("actual", [True, None, 0, 1, "false"])
def test_template_default_false_rejects_enabled_or_malformed_readback(actual):
    view, authority, template, rows = _case(actual)
    template["Resources"]["McpTenantsTable"]["Properties"].pop("DeletionProtectionEnabled", None)
    with pytest.raises(OwnerEnrolledReadbackError):
        _verify_authorization_table(view, authority, template, rows, expected_run_id=RUN_ID)


def test_missing_sdk_boolean_fails_closed():
    view, authority, template, rows = _case(False, include_response=False)
    template["Resources"]["McpTenantsTable"]["Properties"].pop("DeletionProtectionEnabled", None)
    with pytest.raises(OwnerEnrolledReadbackError):
        _verify_authorization_table(view, authority, template, rows, expected_run_id=RUN_ID)


def test_explicit_true_template_requires_true_sdk_boolean():
    view, authority, template, rows = _case(True)
    assert _verify_authorization_table(
        view, authority, template, rows, expected_run_id=RUN_ID
    ) == "33333333-3333-4333-8333-333333333333"


@pytest.mark.parametrize("configured", [None, 0, 1, "false"])
def test_non_boolean_template_value_is_not_normalized(configured):
    view, authority, template, rows = _case(False)
    template["Resources"]["McpTenantsTable"]["Properties"]["DeletionProtectionEnabled"] = configured
    with pytest.raises(OwnerEnrolledReadbackError):
        _verify_authorization_table(view, authority, template, rows, expected_run_id=RUN_ID)
