import json

import pytest

from mapit.aws_identity_binding_infra import build_dev_identity_binding_table, dev_identity_binding_policy_draft


def test_dedicated_table_retained_closed_without_sessions_or_role_changes():
    template = build_dev_identity_binding_table()
    assert set(template["Resources"]) == {"MapitIdentityBindings"}
    resource = template["Resources"]["MapitIdentityBindings"]
    assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
    props = resource["Properties"]
    assert props["TableName"] == "honda-mapit-mcp-dev-identity-bindings"
    assert props["DeletionProtectionEnabled"] is True
    assert props["KeySchema"] == [{"AttributeName": "key", "KeyType": "HASH"}]
    assert props["BillingMode"] == "PAY_PER_REQUEST"
    assert not set(props) & {"StreamSpecification", "TimeToLiveSpecification", "GlobalSecondaryIndexes"}
    assert "AWS::IAM" not in json.dumps(template)
    assert build_dev_identity_binding_table() == template


@pytest.mark.parametrize("operator", [False, True])
def test_policy_exact_resources_no_wildcards_and_distinct_read_write(operator):
    keys = ("tenant-" + "a" * 64, "tenant-" + "b" * 64)
    policy = dev_identity_binding_policy_draft(account_id="123456789012", tenant_keys=keys, operator=operator)
    raw = json.dumps(policy)
    assert "*" not in raw and "Scan" not in raw and "Delete" not in raw and "kms:" not in raw
    assert ("dynamodb:PutItem" in raw) is operator
    assert ("ssm:PutParameter" in raw) is operator
    assert policy["Statement"][0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["identity-bindings-v1"]
    assert all("/dev/tenants/" in value for value in policy["Statement"][1]["Resource"])
    if operator:
        assert policy["Statement"][2]["Condition"] == {"StringEquals": {"ssm:Overwrite": "false"}}
        assert policy["Statement"][3]["Effect"] == "Deny"


@pytest.mark.parametrize("changes", [{"account_id": "000000000000"}, {"tenant_keys": ()},
    {"tenant_keys": ("tenant-" + "a" * 64,) * 2}, {"operator": 1}, {"tenant_keys": ("../prod",)}])
def test_policy_rejects_malformed_scope(changes):
    fields = dict(account_id="123456789012", tenant_keys=("tenant-" + "a" * 64,), operator=False)
    fields.update(changes)
    with pytest.raises(ValueError, match="^identity_binding_policy_invalid$"):
        dev_identity_binding_policy_draft(**fields)
