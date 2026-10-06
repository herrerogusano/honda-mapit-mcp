from __future__ import annotations

import copy

import pytest

from scripts import build_aws_retained_dev_multiuser as builder


API = "abc123def4"
BUCKET = "honda-runtime-artifact-test-bucket"
ZIP = "1" * 64
SOURCE = "2" * 40
JWKS = "3" * 64
MANIFEST = "8" * 64
ACCOUNT = "123456789012"
START = 1_900_000_000
END = START + 300
CALLBACK = "http://localhost:39031/callback"
SUBJECTS = (
    "00000000-0000-4000-8000-000000000001",
    "00000000-0000-4000-8000-000000000002",
)
TENANTS = ("tenant-" + "6" * 64, "tenant-" + "7" * 64)


def build(**overrides):
    values = {
        "api_id": API, "bucket": BUCKET, "zip_sha256": ZIP,
        "source_sha256": SOURCE, "jwks_sha256": JWKS,
        "manifest_sha256": MANIFEST, "account_id": ACCOUNT,
        "execution_start_epoch": START, "execution_end_epoch": END,
        "callback_url": CALLBACK, "subjects": SUBJECTS,
        "tenant_keys": TENANTS,
    }
    values.update(overrides)
    return builder.build_retained_dev_multiuser_template(**values)


def test_builds_fixed_non_deploy_ready_multiuser_candidate():
    template = build()
    resources = template["Resources"]
    assert set(resources) == builder.EXPECTED_RESOURCES
    assert len(resources) == 19
    assert all(resources[name]["Condition"] == "SupportedDeployment" for name in builder.NEW_RESOURCES)
    assert all(resources[name]["DeletionPolicy"] == resources[name]["UpdateReplacePolicy"] == "Retain"
               for name in builder.NEW_RESOURCES)

    pool = resources["McpUserPool"]["Properties"]
    assert pool["MfaConfiguration"] == "OFF"
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}
    assert "EmailConfiguration" not in pool and "SmsConfiguration" not in pool
    assert "McpUserPoolUser" not in resources

    domain = resources["McpUserPoolDomain"]["Properties"]
    assert domain["ManagedLoginVersion"] == 2
    assert domain["UserPoolId"] == {"Ref": "McpUserPool"}
    server = resources["McpResourceServer"]["Properties"]
    assert server["Identifier"] == {"Ref": "McpResourceIdentifier"}
    assert server["Scopes"] == [{"ScopeName": "use", "ScopeDescription": "Read-only MCP access."}]

    client = resources["McpUserPoolClient"]["Properties"]
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["GenerateSecret"] is False
    assert client["CallbackURLs"] == [{"Ref": "OAuthCallbackURL"}]
    assert client["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceIdentifier}/use"}]

    handler = resources["McpHandler"]["Properties"]
    assert handler["Handler"] == "mapit.aws_dev_multiuser_entrypoint.handler"
    assert handler["ReservedConcurrentExecutions"] == 0
    assert handler["Code"] == {"S3Bucket": BUCKET, "S3Key": f"runtime/{ZIP}.zip"}
    assert handler["Environment"]["Variables"]["MAPIT_COGNITO_USER_POOL_ID"] == {"Ref": "McpUserPool"}
    assert handler["Environment"]["Variables"]["MAPIT_COGNITO_CLIENT_ID"] == {"Ref": "McpUserPoolClient"}
    assert handler["Environment"]["Variables"]["MAPIT_OBSERVED_API_ID"] == {"Ref": "ObservedApiId"}
    assert handler["Environment"]["Variables"]["MAPIT_MCP_ENV"] == "dev"
    assert handler["Environment"]["Variables"]["MAPIT_DEV_MULTIUSER_MODE"] == "synthetic"
    assert handler["Environment"]["Variables"]["MAPIT_DEV_MULTIUSER_MANIFEST_SHA256"] == MANIFEST
    assert handler["Environment"]["Variables"]["MAPIT_DEV_EXPECTED_ACCOUNT_ID"] == ACCOUNT
    assert handler["Environment"]["Variables"]["MAPIT_DEV_EXECUTION_START_EPOCH"] == str(START)
    assert handler["Environment"]["Variables"]["MAPIT_DEV_EXECUTION_END_EPOCH"] == str(END)

    table = resources["McpTenantsTable"]["Properties"]
    assert table["TableName"] == builder.TABLE_NAME
    assert table["BillingMode"] == "PAY_PER_REQUEST"
    assert table["OnDemandThroughput"] == {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1}
    assert "PointInTimeRecoverySpecification" not in table
    assert "SSESpecification" not in table
    assert "TimeToLiveSpecification" not in table
    assert "StreamSpecification" not in table
    assert "GlobalSecondaryIndexes" not in table

    role = resources["McpHandlerRole"]["Properties"]["Policies"]
    tenant_policy = next(item for item in role if item["PolicyName"] == "honda-mapit-mcp-dev-retained-tenant-read")
    statement = tenant_policy["PolicyDocument"]["Statement"][0]
    assert statement["Action"] == ["dynamodb:GetItem"]
    assert statement["Resource"] == {"Fn::GetAtt": ["McpTenantsTable", "Arn"]}
    assert statement["Condition"] == {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(TENANTS)}}
    assert template["Metadata"]["NotDeployReady"] is True
    assert template["Metadata"]["ObservedSubjectDigests"]
    assert template["Metadata"]["ManifestContract"]["tenants"] == [
        {"key": TENANTS[0], "subject": SUBJECTS[0], "label": "synthetic-A"},
        {"key": TENANTS[1], "subject": SUBJECTS[1], "label": "synthetic-B"},
    ]


def test_metadata_routes_are_both_read_only_and_post_is_jwt():
    resources = build()["Resources"]
    post = resources["McpPostRoute"]["Properties"]
    assert post["RouteKey"] == "POST /mcp"
    assert post["AuthorizationType"] == "JWT"
    assert post["AuthorizationScopes"] == [{"Fn::Sub": "${McpResourceIdentifier}/use"}]
    for name, path in {
        "McpProtectedResourceMetadataRoute": "GET /.well-known/oauth-protected-resource/mcp",
        "McpAuthorizationServerMetadataRoute": "GET /.well-known/oauth-authorization-server",
    }.items():
        route = resources[name]["Properties"]
        assert route["RouteKey"] == path
        assert route["AuthorizationType"] == "NONE"
        assert "AuthorizationScopes" not in route


def test_factory_does_not_mutate_retained_scaffold():
    from scripts.build_aws_retained_dev import build_retained_dev_template
    before = copy.deepcopy(build_retained_dev_template())
    result = build()
    result["Resources"]["McpTenantsTable"]["Properties"]["TableName"] = "changed"
    assert build_retained_dev_template() == before


@pytest.mark.parametrize(("name", "value", "category"), [
    ("api_id", "ABC123DEF4", "multiuser_api_id_invalid"),
    ("api_id", "not-an-api", "multiuser_api_id_invalid"),
    ("bucket", "../foreign", "multiuser_bucket_invalid"),
    ("zip_sha256", "A" * 64, "multiuser_zip_hash_invalid"),
    ("source_sha256", "3" * 64, "multiuser_source_hash_invalid"),
    ("jwks_sha256", "g" * 64, "multiuser_jwks_hash_invalid"),
    ("manifest_sha256", "g" * 64, "multiuser_manifest_hash_invalid"),
    ("account_id", "123", "multiuser_account_invalid"),
    ("callback_url", "https://localhost:39031/callback", "multiuser_callback_invalid"),
    ("callback_url", "http://example.com:39031/callback", "multiuser_callback_invalid"),
])
def test_unsafe_operator_bindings_fail_closed(name, value, category):
    with pytest.raises(builder.MultiuserTemplateError, match=category):
        build(**{name: value})


def test_subject_and_tenant_bindings_are_exactly_two_opaque_distinct_digests():
    with pytest.raises(builder.MultiuserTemplateError, match="multiuser_subject_binding_invalid"):
        build(subjects=(SUBJECTS[0], SUBJECTS[0]))
    with pytest.raises(builder.MultiuserTemplateError, match="multiuser_tenant_binding_invalid"):
        build(tenant_keys=("tenant-" + "1" * 64, "bad"))
    with pytest.raises(builder.MultiuserTemplateError, match="multiuser_tenant_binding_invalid"):
        build(tenant_keys=("tenant-" + "1" * 64, "tenant-" + "1" * 64))


@pytest.mark.parametrize("start,end", [(0, 1), (START, START), (START, START + 301), (True, START + 1)])
def test_execution_window_is_positive_integer_and_bounded(start, end):
    with pytest.raises(builder.MultiuserTemplateError, match="multiuser_execution_window_invalid"):
        build(execution_start_epoch=start, execution_end_epoch=end)


def test_forbidden_user_secret_and_broad_permission_mutations_fail(monkeypatch):
    original = builder.build_retained_dev_template
    def altered():
        value = original()
        value["Resources"]["McpHandlerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"].append("dynamodb:Scan")
        return value
    monkeypatch.setattr(builder, "build_retained_dev_template", altered)
    with pytest.raises(builder.MultiuserTemplateError):
        build()
