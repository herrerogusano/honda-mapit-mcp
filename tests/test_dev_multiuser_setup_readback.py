from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.dev_multiuser_readback import verify_closed_setup

ACCOUNT = "123456789012"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
API = "abcdefghij"
POOL = "eu-west-1_A1b2C3d4E"
CLIENT = "SyntheticClient123"
TABLE_ARN = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants"
CALLBACK = "http://localhost:39031/callback"
RUN_ID = 2026100601


def _ok(**kwargs):
    return {**kwargs, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _records():
    types = {
        "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage", "McpHandlerRole": "AWS::IAM::Role", "McpHandlerLogGroup": "AWS::Logs::LogGroup", "McpHandler": "AWS::Lambda::Function", "McpUserPool": "AWS::Cognito::UserPool", "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain", "McpResourceServer": "AWS::Cognito::UserPoolResourceServer", "McpUserPoolClient": "AWS::Cognito::UserPoolClient", "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding", "McpTenantsTable": "AWS::DynamoDB::Table",
    }
    physical = {"McpApi": API, "McpApiStage": "$default", "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role", "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler", "McpHandler": "honda-mapit-mcp-dev-retained-handler", "McpUserPool": POOL, "McpUserPoolDomain": f"honda-mapit-mcp-dev-multiuser-{ACCOUNT}", "McpResourceServer": "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp", "McpUserPoolClient": CLIENT, "McpManagedLoginBranding": "11111111-2222-4333-8444-555555555555", "McpTenantsTable": "honda-mapit-mcp-dev-tenants"}
    return [{"LogicalResourceId": name, "ResourceType": typ, "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": physical[name]} for name, typ in types.items()]


class Cfn:
    def describe_stacks(self, **kwargs): return _ok(Stacks=[{"StackId": STACK, "StackName": "honda-mapit-mcp-dev-retained", "StackStatus": "CREATE_COMPLETE", "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev"}, {"Key": "OperatorRunId", "Value": str(RUN_ID)}]}])
    def describe_stack_resources(self, **kwargs): return _ok(StackResources=_records())


class Api:
    def get_api(self, **kwargs): return _ok(ApiId=API, Name="honda-mapit-mcp-dev-retained-api", DisableExecuteApiEndpoint=True)
    def get_routes(self, **kwargs): return _ok(Items=[], NextToken=None)


class Cognito:
    def describe_user_pool(self, **kwargs): return _ok(UserPool={"Id": POOL, "Name": "honda-mapit-mcp-dev-multiuser", "MfaConfiguration": "OFF", "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True, "UnusedAccountValidityDays": 7}, "EmailConfiguration": {"EmailSendingAccount": "COGNITO_DEFAULT"}, "UserPoolTags": {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(RUN_ID), "aws:cloudformation:stack-id": STACK, "aws:cloudformation:stack-name": "honda-mapit-mcp-dev-retained", "aws:cloudformation:logical-id": "McpUserPool"}})
    def describe_user_pool_client(self, **kwargs): return _ok(UserPoolClient={"UserPoolId": POOL, "ClientId": CLIENT, "AllowedOAuthFlowsUserPoolClient": True, "AllowedOAuthFlows": ["code"], "AllowedOAuthScopes": [f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp/use"], "CallbackURLs": [CALLBACK], "DefaultRedirectURI": CALLBACK, "SupportedIdentityProviders": ["COGNITO"], "EnableTokenRevocation": True, "PreventUserExistenceErrors": "ENABLED", "AccessTokenValidity": 60, "IdTokenValidity": 60, "RefreshTokenValidity": 30, "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"}})
    def describe_resource_server(self, **kwargs): return _ok(ResourceServer={"UserPoolId": POOL, "Identifier": f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp", "Scopes": [{"ScopeName": "use", "ScopeDescription": "Read-only MCP access."}]})
    def describe_user_pool_domain(self, **kwargs): return _ok(DomainDescription={"Domain": f"honda-mapit-mcp-dev-multiuser-{ACCOUNT}", "UserPoolId": POOL, "AWSAccountId": ACCOUNT, "Status": "ACTIVE", "ManagedLoginVersion": 2, "CustomDomainConfig": None})
    def describe_managed_login_branding_by_client(self, **kwargs): return _ok(ManagedLoginBranding={"UserPoolId": POOL, "ManagedLoginBrandingId": "11111111-2222-4333-8444-555555555555", "UseCognitoProvidedValues": True})


class Ddb:
    def describe_table(self, **kwargs): return _ok(Table={"TableName": "honda-mapit-mcp-dev-tenants", "TableArn": TABLE_ARN, "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"}, "OnDemandThroughput": {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1}, "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}], "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}]})
    def list_tags_of_resource(self, **kwargs): return _ok(Tags=[{"Key": key, "Value": value} for key, value in {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "multiuser-authorization", "OperatorRunId": str(RUN_ID)}.items()])
    def describe_time_to_live(self, **kwargs): return _ok(TimeToLiveDescription={"TimeToLiveStatus": "DISABLED"})
    def describe_continuous_backups(self, **kwargs): return _ok(ContinuousBackupsDescription={"ContinuousBackupsStatus": "ENABLED", "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}})


def _clients(): return {"cloudformation": Cfn(), "cognito": Cognito(), "apigateway": Api(), "dynamodb": Ddb()}


def test_closed_setup_readback_is_exact_and_safe():
    result = verify_closed_setup(_clients(), account=ACCOUNT, stack_arn=STACK, api_id=API, user_pool_id=POOL, client_id=CLIENT, callback_url=CALLBACK, original_creation_run_id=RUN_ID)
    assert result == {"success": True, "category": "setup_readback_verified", "calls": 13, "resources_verified": True, "api_closed": True, "cognito_verified": True, "dynamodb_verified": True}


def test_setup_rejects_wrong_cfn_resource_status_and_table_tags():
    clients = _clients(); original = clients["cloudformation"].describe_stack_resources
    def bad(**kwargs):
        rows = original(**kwargs); rows["StackResources"][0]["ResourceStatus"] = "DELETE_COMPLETE"; return rows
    clients["cloudformation"].describe_stack_resources = bad
    assert verify_closed_setup(clients, account=ACCOUNT, stack_arn=STACK, api_id=API, user_pool_id=POOL, client_id=CLIENT, callback_url=CALLBACK, original_creation_run_id=RUN_ID)["category"] == "setup_resources_mismatch"
    clients = _clients(); original = clients["dynamodb"].list_tags_of_resource
    def missing(**kwargs):
        result = original(**kwargs); result["Tags"] = result["Tags"][:-1]; return result
    clients["dynamodb"].list_tags_of_resource = missing
    assert verify_closed_setup(clients, account=ACCOUNT, stack_arn=STACK, api_id=API, user_pool_id=POOL, client_id=CLIENT, callback_url=CALLBACK, original_creation_run_id=RUN_ID)["category"] == "dynamodb_tags_mismatch"


def test_botocore_models_and_stubber_cover_actual_read_methods_without_network():
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config
    from botocore.stub import Stubber

    kwargs = {"region_name": "eu-west-1", "aws_access_key_id": "synthetic", "aws_secret_access_key": "synthetic", "aws_session_token": "synthetic", "config": Config(proxies={})}
    ddb = boto3.client("dynamodb", **kwargs)
    cognito = boto3.client("cognito-idp", **kwargs)
    assert ddb.meta.method_to_api_mapping["describe_time_to_live"] == "DescribeTimeToLive"
    assert ddb.meta.method_to_api_mapping["describe_continuous_backups"] == "DescribeContinuousBackups"
    assert cognito.meta.method_to_api_mapping["describe_managed_login_branding_by_client"] == "DescribeManagedLoginBrandingByClient"
    with Stubber(ddb) as ddb_stub, Stubber(cognito) as cognito_stub:
        ddb_stub.add_response("describe_time_to_live", {"TimeToLiveDescription": {"TimeToLiveStatus": "DISABLED"}}, {"TableName": "honda-mapit-mcp-dev-tenants"})
        ddb_stub.add_response("describe_continuous_backups", {"ContinuousBackupsDescription": {"ContinuousBackupsStatus": "ENABLED", "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}}}, {"TableName": "honda-mapit-mcp-dev-tenants"})
        cognito_stub.add_response("describe_managed_login_branding_by_client", {"ManagedLoginBranding": {"UserPoolId": POOL, "ManagedLoginBrandingId": "11111111-2222-4333-8444-555555555555", "UseCognitoProvidedValues": True}}, {"UserPoolId": POOL, "ClientId": CLIENT})
        assert ddb.describe_time_to_live(TableName="honda-mapit-mcp-dev-tenants")["TimeToLiveDescription"]["TimeToLiveStatus"] == "DISABLED"
        assert ddb.describe_continuous_backups(TableName="honda-mapit-mcp-dev-tenants")["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"] == "DISABLED"
        assert cognito.describe_managed_login_branding_by_client(UserPoolId=POOL, ClientId=CLIENT)["ManagedLoginBranding"]["UseCognitoProvidedValues"] is True
