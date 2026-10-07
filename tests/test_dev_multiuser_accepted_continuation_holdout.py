"""Independent holdouts for the accepted-runtime continuation path."""
from __future__ import annotations

import hashlib
import base64
import json
import time
import zipfile
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from scripts.dev_multiuser_confirmed_pair_recovery import (
    prepare_confirmed_pair_reset,
    reset_confirmed_pair_once,
    validate_recurring_pair_history,
)
from scripts.run_dev_multiuser_accepted_continuation import (
    AcceptedContinuationError,
    AcceptedContinuationInputs,
    run_accepted_runtime_continuation,
    validate_accepted_pair_lineage,
)
from tests import test_dev_multiuser_confirmed_pair_recovery as pair


def _completed_reset(original, first_pair, *, source, start, end, chain=None, include_consumed=False):
    fresh, reset, recovery = pair.Journal(), pair.Journal(), pair.Journal()
    recurring = {}
    if chain is not None:
        recurring = {
            "first_confirmed_pair_sha256": chain["first_pair_sha256"],
            "previous_reset_sha256": chain["previous_reset_sha256"],
        }
        if include_consumed:
            recurring["consumed_pair_sha256"] = chain["latest_pair_sha256"]
    prepared = prepare_confirmed_pair_reset(
        clients={"cognito": pair.Cognito()},
        original_creation_journal=original,
        latest_pair_journal=first_pair,
        fresh_user_journal=fresh,
        reset_journal=reset,
        provenance_journal=recovery,
        account=pair.ACCOUNT,
        user_pool_id=pair.POOL,
        source_sha256=source,
        authorized_from_epoch=start,
        authorized_until_epoch=end,
        allow_two_confirmed_user_resets=True,
        wall_clock=lambda: start + 1,
        **recurring,
    )
    assert prepared["success"] is True
    executed = reset_confirmed_pair_once(
        clients={"cognito": pair.Cognito()},
        fresh_user_journal=fresh,
        reset_journal=reset,
        account=pair.ACCOUNT,
        user_pool_id=pair.POOL,
        run_id=pair.RUN,
        source_sha256=source,
        authorized_from_epoch=start,
        authorized_until_epoch=end,
        allow_two_confirmed_user_resets=True,
        on_confirmed_user=lambda *_: None,
        password_factory=lambda slot: "Xx9!" + slot * 32,
        wall_clock=lambda: start + 2,
    )
    assert executed["success"] is True
    return fresh, reset, recovery


def _lineage_fixture():
    original, first_pair, *_ = pair._initial_journals()
    before = (original.load(), first_pair.load())

    users_8ed, reset_8ed, _ = _completed_reset(
        original, first_pair, source="c" * 40,
        start=pair.NEW_START, end=pair.NEW_END,
    )
    h8ed = validate_recurring_pair_history(
        original_creation_journal=original,
        first_confirmed_pair_journal=first_pair,
        latest_pair_journal=users_8ed,
        previous_reset_journal=reset_8ed,
        account=pair.ACCOUNT,
        user_pool_id=pair.POOL,
    )

    start_f247 = pair.NEW_END + 100
    end_f247 = start_f247 + 250
    users_f247, reset_f247, _ = _completed_reset(
        original, first_pair, source="d" * 40,
        start=start_f247, end=end_f247, chain=h8ed,
    )
    hf247 = validate_recurring_pair_history(
        original_creation_journal=original,
        first_confirmed_pair_journal=first_pair,
        latest_pair_journal=users_f247,
        previous_reset_journal=reset_f247,
        earlier_reset_journal=reset_8ed,
        account=pair.ACCOUNT,
        user_pool_id=pair.POOL,
    )

    start_54ad = end_f247 + 100
    end_54ad = start_54ad + 250
    users_54ad, reset_54ad, _ = _completed_reset(
        original, first_pair, source="b" * 40,
        start=start_54ad, end=end_54ad, chain=hf247, include_consumed=True,
    )
    subjects = (pair.SUB_A, pair.SUB_B)
    manifest = {
        "source_sha": "b" * 40,
        "tenants": [
            {"key": "tenant-" + "1" * 64, "subject": subjects[0], "label": "synthetic-A"},
            {"key": "tenant-" + "2" * 64, "subject": subjects[1], "label": "synthetic-B"},
        ],
    }
    binding = {
        "schema": 1,
        "operation": "dev_multiuser_closed_update",
        "account": pair.ACCOUNT,
        "caller": f"arn:aws:iam::{pair.ACCOUNT}:user/synthetic-operator",
        "end": end_54ad + 10,
        "prior": "a" * 64,
        "role": f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
        "source": "b" * 40,
        "stack": f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained/00000000-0000-0000-0000-000000000001",
        "start": start_54ad - 10,
        "target": "e" * 64,
        "token": "dev-multiuser-" + "0" * 32,
    }
    runtime = pair.Journal({"phase": "accepted", "binding": binding})
    assert (original.load(), first_pair.load()) == before
    return {
        "original_creation_users": original,
        "first_pair_users": first_pair,
        "first_reset_users": users_8ed,
        "first_reset": reset_8ed,
        "prior_reset_users": users_f247,
        "prior_reset": reset_f247,
        "accepted_users": users_54ad,
        "accepted_reset": reset_54ad,
        "accepted_runtime": runtime,
        "accepted_manifest": manifest,
        "account": pair.ACCOUNT,
        "pool": pair.POOL,
    }


def test_accepted_pair_lineage_validates_all_consumed_generations_read_only():
    inputs = _lineage_fixture()
    historic = tuple(inputs[name].load() for name in (
        "original_creation_users", "first_pair_users", "first_reset_users",
        "first_reset", "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset",
    ))
    result = validate_accepted_pair_lineage(**inputs)
    assert result["accepted_pair_sha256"] == hashlib.sha256(pair._canonical(inputs["accepted_users"].load())).hexdigest()
    assert result["accepted_runtime_binding"] == inputs["accepted_runtime"].load()["binding"]
    assert tuple(inputs[name].load() for name in (
        "original_creation_users", "first_pair_users", "first_reset_users",
        "first_reset", "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset",
    )) == historic


def test_accepted_pair_lineage_rejects_subject_or_reset_chain_mismatch():
    inputs = _lineage_fixture()
    inputs["accepted_manifest"]["tenants"][0]["subject"] = pair.SUB_B
    try:
        validate_accepted_pair_lineage(**inputs)
    except AcceptedContinuationError as exc:
        assert exc.category == "history_invalid"
    else:
        raise AssertionError("subject mismatch was accepted")

    inputs = _lineage_fixture()
    inputs["accepted_reset"].state["consumed_pair_sha256"] = "f" * 64
    try:
        validate_accepted_pair_lineage(**inputs)
    except AcceptedContinuationError as exc:
        assert exc.category == "history_invalid"
    else:
        raise AssertionError("reset chain mismatch was accepted")


def _b64u(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class _PositiveContinuationClients:
    """SDK-shaped local fakes for the orchestration happy path only."""
    def __init__(self, prior_template, old_zip, old_receipt, private_key):
        self.template = prior_template
        self.status = "UPDATE_COMPLETE"
        self.role = f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
        self.stack = f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001"
        self.function = "honda-mapit-mcp-dev-retained-handler"
        self.api_id = "a1b2c3d4e5"
        self.pool = pair.POOL
        self.client_id = "client123"
        self.table_arn = f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/honda-mapit-mcp-dev-tenants"
        self.users = {
            pair._username(pair.RUN, "A"): (pair.SUB_A, pair.OLD_START + 10),
            pair._username(pair.RUN, "B"): (pair.SUB_B, pair.LATEST_START + 10),
        }
        self.events = [{"PhysicalResourceId": self.stack, "ResourceType": "AWS::CloudFormation::Stack",
                        "ResourceStatus": "UPDATE_COMPLETE", "ClientRequestToken": "dev-multiuser-" + "0" * 32,
                        "Timestamp": pair.datetime.fromtimestamp(old_receipt.execution_start_epoch + 1, pair.timezone.utc)}]
        self.stack_event_requests = []
        self.cfn_writes = []
        self.s3_puts = []
        self.s3_objects = {"runtime/" + old_receipt.zip_sha256 + ".zip": old_zip}
        self.dynamo = {}
        self.dynamo_reads = []
        self.calls = []
        self.private_key = private_key
        self.lambda_reserved = 0
        self.api_disabled = True
        self.timeline = []
        self.step_execution = None
        self.step_machine = "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
        self.step_role = f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-shutdown-workflow"
        self.authorizer_id = "auth123"
        self.integration_id = "integration123"
        self.route_ids = {
            "POST /mcp": "route123",
            "GET /.well-known/oauth-protected-resource/mcp": "route456",
            "GET /.well-known/oauth-authorization-server": "route789",
        }
        self.invoke_policy = self._invoke_policy()
        self.sts = self
        self.cloudformation = self
        self.lambda_client = self
        self.apigatewayv2 = self
        self.cognito = self
        self.s3 = self
        self.dynamodb = self
        self.stepfunctions = self
        self.iam = self
        self.apigateway = self
        self.kms = self
        self.events_client = self
        self.cloudwatch = self

    def clients(self):
        return {"sts": self, "iam": self, "cloudformation": self, "cognito": self,
                "apigateway": self, "apigatewayv2": self, "dynamodb": self,
                "lambda": self, "stepfunctions": self, "events": self,
                "cloudwatch": self, "s3": self, "kms": self}

    @staticmethod
    def _ok(**values):
        return {**values, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_caller_identity(self):
        return self._ok(Account=pair.ACCOUNT, Arn=f"arn:aws:iam::{pair.ACCOUNT}:user/synthetic-operator")

    def describe_stacks(self, **request):
        assert request == {"StackName": self.stack}
        return self._ok(Stacks=[{"StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained",
            "StackStatus": self.status, "RoleARN": self.role, "EnableTerminationProtection": True,
            "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"},
                     {"Key": "Environment", "Value": "dev"},
                     {"Key": "Purpose", "Value": "retained-dev"},
                     {"Key": "OperatorRunId", "Value": str(pair.RUN)}]}])

    def describe_stack_resources(self, **request):
        assert request in ({"StackName": self.stack}, {"StackName": "honda-mapit-mcp-dev-retained"})
        ids = {
            "McpApi": self.api_id, "McpApiStage": "$default",
            "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
            "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
            "McpHandler": self.function, "McpUserPool": self.pool,
            "McpUserPoolDomain": f"honda-mapit-mcp-dev-multiuser-{pair.ACCOUNT}",
            "McpResourceServer": f"{self.pool}|https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp",
            "McpUserPoolClient": self.client_id,
            "McpManagedLoginBranding": f"{self.pool}|00000000-0000-4000-8000-000000000001",
            "McpJwtAuthorizer": self.authorizer_id,
            "McpLambdaIntegration": self.integration_id,
            "McpPostRoute": self.route_ids["POST /mcp"],
            "McpProtectedResourceMetadataRoute": self.route_ids["GET /.well-known/oauth-protected-resource/mcp"],
            "McpAuthorizationServerMetadataRoute": self.route_ids["GET /.well-known/oauth-authorization-server"],
            "McpTenantsTable": "honda-mapit-mcp-dev-tenants",
        }
        ids.update({name: name for name in self.template["Resources"] if name not in ids})
        return self._ok(StackResources=[{"LogicalResourceId": name, "ResourceType": row["Type"],
            "PhysicalResourceId": ids[name],
            "ResourceStatus": "UPDATE_COMPLETE", "StackId": self.stack,
            "StackName": "honda-mapit-mcp-dev-retained"}
            for name, row in self.template["Resources"].items()])

    def describe_stack_events(self, **request):
        assert request == {"StackName": self.stack}
        self.stack_event_requests.append(dict(request))
        # Model a full first SDK page with a continuation token. The accepted
        # update is present on this page; the runner must not paginate or save
        # the token as follow-up state.
        fillers = [
            {"StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained",
             "PhysicalResourceId": self.stack, "ResourceType": "AWS::CloudFormation::Stack",
             "ResourceStatus": "UPDATE_IN_PROGRESS", "ClientRequestToken": f"older-{i}",
             "Timestamp": pair.datetime.fromtimestamp(self.update_epoch - 10 - i, pair.timezone.utc)}
            for i in range(99)
        ]
        return self._ok(StackEvents=fillers + list(self.events), NextToken="synthetic-next-page")

    def get_template(self, **request):
        assert request == {"StackName": self.stack, "TemplateStage": "Original"}
        return self._ok(TemplateBody=json.loads(json.dumps(self.template)))

    def update_stack(self, **request):
        assert set(request) == {"StackName", "TemplateBody", "Capabilities", "ClientRequestToken", "RoleARN"}
        assert request["StackName"] == self.stack
        assert request["RoleARN"] == self.role
        assert request["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
        self.cfn_writes.append(request)
        self.timeline.append("cfn_update")
        self.template = json.loads(request["TemplateBody"])
        self.status = "UPDATE_COMPLETE"
        self.events = [{"StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained",
                        "PhysicalResourceId": self.stack, "ResourceType": "AWS::CloudFormation::Stack",
                        "ResourceStatus": "UPDATE_COMPLETE", "ClientRequestToken": request["ClientRequestToken"],
                        "Timestamp": pair.datetime.fromtimestamp(self.update_epoch, pair.timezone.utc)}]
        return self._ok(StackId=self.stack)

    def get_account_settings(self):
        return self._ok(AccountLimit={"ConcurrentExecutions": 10, "UnreservedConcurrentExecutions": 10},
                        AccountUsage={"FunctionCount": 1, "TotalCodeSize": 1})

    def get_function_concurrency(self, **request):
        assert request == {"FunctionName": self.function}
        if self.lambda_reserved is None:
            return self._ok()
        return self._ok(ReservedConcurrentExecutions=self.lambda_reserved)

    def delete_function_concurrency(self, **request):
        assert request == {"FunctionName": self.function}
        self.lambda_reserved = None
        return self._ok()

    def put_function_concurrency(self, **request):
        assert request == {"FunctionName": self.function, "ReservedConcurrentExecutions": 0}
        self.lambda_reserved = 0
        return self._ok(ReservedConcurrentExecutions=0)

    def get_api(self, **request):
        assert request == {"ApiId": self.api_id}
        return self._ok(ApiId=self.api_id, Name="honda-mapit-mcp-dev-retained-api", DisableExecuteApiEndpoint=self.api_disabled)

    def get_routes(self, **request):
        assert request == {"ApiId": self.api_id, "MaxResults": "100"}
        integration_target = f"integrations/{self.integration_id}"
        uri = f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        return self._ok(Items=[
            {"RouteId": self.route_ids["POST /mcp"], "RouteKey": "POST /mcp", "AuthorizationType": "JWT",
             "AuthorizerId": self.authorizer_id, "AuthorizationScopes": [uri + "/use"], "Target": integration_target},
            {"RouteId": self.route_ids["GET /.well-known/oauth-protected-resource/mcp"],
             "RouteKey": "GET /.well-known/oauth-protected-resource/mcp", "AuthorizationType": "NONE",
             "Target": integration_target},
            {"RouteId": self.route_ids["GET /.well-known/oauth-authorization-server"],
             "RouteKey": "GET /.well-known/oauth-authorization-server", "AuthorizationType": "NONE",
             "Target": integration_target},
        ])

    def get_authorizers(self, **request):
        assert request == {"ApiId": self.api_id, "MaxResults": "100"}
        return self._ok(Items=[{"AuthorizerId": self.authorizer_id, "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {"Issuer": f"https://cognito-idp.eu-west-1.amazonaws.com/{self.pool}",
                                 "Audience": [f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"]}}])

    def get_integrations(self, **request):
        assert request == {"ApiId": self.api_id, "MaxResults": "100"}
        function_arn = f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:{self.function}"
        return self._ok(Items=[{"IntegrationId": self.integration_id, "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST", "PayloadFormatVersion": "2.0", "TimeoutInMillis": 20000,
            "IntegrationUri": f"arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/{function_arn}/invocations"}])

    def update_api(self, **request):
        assert request["ApiId"] == self.api_id
        self.api_disabled = request["DisableExecuteApiEndpoint"]
        self.timeline.append("api_closed" if self.api_disabled else "api_open")
        return self._ok(ApiId=self.api_id)

    def get_function_configuration(self, **request):
        assert request == {"FunctionName": self.function}
        props = self.template["Resources"]["McpHandler"]["Properties"]
        variables = dict(props["Environment"]["Variables"])
        variables["MAPIT_COGNITO_USER_POOL_ID"] = self.pool
        variables["MAPIT_COGNITO_CLIENT_ID"] = self.client_id
        variables["MAPIT_OBSERVED_API_ID"] = self.api_id
        return self._ok(FunctionName=self.function, FunctionArn=f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:{self.function}",
            State="Active", Runtime="python3.13", Handler=props["Handler"], Architectures=["arm64"],
            MemorySize=256, Timeout=20, Environment={"Variables": variables},
            Role=f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role")

    def get_function(self, **request):
        assert request == {"FunctionName": self.function}
        key = self.template["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"]
        code_sha = base64.b64encode(hashlib.sha256(self.s3_objects[key]).digest()).decode("ascii")
        return self._ok(Configuration={"FunctionName": self.function,
            "FunctionArn": f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:{self.function}",
            "Role": f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
            "CodeSha256": code_sha})

    def get_policy(self, **request):
        assert request == {"FunctionName": self.function}
        return self._ok(Policy=json.dumps(self.invoke_policy, separators=(",", ":")))

    def _invoke_policy(self):
        function_arn = f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:{self.function}"
        prefix = f"arn:aws:execute-api:eu-west-1:{pair.ACCOUNT}:{self.api_id}/$default/"
        paths = ("POST/mcp", "GET/.well-known/oauth-protected-resource/mcp",
                 "GET/.well-known/oauth-authorization-server")
        return {"Version": "2012-10-17", "Statement": [
            {"Sid": f"AllowApiGateway{index}", "Effect": "Allow", "Action": "lambda:InvokeFunction",
             "Resource": function_arn, "Principal": {"Service": "apigateway.amazonaws.com"},
             "Condition": {"ArnLike": {"AWS:SourceArn": prefix + path},
                           "StringEquals": {"AWS:SourceAccount": pair.ACCOUNT}}}
            for index, path in enumerate(paths, start=1)]}

    def describe_user_pool(self, **request):
        assert request == {"UserPoolId": self.pool}
        return self._ok(UserPool={"Id": self.pool, "Name": "honda-mapit-mcp-dev-multiuser",
            "MfaConfiguration": "OFF", "UserPoolTier": "ESSENTIALS",
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            "UserPoolTags": {"Project": "honda-mapit-mcp", "Environment": "dev",
                "Purpose": "retained-dev", "OperatorRunId": str(pair.RUN),
                "aws:cloudformation:stack-id": self.stack,
                "aws:cloudformation:stack-name": "honda-mapit-mcp-dev-retained",
                "aws:cloudformation:logical-id": "McpUserPool"}})

    def describe_user_pool_client(self, **request):
        assert request == {"UserPoolId": self.pool, "ClientId": self.client_id}
        uri = f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        callback = "http://localhost:39031/callback"
        return self._ok(UserPoolClient={"UserPoolId": self.pool, "ClientId": self.client_id,
            "AllowedOAuthFlowsUserPoolClient": True, "AllowedOAuthFlows": ["code"],
            "AllowedOAuthScopes": [uri + "/use"], "CallbackURLs": [callback],
            "DefaultRedirectURI": callback, "SupportedIdentityProviders": ["COGNITO"],
            "EnableTokenRevocation": True, "PreventUserExistenceErrors": "ENABLED",
            "AccessTokenValidity": 60, "IdTokenValidity": 60, "RefreshTokenValidity": 30,
            "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"}})

    def describe_resource_server(self, **request):
        uri = f"https://{self.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        assert request == {"UserPoolId": self.pool, "Identifier": uri}
        return self._ok(ResourceServer={"UserPoolId": self.pool, "Identifier": uri,
            "Scopes": [{"ScopeName": "use", "ScopeDescription": "Read-only MCP access."}]})

    def describe_user_pool_domain(self, **request):
        domain = f"honda-mapit-mcp-dev-multiuser-{pair.ACCOUNT}"
        assert request == {"Domain": domain}
        return self._ok(DomainDescription={"Domain": domain, "UserPoolId": self.pool,
            "AWSAccountId": pair.ACCOUNT, "Status": "ACTIVE", "ManagedLoginVersion": 2})

    def describe_managed_login_branding_by_client(self, **request):
        assert request == {"UserPoolId": self.pool, "ClientId": self.client_id}
        return self._ok(ManagedLoginBranding={"UserPoolId": self.pool,
            "ManagedLoginBrandingId": "00000000-0000-4000-8000-000000000001",
            "UseCognitoProvidedValues": True})

    def describe_table(self, **request):
        assert request == {"TableName": "honda-mapit-mcp-dev-tenants"}
        return self._ok(Table={"TableName": "honda-mapit-mcp-dev-tenants",
            "TableArn": f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
            "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "OnDemandThroughput": {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1},
            "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
            "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
            "GlobalSecondaryIndexes": [], "LocalSecondaryIndexes": []})

    def list_tags_of_resource(self, **request):
        assert request == {"ResourceArn": f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/honda-mapit-mcp-dev-tenants"}
        return self._ok(Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "multiuser-authorization"},
            {"Key": "OperatorRunId", "Value": str(pair.RUN)}])

    def describe_time_to_live(self, **request):
        assert request == {"TableName": "honda-mapit-mcp-dev-tenants"}
        return self._ok(TimeToLiveDescription={"TimeToLiveStatus": "DISABLED"})

    def describe_continuous_backups(self, **request):
        assert request == {"TableName": "honda-mapit-mcp-dev-tenants"}
        return self._ok(ContinuousBackupsDescription={"ContinuousBackupsStatus": "ENABLED",
            "PointInTimeRecoveryDescription": {"PointInTimeRecoveryStatus": "DISABLED"}})

    def list_tags(self, **request):
        assert request == {"Resource": f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:{self.function}"}
        return self._ok(Tags={"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev"})

    def put_object(self, **request):
        assert set(request) == {"Bucket", "Key", "Body", "IfNoneMatch", "ExpectedBucketOwner",
            "ServerSideEncryption", "ChecksumSHA256", "ContentType"}
        assert request["IfNoneMatch"] == "*" and request["ExpectedBucketOwner"] == pair.ACCOUNT
        assert request["ServerSideEncryption"] == "AES256" and request["ContentType"] == "application/zip"
        assert request["Key"] == f"runtime/{hashlib.sha256(request['Body']).hexdigest()}.zip"
        assert request["ChecksumSHA256"] == base64.b64encode(hashlib.sha256(request["Body"]).digest()).decode("ascii")
        self.timeline.append("artifact_put")
        self.s3_puts.append(dict(request))
        self.s3_objects[request["Key"]] = request["Body"]
        return self._ok()

    def head_object(self, **request):
        assert request["ExpectedBucketOwner"] == pair.ACCOUNT
        body = self.s3_objects[request["Key"]]
        return self._ok(ContentLength=len(body), ChecksumSHA256=base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"), ServerSideEncryption="AES256", ContentType="application/zip")

    def get_item(self, **request):
        assert set(request) == {"TableName", "Key", "ConsistentRead", "ReturnConsumedCapacity"}
        assert request["TableName"] == self.table_arn
        assert request["ConsistentRead"] is True and request["ReturnConsumedCapacity"] == "NONE"
        key = request["Key"]["key"]["S"]
        self.dynamo_reads.append(key)
        value = self.dynamo.get(key)
        result = self._ok()
        if value is not None:
            result["Item"] = dict(value)
        return result

    def put_item(self, **request):
        assert set(request) in ({"TableName", "Item", "ConditionExpression", "ExpressionAttributeNames",
            "ReturnValues", "ReturnConsumedCapacity"}, {"TableName", "Item", "ConditionExpression",
            "ExpressionAttributeNames", "ReturnValues", "ReturnConsumedCapacity", "ExpressionAttributeValues"})
        assert request["TableName"] == self.table_arn
        assert request["ReturnValues"] == "NONE" and request["ReturnConsumedCapacity"] == "NONE"
        assert request["ConditionExpression"] in {"attribute_not_exists(#key)", "#revision = :revision AND (#status = :active OR #status = :revoked)"}
        key = request["Item"]["key"]["S"]
        self.dynamo[key] = dict(request["Item"])
        return self._ok()

    def admin_get_user(self, *, UserPoolId, Username):
        assert UserPoolId == self.pool and Username in self.users
        self.calls.append(("get", Username))
        subject, created = self.users[Username]
        return self._ok(Username=Username, Enabled=True, UserStatus="CONFIRMED",
            UserCreateDate=pair.datetime.fromtimestamp(created, pair.timezone.utc),
            UserAttributes=[{"Name": "sub", "Value": subject}])

    def admin_set_user_password(self, *, UserPoolId, Username, Password, Permanent):
        assert UserPoolId == self.pool and Username in self.users and Permanent is True
        self.calls.append(("set", Username))
        self.timeline.append(("password_set", Username))
        return self._ok()

    def describe_state_machine(self, **request):
        assert request == {"stateMachineArn": self.step_machine}
        from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
        definition = build_dev_multiuser_timed_controls(self.api_id)["Resources"]["ShutdownStateMachine"]["Properties"]["DefinitionString"]
        return self._ok(stateMachineArn=self.step_machine, type="STANDARD", status="ACTIVE",
            definition=definition, roleArn=self.step_role, loggingConfiguration={"level": "OFF"},
            tracingConfiguration={"enabled": False})

    def start_execution(self, **request):
        self.step_execution = f"arn:aws:states:eu-west-1:{pair.ACCOUNT}:execution:honda-mapit-mcp-dev-retained-shutdown:{request['name']}"
        return self._ok(executionArn=self.step_execution)

    def describe_execution(self, **request):
        assert request == {"executionArn": self.step_execution}
        return self._ok(executionArn=self.step_execution, stateMachineArn=self.step_machine,
            status="RUNNING", input='{"bounded_dev_probe":true}')


def _write_journal(path: Path, value):
    from scripts.dev_multiuser_journal import PlainFileJournal
    path.mkdir(parents=True)
    PlainFileJournal(path).save(value)


def _write_json(path: Path, value):
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="ascii")


def test_full_continuation_is_one_closed_template_update_then_reset_login_and_close(tmp_path, monkeypatch):
    """Exercise the runner's complete ordering with local SDK-shaped fakes."""
    import scripts.run_dev_multiuser_accepted_continuation as runner
    import scripts.run_dev_multiuser_hosted_acceptance as hosted
    import scripts.run_dev_multiuser_runtime_update as runtime
    from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
    from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
    from scripts.dev_multiuser_managed_login import ManagedLoginClient, ManagedLoginTokens

    chain = _lineage_fixture()
    base = 1_900_000_000
    prior_start, prior_end = base + 2_750, base + 3_000
    auth = {"account": pair.ACCOUNT, "source_sha": "c" * 40, "run_id": 2026100701,
        "expected_caller_arn": f"arn:aws:iam::{pair.ACCOUNT}:user/synthetic-operator",
        "start": base + 3_300, "end": base + 6_900, "ci_run_id": 77}
    root = tmp_path / "private"
    root.mkdir()
    private_output_root = root / "new-private-run"
    private_output_root.mkdir()
    auth_path = write_private_authorization(root / "authorization.json", auth, acl_checker=lambda _: True)
    app_stack = f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001"
    artifacts_stack = f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/00000000-0000-4000-8000-000000000002"
    roles_stack = f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained-cd-delivery/00000000-0000-4000-8000-000000000003"
    controls_stack = f"arn:aws:cloudformation:eu-west-1:{pair.ACCOUNT}:stack/honda-mapit-mcp-dev-retained-controls/00000000-0000-4000-8000-000000000004"
    fixed = {
        "account_id": pair.ACCOUNT,
        "provider_arn": f"arn:aws:iam::{pair.ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
        "owner_id": "1234567", "repository_id": "7654321",
        "observed_dev_subject_format": "immutable_environment",
        "observed_dev_subject_sha256": hashlib.sha256(b"repo:herrerogusano@1234567/honda-mapit-mcp@7654321:environment:dev").hexdigest(),
        "stack_arn": app_stack, "artifact_stack_arn": artifacts_stack,
        "handler_arn": f"arn:aws:lambda:eu-west-1:{pair.ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler",
        "api_arn": f"arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
        "shutdown_state_machine_arn": f"arn:aws:states:eu-west-1:{pair.ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown",
        "artifact_bucket_arn": f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{pair.ACCOUNT}-eu-west-1",
        "execution_role_arn": f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "lambda_environment_key_arn": f"arn:aws:kms:eu-west-1:{pair.ACCOUNT}:key/00000000-0000-4000-8000-000000000005",
        "lambda_environment_key_describe": True,
    }
    inputs_paths = {}
    for key in ("app_binding", "roles_binding", "controls_binding", "artifact_binding", "role_bindings"):
        path = root / (key + ".json")
        if key == "app_binding": value = {"stack_arn": app_stack, "original_creation_run_id": int(pair.RUN)}
        elif key == "roles_binding": value = {"stack_arn": roles_stack, "original_creation_run_id": 2026100602}
        elif key == "controls_binding": value = {"stack_arn": controls_stack, "original_creation_run_id": 2026100603}
        elif key == "artifact_binding": value = {"stack_arn": artifacts_stack, "original_creation_run_id": 2026100604}
        else: value = fixed
        _write_json(path, value); inputs_paths[key] = path

    # Prepare the accepted bundle using the same strict manifest/JWKS parser as the runtime.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = private_key.public_key().public_numbers()
    jwks = json.dumps({"keys": [{"kty": "RSA", "kid": "dev-key", "use": "sig", "alg": "RS256",
        "n": _b64u(nums.n), "e": _b64u(nums.e)}]}, separators=(",", ":")).encode("ascii")
    keys = ("tenant-" + "1" * 64, "tenant-" + "2" * 64)
    subjects = (pair.SUB_A, pair.SUB_B)
    table_arn = f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/honda-mapit-mcp-dev-tenants"
    old_manifest = {"schema": 1, "builder": "build_retained_dev_multiuser_archive", "environment": "dev",
        "synthetic": True, "source_sha": "b" * 40, "api_id": "a1b2c3d4e5", "user_pool_id": pair.POOL,
        "client_id": "client123", "jwks_sha256": hashlib.sha256(jwks).hexdigest(), "table_arn": table_arn,
        "tenants": [{"key": keys[i], "subject": subjects[i], "label": f"synthetic-{chr(65+i)}"} for i in range(2)]}
    old_raw = json.dumps(old_manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    artifact_dir = root / "accepted-artifact"; artifact_dir.mkdir()
    (artifact_dir / "manifest.json").write_bytes(old_raw)
    (artifact_dir / "jwks.json").write_bytes(jwks)
    old_zip_path = artifact_dir / "runtime.zip"
    with zipfile.ZipFile(old_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mapit/dev-multiuser.manifest.json", old_raw)
        zf.writestr("mapit/dev-multiuser.jwks.json", jwks)
        zf.writestr("mapit/__init__.py", b"")
    old_zip = old_zip_path.read_bytes()
    old_receipt = runtime.MultiuserBuildReceipt("b" * 40, "a1b2c3d4e5", pair.POOL, "client123",
        hashlib.sha256(jwks).hexdigest(), hashlib.sha256(old_raw).hexdigest(), hashlib.sha256(old_zip).hexdigest(),
        old_zip_path, prior_start, prior_end)
    prior_template = runtime.build_multiuser_candidate_template(old_receipt, account_id=pair.ACCOUNT,
        bucket=fixed["artifact_bucket_arn"].split(":::", 1)[-1], callback_url=hosted.CALLBACK_URL,
        subjects=subjects, tenant_keys=keys)
    target_sha = hashlib.sha256(json.dumps(prior_template, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    initial_setup = build_retained_dev_multiuser_setup(api_id="a1b2c3d4e5", callback_url=hosted.CALLBACK_URL)
    prior_binding_sha = hashlib.sha256(json.dumps(initial_setup, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    binding = {"schema": 1, "operation": "dev_multiuser_closed_update", "account": pair.ACCOUNT,
        "caller": auth["expected_caller_arn"], "end": prior_end + 50,
        "prior": prior_binding_sha,
        "role": f"arn:aws:iam::{pair.ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
        "source": "b" * 40, "stack": app_stack, "start": prior_start - 50, "target": target_sha,
        "token": "dev-multiuser-" + "0" * 32}
    _write_journal(root / "original-users", chain["original_creation_users"].load())
    _write_journal(root / "first-pair-users", chain["first_pair_users"].load())
    for name in ("first_reset_users", "first_reset", "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset"):
        _write_journal(root / name, chain[name].load())
    _write_journal(root / "accepted-runtime", {"phase": "accepted", "binding": binding})
    inputs = AcceptedContinuationInputs(auth_path, private_output_root,
        inputs_paths["app_binding"], inputs_paths["roles_binding"], inputs_paths["controls_binding"],
        inputs_paths["artifact_binding"], inputs_paths["role_bindings"], tmp_path / "wheels",
        root / "original-users", root / "first-pair-users", root / "first_reset_users", root / "first_reset",
        root / "prior_reset_users", root / "prior_reset", root / "accepted_users", root / "accepted_reset",
        root / "accepted-runtime", artifact_dir)

    clients = _PositiveContinuationClients(prior_template, old_zip, old_receipt, private_key)
    clients.update_epoch = auth["start"] + 20
    clients.events = [{
        "StackId": app_stack, "StackName": "honda-mapit-mcp-dev-retained",
        "PhysicalResourceId": app_stack, "ResourceType": "AWS::CloudFormation::Stack",
        "ResourceStatus": "UPDATE_COMPLETE", "ClientRequestToken": binding["token"],
        "Timestamp": pair.datetime.fromtimestamp(prior_start + 1, pair.timezone.utc),
    }]
    # Keep independent infra/IAM proof helpers at their own unit-test boundary;
    # this test exercises orchestration, exact CFN diff, S3/DDB/Cognito and timed closure.
    monkeypatch.setattr(runner, "_run_private_infrastructure_preflight", lambda *_a, **_k: None)
    monkeypatch.setattr(runner, "verify_role_pair", lambda *_a, **_k: {"success": True})
    import scripts.build_aws_dev_runtime as runtime_builder
    monkeypatch.setattr(runtime_builder, "_validate_external_wheel_dir", lambda *_a, **_k: tmp_path / "wheels")
    arm_payloads = []
    import scripts.probe_aws_dev_multiuser_arm as arm_probe
    monkeypatch.setattr(arm_probe.docker_helpers, "_docker_context", lambda: "synthetic-context")
    monkeypatch.setattr(arm_probe, "probe_candidate_archive", lambda *_a, **kwargs: arm_payloads.append(kwargs["payload"]) or {"success": True, "category": "multiuser_arm_probe_passed"})
    now = [auth["start"] + 20]
    def clock(): return now[0]
    def sleep(seconds): now[0] += max(1, int(seconds))
    reset_order = []
    token_by_user = {}

    class SyntheticLogin(ManagedLoginClient):
        def __init__(self, *, username=None, **_kwargs): self.username = username
        def dry_login_page(self): return {"success": True}
        def login(self, *, username, password):
            reset_order.append(("login", username))
            clients.timeline.append(("login", username))
            claims = {"iss": f"https://cognito-idp.eu-west-1.amazonaws.com/{pair.POOL}",
                "aud": "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp",
                "client_id": "client123", "sub": clients.users[username][0], "token_use": "access",
                "scope": "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp/use",
                "iat": int(time.time()) - 2, "exp": int(time.time()) + 300}
            token = jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "dev-key"})
            token_by_user[username] = token
            return ManagedLoginTokens(token, 300, claims["scope"])
    def build_archive(_wheels, manifest_path, jwks_path, archive_path, *, account_id):
        raw_manifest, raw_jwks = manifest_path.read_bytes(), jwks_path.read_bytes()
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("mapit/dev-multiuser.manifest.json", raw_manifest)
            zf.writestr("mapit/dev-multiuser.jwks.json", raw_jwks)
            zf.writestr("mapit/__init__.py", b"")
        return SimpleNamespace(sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
            manifest_valid=True, source_allowlist_valid=True, dependencies_valid=True, lock_valid=True)
    from scripts.dev_multiuser_managed_login import HttpResponse
    from scripts.dev_multiuser_e2e import run_http_acceptance
    def http_transport(method, url, headers, body, timeout):
        assert method == "POST" and url == f"https://{clients.api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        assert timeout == 10
        request = json.loads(body)
        rpc_id = request["id"]
        token = headers.get("Authorization", "").removeprefix("Bearer ")
        user = "a" if token == token_by_user[pair._username(pair.RUN, "A")] else "b"
        if request["method"] == "initialize":
            status, value = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"protocolVersion": "2025-03-26"}}
        elif request["method"] == "tools/list":
            if token == "":
                status, value = 403, {}
            else:
                from scripts.dev_multiuser_e2e import TOOLS
                status, value = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": [{"name": name} for name in sorted(TOOLS)]}}
        else:
            name = request["params"]["name"]
            if not token:
                status, value = 403, {}
            elif name == "get_route_detail":
                status, value = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"isError": True, "structuredContent": {}}}
            elif name == "get_distance":
                status, value = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"isError": False, "structuredContent": {"distance_km": 11 if user == "a" else 22, "route_count": 1}}}
            else:
                revoked = clients.dynamo.get(keys[0], {}).get("status", {}).get("S") == "revoked"
                if user == "a" and revoked:
                    status, value = 403, {}
                else:
                    status, value = 200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"isError": False, "structuredContent": {"status": "synthetic-A" if user == "a" else "synthetic-B"}}}
        response_body = b"" if status != 200 else json.dumps(value, separators=(",", ":")).encode()
        return HttpResponse(status, url, {}, response_body)
    http_results = []
    def http_acceptance(**kwargs):
        assert kwargs["api_id"] == clients.api_id
        result = run_http_acceptance(**kwargs, transport=http_transport, clock=http_clock, sleeper=http_sleep)
        http_results.append(result)
        return result
    http_now = [0.0]
    http_clock = lambda: http_now[0]
    http_sleep = lambda amount: http_now.__setitem__(0, http_now[0] + amount)

    historical = tuple(chain[name].load() for name in (
        "original_creation_users", "first_pair_users", "first_reset_users", "first_reset",
        "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset", "accepted_runtime"))
    result = run_accepted_runtime_continuation(inputs, clients=clients.clients(),
        source_verifier=lambda _auth: None, acl_checker=lambda _path: True,
        login_client_factory=SyntheticLogin, jwks_fetcher=lambda **_kw: (jwks, hashlib.sha256(jwks).hexdigest()),
        archive_factory=build_archive, http_acceptance=http_acceptance,
        clock=clock, monotonic=lambda: 10.0, sleep=sleep)

    assert result["success"] is True, result
    assert len(clients.cfn_writes) == 1 and len(clients.s3_puts) == 1
    request = clients.cfn_writes[0]
    updated = json.loads(request["TemplateBody"])
    assert set(updated["Resources"]) == set(prior_template["Resources"])
    assert updated["Resources"]["McpTenantsTable"]["Properties"]["KeySchema"] == prior_template["Resources"]["McpTenantsTable"]["Properties"]["KeySchema"]
    assert updated["Resources"]["McpTenantsTable"]["Properties"]["AttributeDefinitions"] == prior_template["Resources"]["McpTenantsTable"]["Properties"]["AttributeDefinitions"]
    assert updated["Resources"]["McpTenantsTable"]["Properties"] == prior_template["Resources"]["McpTenantsTable"]["Properties"]
    assert runner._only_artifact_source_window_delta(prior_template, updated)
    assert updated["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] != prior_template["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"]
    assert updated["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]["MAPIT_DEV_EXECUTION_START_EPOCH"] != prior_template["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]["MAPIT_DEV_EXECUTION_START_EPOCH"]
    assert clients.calls.count(("set", pair._username(pair.RUN, "A"))) == 1
    assert clients.calls.count(("set", pair._username(pair.RUN, "B"))) == 1
    assert reset_order.count(("login", pair._username(pair.RUN, "A"))) == 1
    assert reset_order.count(("login", pair._username(pair.RUN, "B"))) == 1
    assert clients.stack_event_requests and all(
        request == {"StackName": clients.stack} for request in clients.stack_event_requests)
    assert all(b"synthetic-next-page" not in path.read_bytes()
               for path in private_output_root.rglob("*") if path.is_file())
    assert clients.timeline.index("cfn_update") < clients.timeline.index(("password_set", pair._username(pair.RUN, "A")))
    assert clients.timeline.index(("password_set", pair._username(pair.RUN, "A"))) < clients.timeline.index(("password_set", pair._username(pair.RUN, "B")))
    assert clients.timeline.index(("password_set", pair._username(pair.RUN, "A"))) < clients.timeline.index(("login", pair._username(pair.RUN, "A")))
    assert clients.timeline.index(("login", pair._username(pair.RUN, "A"))) < clients.timeline.index(("password_set", pair._username(pair.RUN, "B")))
    assert clients.timeline.index(("password_set", pair._username(pair.RUN, "B"))) < clients.timeline.index(("login", pair._username(pair.RUN, "B")))
    assert all(name not in {"admin_create_user", "iam_update"} for name, *_ in clients.calls)
    assert clients.api_disabled is True and clients.lambda_reserved == 0
    assert http_results and http_results[0]["success"] is True and http_results[0]["category"] == "http_acceptance_verified"
    assert {row["key"]["S"] for row in clients.dynamo.values()} == set(keys)
    assert clients.timeline.index("api_open") < clients.timeline.index("api_closed")
    assert clients.timeline.index("artifact_put") < clients.timeline.index("cfn_update")
    assert arm_payloads and arm_payloads[0]["now"] >= arm_payloads[0]["start"]
    assert (private_output_root / "accepted-runtime-continuation" / "continuation").is_dir()
    # The fixed per-authorization root is consumed. A duplicate call may do
    # read-only reconciliation, but cannot publish or update a second time.
    writes_before = (len(clients.cfn_writes), len(clients.s3_puts), len([c for c in clients.calls if c[0] == "set"]))
    replay = run_accepted_runtime_continuation(inputs, clients=clients.clients(),
        source_verifier=lambda _auth: None, acl_checker=lambda _path: True,
        login_client_factory=SyntheticLogin, jwks_fetcher=lambda **_kw: (jwks, hashlib.sha256(jwks).hexdigest()),
        archive_factory=build_archive, http_acceptance=http_acceptance,
        clock=clock, monotonic=lambda: 10.0, sleep=sleep)
    assert replay["success"] is False
    assert writes_before == (len(clients.cfn_writes), len(clients.s3_puts), len([c for c in clients.calls if c[0] == "set"]))
    assert tuple(chain[name].load() for name in (
        "original_creation_users", "first_pair_users", "first_reset_users", "first_reset",
        "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset", "accepted_runtime")) == historical
