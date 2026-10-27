from __future__ import annotations

from contextlib import nullcontext
import json

import pytest

from scripts.dev_multiuser_orphan_cleanup import (
    _binding,
    _digest,
    cleanup_orphan_authorizer,
)


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/synthetic-operator"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
API = "abcdefghij"
AUTHORIZE = "auth-orphan-123"
NAME = "honda-mapit-mcp-dev-retained-jwt-authorizer"
ISSUER = f"https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_A1b2C3d4E"
AUDIENCE = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
TOKEN = "dev-multiuser-" + "a" * 32
LINEAGE_TOKEN = "dev-multiuser-" + "b" * 32
START, END = 1_900_000_000, 1_900_000_300


def ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _template():
    types = (
        "McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
        "McpUserPool", "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient",
        "McpJwtAuthorizer", "McpLambdaIntegration",
    )
    return {"Resources": {name: {"Type": "Synthetic::" + name} for name in types}}


TEMPLATE = _template()


def _auth():
    fields = {
        "account": ACCOUNT, "expected_caller_arn": CALLER, "region": "eu-west-1",
        "source_sha": "b" * 40, "token": TOKEN, "start": START, "end": END,
    }
    fields["binding_sha256"] = _digest(_binding(
        account=ACCOUNT, caller=CALLER, stack=STACK, api_id=API, region="eu-west-1",
        source=fields["source_sha"], token=TOKEN, lineage_token=LINEAGE_TOKEN,
        start=START, end=END,
        authorizer_name=NAME, issuer=ISSUER, audience=AUDIENCE,
    ))
    return fields


class Journal:
    def __init__(self, value=None):
        self.value = value
        self.saves = []

    def load(self):
        return self.value

    def save(self, value):
        self.saves.append(value)
        self.value = value

    def locked(self):
        return nullcontext()


class CloudFormation:
    def __init__(self, *, bad_event=False):
        self.calls = []
        self.bad_event = bad_event

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        return ok(Stacks=[{
            "StackId": STACK, "StackName": "honda-mapit-mcp-dev-retained",
            "StackStatus": "UPDATE_ROLLBACK_COMPLETE",
            "RoleARN": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
            "EnableTerminationProtection": True,
        }])

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        return ok(TemplateBody=json.dumps(TEMPLATE, separators=(",", ":")))

    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs))
        return ok(StackResources=[{
            "LogicalResourceId": name, "ResourceType": item["Type"],
            "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": {
                "McpApi": API, "McpApiStage": "$default",
                "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
                "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
                "McpHandler": "honda-mapit-mcp-dev-retained-handler",
                "McpUserPool": "eu-west-1_A1b2C3d4E",
            }.get(name, "physical-" + name),
        } for name, item in TEMPLATE["Resources"].items()])

    def describe_stack_events(self, **kwargs):
        self.calls.append(("describe_stack_events", kwargs))
        token = "foreign" if self.bad_event else LINEAGE_TOKEN
        return ok(StackEvents=[
            {"StackId": STACK, "ResourceType": "AWS::ApiGatewayV2::Authorizer",
             "LogicalResourceId": "McpJwtAuthorizer", "PhysicalResourceId": AUTHORIZE,
             "ClientRequestToken": token, "ResourceStatus": "CREATE_COMPLETE"},
            {"StackId": STACK, "ResourceType": "AWS::ApiGatewayV2::Authorizer",
             "LogicalResourceId": "McpJwtAuthorizer", "PhysicalResourceId": AUTHORIZE,
             "ClientRequestToken": token, "ResourceStatus": "DELETE_SKIPPED"},
        ])


class ApiGateway:
    def __init__(self, *, delete_reply=None, delete_error=None, reread_items=None):
        self.calls = []
        self.deleted = False
        self.delete_reply = delete_reply or {"ResponseMetadata": {"HTTPStatusCode": 204}}
        self.delete_error = delete_error
        self.reread_items = [] if reread_items is None else reread_items

    def get_api(self, **kwargs):
        self.calls.append(("get_api", kwargs))
        return ok(ApiId=API, ProtocolType="HTTP", DisableExecuteApiEndpoint=True)

    def get_authorizers(self, **kwargs):
        self.calls.append(("get_authorizers", kwargs))
        if self.deleted:
            return ok(Items=self.reread_items)
        return ok(Items=[{
            "ApiId": API, "AuthorizerId": AUTHORIZE, "Name": NAME,
            "AuthorizerType": "JWT", "JwtConfiguration": {"Audience": [AUDIENCE], "Issuer": ISSUER},
        }])

    def get_routes(self, **kwargs):
        self.calls.append(("get_routes", kwargs))
        return ok(Items=[])

    def get_integrations(self, **kwargs):
        self.calls.append(("get_integrations", kwargs))
        return ok(Items=[])

    def delete_authorizer(self, **kwargs):
        self.calls.append(("delete_authorizer", kwargs))
        if self.delete_error is not None:
            raise self.delete_error
        self.deleted = True
        return self.delete_reply


class Sts:
    def get_caller_identity(self, **kwargs):
        return ok(Account=ACCOUNT, Arn=CALLER)


class Lambda:
    def get_function_concurrency(self, **kwargs):
        return ok(ReservedConcurrentExecutions=0)


def _clients(*, api=None, cfn=None):
    return {
        "sts": Sts(), "cloudformation": cfn or CloudFormation(),
        "apigatewayv2": api or ApiGateway(), "lambda": Lambda(),
    }


def _run(clients=None, journal=None, **kwargs):
    return cleanup_orphan_authorizer(
        clients or _clients(), journal or Journal(), auth=_auth(), app_stack=STACK,
        api_id=API, expected_template=TEMPLATE, authorizer_name=NAME,
        issuer=ISSUER, audience=AUDIENCE, lineage_token=LINEAGE_TOKEN,
        wall_clock=lambda: START + 1, **kwargs,
    )


def test_cleanup_is_one_delete_after_exact_lineage_and_post_readback():
    api = ApiGateway()
    journal = Journal()
    result = _run(clients=_clients(api=api), journal=journal)
    assert result == {"success": True, "category": "cleanup_verified", "calls": 12}
    assert [name for name, _ in api.calls] == [
        "get_api", "get_authorizers", "get_routes", "get_integrations",
        "delete_authorizer", "get_authorizers",
    ]
    assert api.calls[-2][1] == {"ApiId": API, "AuthorizerId": AUTHORIZE}
    assert journal.value["phase"] == "complete"
    assert journal.value["authorizer_id"] == AUTHORIZE
    assert "authorizer_id" not in repr(result)


@pytest.mark.parametrize("mutation", [
    lambda auth: auth.update(account="999999999999"),
    lambda auth: auth.update(region="us-east-1"),
    lambda auth: auth.update(token="dev-multiuser-" + "b" * 32),
    lambda auth: auth.update(end=START + 3601),
])
def test_binding_mutations_fail_before_any_read(mutation):
    auth = _auth()
    mutation(auth)
    clients = _clients()
    result = cleanup_orphan_authorizer(
        clients, Journal(), auth=auth, app_stack=STACK, api_id=API,
        expected_template=TEMPLATE, authorizer_name=NAME, issuer=ISSUER,
        audience=AUDIENCE, lineage_token=LINEAGE_TOKEN, wall_clock=lambda: START + 1,
    )
    assert result["success"] is False and result["calls"] == 0


def test_foreign_event_lineage_never_deletes():
    api = ApiGateway()
    result = _run(clients=_clients(api=api, cfn=CloudFormation(bad_event=True)))
    assert result["success"] is False and result["category"] == "cleanup_lineage_mismatch"
    assert not any(name == "delete_authorizer" for name, _ in api.calls)


def test_existing_journal_is_terminal_and_never_replayed():
    api = ApiGateway()
    journal = Journal({"schema": 1, "kind": "retained-dev-orphan-authorizer-cleanup",
                       "phase": "outcome_unknown", "authorizer_id": AUTHORIZE})
    result = _run(clients=_clients(api=api), journal=journal)
    assert result == {"success": False, "category": "cleanup_journal_not_fresh", "calls": 0}
    assert api.calls == []


@pytest.mark.parametrize("delete_reply", [
    {"ResponseMetadata": {"HTTPStatusCode": 404}},
    {"ResponseMetadata": {"HTTPStatusCode": 429}},
])
def test_delete_non_204_is_ambiguous_terminal_without_retry(delete_reply):
    api = ApiGateway(delete_reply=delete_reply)
    journal = Journal()
    result = _run(clients=_clients(api=api), journal=journal)
    assert result["success"] is False and result["category"] == "cleanup_outcome_unknown"
    assert len([name for name, _ in api.calls if name == "delete_authorizer"]) == 1
    assert journal.value["phase"] == "outcome_unknown"


def test_delete_exception_is_ambiguous_and_not_replayed():
    api = ApiGateway(delete_error=RuntimeError("private token/URL"))
    journal = Journal()
    result = _run(clients=_clients(api=api), journal=journal)
    assert result["category"] == "cleanup_outcome_unknown"
    assert journal.value["phase"] == "outcome_unknown"
    replay = _run(clients=_clients(api=api), journal=journal)
    assert replay == {"success": False, "category": "cleanup_journal_not_fresh", "calls": 0}


def test_post_delete_nonempty_authorizers_is_terminal():
    api = ApiGateway(reread_items=[{"AuthorizerId": "still-present"}])
    journal = Journal()
    result = _run(clients=_clients(api=api), journal=journal)
    assert result["category"] == "cleanup_outcome_unknown"
    assert journal.value["phase"] == "outcome_unknown"
