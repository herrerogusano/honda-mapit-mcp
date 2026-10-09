from __future__ import annotations

from datetime import datetime, timezone
from collections import OrderedDict

import pytest

from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template
from scripts.dev_owner_oauth_sdk import (
    APP_STACK,
    DOMAIN,
    IDENTITY_STACK,
    OwnerOAuthSdkBindings,
    OwnerOAuthSdkError,
)


ACCOUNT = "123456789012"
POOL = "eu-west-1_abcdefghijk"
API = "abcdefghij"
CALLBACK = "http://localhost:39031/callback/codex-dev-owner"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/operator"
HANDLER = "honda-mapit-mcp-dev-retained-handler"
RESOURCE_URI = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
STACK_IDS = {
    IDENTITY_STACK: f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{IDENTITY_STACK}/11111111-1111-4111-8111-111111111111",
    APP_STACK: f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{APP_STACK}/22222222-2222-4222-8222-222222222222",
}


def _ok(**values):
    return {**values, "ResponseMetadata": {"HTTPStatusCode": 200}}


class _Service:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def __getattr__(self, method):
        def invoke(**kwargs):
            self.calls.append((method, kwargs))
            return self.handler(method, kwargs)
        return invoke


def _resources(name, count):
    logicals = (
        ["McpUserPool", "McpUserPoolDomain", "McpUserPoolClient", "McpManagedLoginBranding"]
        if name == IDENTITY_STACK else ["McpApi", "McpHandler"]
    )
    rows = []
    for index in range(count):
        logical = logicals[index] if index < len(logicals) else f"Extra{index:02d}"
        physical = {
            "McpUserPool": POOL,
            "McpUserPoolClient": "ownerclient123",
            "McpManagedLoginBranding": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "McpApi": API,
            "McpHandler": HANDLER,
        }.get(logical, f"physical-{name}-{index}")
        rows.append({
            "LogicalResourceId": logical,
            "PhysicalResourceId": physical,
            "ResourceType": "AWS::Test::Resource",
            "ResourceStatus": "CREATE_COMPLETE",
        })
    return rows


class _ContextClients:
    def __init__(self):
        self.client_ids = ["ownerclient123", "prodclient456"]
        self.protected_scope = ["https://production.example/mcp/use"]
        self.mfa_enabled = True
        self.template_body = {"Resources": {"Example": {"Type": "AWS::Test::Resource"}}}
        self.clock = None
        self.services = {}
        self.services["sts"] = _Service(lambda method, kw: _ok(Account=ACCOUNT, Arn=CALLER))
        self.services["cloudformation"] = _Service(self._cloudformation)
        self.services["cognito"] = _Service(self._cognito)
        self.services["apigatewayv2"] = _Service(lambda method, kw: _ok(
            ApiId=API, DisableExecuteApiEndpoint=True,
        ))
        self.services["lambda"] = _Service(self._lambda)

    def _cloudformation(self, method, kw):
        if method == "describe_stacks":
            name = kw["StackName"]
            stack_id = STACK_IDS[name]
            return _ok(Stacks=[{
                "StackName": name,
                "StackId": stack_id,
                "StackStatus": "UPDATE_COMPLETE",
                "EnableTerminationProtection": True,
            }])
        if method == "list_stack_resources":
            name = next(key for key, value in STACK_IDS.items() if value == kw["StackName"])
            count = 4 if name == IDENTITY_STACK else 19
            return _ok(StackResourceSummaries=_resources(name, count))
        if method == "get_template":
            return _ok(TemplateBody=self.template_body)
        raise AssertionError(method)

    def _cognito(self, method, kw):
        if method == "describe_user_pool":
            return _ok(UserPool={
                "Id": POOL,
                "Arn": f"arn:aws:cognito-idp:eu-west-1:{ACCOUNT}:userpool/{POOL}",
                "Name": "honda-mapit-mcp-identity",
                "MfaConfiguration": "ON",
                "DeletionProtection": "ACTIVE",
                "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
                "UserPoolTier": "ESSENTIALS",
            })
        if method == "get_user_pool_mfa_config":
            return _ok(
                MfaConfiguration="ON",
                SoftwareTokenMfaConfiguration={"Enabled": self.mfa_enabled},
                SmsMfaConfiguration={"Enabled": False},
            )
        if method == "describe_user_pool_domain":
            return _ok(DomainDescription={
                "Domain": DOMAIN,
                "UserPoolId": POOL,
                "AWSAccountId": ACCOUNT,
                "Status": "ACTIVE",
                "ManagedLoginVersion": 2,
            })
        if method == "list_user_pool_clients":
            return _ok(UserPoolClients=[{
                "ClientId": client_id,
                "ClientName": "owner" if client_id == "ownerclient123" else "existing",
                "UserPoolId": POOL,
            } for client_id in self.client_ids])
        if method == "describe_user_pool_client":
            client_id = kw["ClientId"]
            if client_id == "prodclient456":
                return _ok(UserPoolClient={
                    "ClientId": client_id, "UserPoolId": POOL,
                    "ClientName": "existing", "AllowedOAuthScopes": self.protected_scope,
                })
            return _ok(UserPoolClient={
                "ClientId": client_id, "UserPoolId": POOL, "ClientName": "owner",
            })
        if method == "describe_resource_server":
            return _ok(ResourceServer={
                "UserPoolId": POOL, "Identifier": RESOURCE_URI,
                "Name": "honda-mapit-mcp-identity", "Scopes": [{"ScopeName": "use"}],
            })
        if method == "describe_managed_login_branding_by_client":
            return _ok(ManagedLoginBranding={
                "ManagedLoginBrandingId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "UserPoolId": POOL, "ClientId": kw["ClientId"],
                "UseCognitoProvidedValues": True,
            })
        raise AssertionError(method)

    def _lambda(self, method, kw):
        if method == "get_function_concurrency":
            return _ok(ReservedConcurrentExecutions=0)
        if method == "get_function_configuration":
            return _ok(
                FunctionName=HANDLER,
                FunctionArn=f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:{HANDLER}",
                State="Active", LastUpdateStatus="Successful",
                CodeSha256="fixture-code-hash", Role=f"arn:aws:iam::{ACCOUNT}:role/execution",
                Handler="mapit.handler", Runtime="python3.13", Architectures=["arm64"],
                Timeout=15, MemorySize=256, RevisionId="revision-fixture",
            )
        raise AssertionError(method)


def _bindings(clients, **kwargs):
    return OwnerOAuthSdkBindings(
        clients.services,
        account_id=ACCOUNT,
        operator_user_arn=CALLER,
        until_epoch=10_000,
        wall_clock=lambda: 100.0,
        monotonic=lambda: 1.0,
        **kwargs,
    )


def test_context_hash_is_stable_when_only_new_candidate_client_is_excluded():
    clients = _ContextClients()
    sdk = _bindings(clients)
    before = sdk.capture_context()
    clients.client_ids.append("newclient789")
    after = sdk.capture_context(exclude_client_id="newclient789")
    assert before["verified"] is after["verified"] is True
    assert before["context_sha256"] == after["context_sha256"]
    assert before["owner_pool_id"] == POOL
    assert before["api_id"] == API


def test_context_fails_closed_on_owner_mfa_drift():
    clients = _ContextClients()
    clients.mfa_enabled = False
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).capture_context()
    assert [method for method, _ in clients.services["cognito"].calls][-1] == "get_user_pool_mfa_config"
    assert not clients.services["apigatewayv2"].calls


def test_protected_existing_client_drift_changes_context_fingerprint():
    clients = _ContextClients()
    first = _bindings(clients).capture_context()
    clients.protected_scope = ["openid", "profile"]
    changed = _bindings(clients).capture_context()
    assert first["context_sha256"] != changed["context_sha256"]


def test_wrong_sts_account_stops_before_resource_reads():
    clients = _ContextClients()
    clients.services["sts"] = _Service(lambda method, kw: _ok(Account="999999999999", Arn=CALLER))
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).capture_context()
    assert len(clients.services["sts"].calls) == 1
    assert not clients.services["cloudformation"].calls


def test_real_sdk_ordered_template_mappings_are_accepted_canonically():
    clients = _ContextClients()
    clients.template_body = OrderedDict([
        ("Resources", OrderedDict([
            ("Example", OrderedDict([("Type", "AWS::Test::Resource")]))
        ]))
    ])
    result = _bindings(clients).capture_context()
    assert result["verified"] is True
    assert len(clients.services["cloudformation"].calls) == 6


def test_malformed_template_body_fails_before_cognito_or_api_reads():
    clients = _ContextClients()
    clients.template_body = ["not", "a", "template"]
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).capture_context()
    assert len(clients.services["cloudformation"].calls) == 3
    assert not clients.services["cognito"].calls
    assert not clients.services["apigatewayv2"].calls


def test_client_pagination_is_rejected_without_following_token():
    clients = _ContextClients()
    original = clients.services["cognito"].handler

    def with_token(method, kw):
        result = original(method, kw)
        if method == "list_user_pool_clients":
            result["NextToken"] = "next-page"
        return result

    clients.services["cognito"].handler = with_token
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).capture_context()
    assert [method for method, _ in clients.services["cognito"].calls][-1] == "list_user_pool_clients"


def test_stack_resource_pagination_is_rejected_without_getting_template():
    clients = _ContextClients()
    original = clients.services["cloudformation"].handler

    def with_token(method, kw):
        result = original(method, kw)
        if method == "list_stack_resources":
            result["NextToken"] = "next-page"
        return result

    clients.services["cloudformation"].handler = with_token
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).capture_context()
    assert [method for method, _ in clients.services["cloudformation"].calls] == [
        "describe_stacks", "list_stack_resources",
    ]


def test_shared_sdk_call_ceiling_stops_before_the_next_request():
    clients = _ContextClients()
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients, max_calls=1).capture_context()
    assert len(clients.services["sts"].calls) == 1
    assert not clients.services["cloudformation"].calls


def test_context_deadline_is_rechecked_after_sdk_call():
    clients = _ContextClients()
    current = [100.0]

    def identity(method, kwargs):
        current[0] = 996.0
        return _ok(Account=ACCOUNT, Arn=CALLER)

    clients.services["sts"] = _Service(identity)
    sdk = OwnerOAuthSdkBindings(
        clients.services, account_id=ACCOUNT, operator_user_arn=CALLER,
        until_epoch=1000, wall_clock=lambda: current[0], monotonic=lambda: 1.0,
    )
    with pytest.raises(OwnerOAuthSdkError):
        sdk.capture_context()
    assert len(clients.services["sts"].calls) == 1
    assert not clients.services["cloudformation"].calls


def test_candidate_readback_uses_exact_sdk_requests_and_refuses_secret_client():
    template = build_dev_owner_oauth_template(
        account_id=ACCOUNT,
        api_id=API,
        owner_pool_id=POOL,
        callback_url=CALLBACK,
    )
    client_id = "newclient789"
    branding_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    physical = {
        "McpResourceServer": RESOURCE_URI,
        "McpUserPoolClient": client_id,
        "McpManagedLoginBranding": f"{POOL}|{branding_uuid}",
    }
    clients = _ContextClients()
    client_props = template["Resources"]["McpUserPoolClient"]["Properties"]
    client_reply = {
        key: value for key, value in client_props.items() if key != "GenerateSecret"
    }
    client_reply.update({
        "ClientId": client_id,
        "CreationDate": datetime.fromtimestamp(120, timezone.utc),
    })
    clients.services["cognito"] = _Service(lambda method, kw: {
        "describe_user_pool_client": _ok(UserPoolClient=client_reply),
        "describe_resource_server": _ok(ResourceServer=template["Resources"]["McpResourceServer"]["Properties"]),
        "describe_managed_login_branding_by_client": _ok(ManagedLoginBranding={
            "ManagedLoginBrandingId": branding_uuid,
            "UserPoolId": POOL,
            "UseCognitoProvidedValues": True,
        }),
    }[method])
    sdk = _bindings(clients)
    receipt = sdk.validate_candidate(
        f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/x/33333333-3333-4333-8333-333333333333",
        template, "run-fixture", 100, 200, physical,
    )
    assert receipt["verified"] is True
    assert receipt["client_id"] == client_id
    calls = clients.services["cognito"].calls
    assert calls == [
        ("describe_user_pool_client", {"UserPoolId": POOL, "ClientId": client_id}),
        ("describe_resource_server", {"UserPoolId": POOL, "Identifier": RESOURCE_URI}),
        ("describe_managed_login_branding_by_client", {
            "UserPoolId": POOL, "ClientId": client_id, "ReturnMergedResources": False,
        }),
    ]

    physical["McpManagedLoginBranding"] = "eu-west-1_otherpool|aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).validate_candidate(
            f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/x/33333333-3333-4333-8333-333333333333",
            template, "run-fixture", 100, 200, physical,
        )
    physical["McpManagedLoginBranding"] = f"{POOL}|aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    client_reply["ClientSecret"] = "must-not-be-accepted"
    with pytest.raises(OwnerOAuthSdkError):
        _bindings(clients).validate_candidate(
            f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/x/33333333-3333-4333-8333-333333333333",
            template, "run-fixture", 100, 200, physical,
        )


def test_botocore_model_confirms_real_cognito_operation_shapes():
    botocore_session = pytest.importorskip("botocore.session")
    model = botocore_session.get_session().get_service_model("cognito-idp")
    operation = model.operation_model("DescribeManagedLoginBrandingByClient")
    assert set(operation.input_shape.members) == {"UserPoolId", "ClientId", "ReturnMergedResources"}
    assert set(operation.input_shape.required_members) == {"UserPoolId", "ClientId"}
    assert set(operation.output_shape.members) == {"ManagedLoginBranding"}
    assert "GetUserPoolMfaConfig" in model.operation_names


def test_candidate_readback_runs_against_real_botocore_stubber_shapes():
    botocore = pytest.importorskip("botocore.session")
    Stubber = pytest.importorskip("botocore.stub").Stubber
    template = build_dev_owner_oauth_template(
        account_id=ACCOUNT, api_id=API, owner_pool_id=POOL, callback_url=CALLBACK,
    )
    client_id = "newclient789"
    branding_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    branding_id = f"{POOL}|{branding_uuid}"
    physical = {
        "McpResourceServer": RESOURCE_URI,
        "McpUserPoolClient": client_id,
        "McpManagedLoginBranding": branding_id,
    }
    client_properties = template["Resources"]["McpUserPoolClient"]["Properties"]
    client_response = {
        key: value for key, value in client_properties.items() if key != "GenerateSecret"
    }
    client_response.update({
        "ClientId": client_id,
        "CreationDate": datetime.fromtimestamp(120, timezone.utc),
    })
    server_response = template["Resources"]["McpResourceServer"]["Properties"]
    cognito = botocore.get_session().create_client(
        "cognito-idp", region_name="eu-west-1",
        aws_access_key_id="offline-fixture", aws_secret_access_key="offline-fixture",
    )
    stubber = Stubber(cognito)
    stubber.add_response("describe_user_pool_client", {
        "UserPoolClient": client_response, "ResponseMetadata": {"HTTPStatusCode": 200},
    }, {
        "UserPoolId": POOL, "ClientId": client_id,
    })
    stubber.add_response("describe_resource_server", {
        "ResourceServer": server_response, "ResponseMetadata": {"HTTPStatusCode": 200},
    }, {
        "UserPoolId": POOL, "Identifier": RESOURCE_URI,
    })
    stubber.add_response("describe_managed_login_branding_by_client", {
        "ManagedLoginBranding": {
            "ManagedLoginBrandingId": branding_uuid,
            "UserPoolId": POOL,
            "UseCognitoProvidedValues": True,
        },
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }, {
        "UserPoolId": POOL, "ClientId": client_id, "ReturnMergedResources": False,
    })
    sdk = OwnerOAuthSdkBindings(
        {"cognito": cognito}, account_id=ACCOUNT, operator_user_arn=CALLER,
        until_epoch=10_000, wall_clock=lambda: 100.0, monotonic=lambda: 1.0,
    )
    with stubber:
        receipt = sdk.validate_candidate(
            f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/x/33333333-3333-4333-8333-333333333333",
            template, "run-fixture", 100, 200, physical,
        )
        stubber.assert_no_pending_responses()
    assert receipt["verified"] is True
    assert receipt["client_id"] == client_id
