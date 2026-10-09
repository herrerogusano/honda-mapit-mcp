"""Bounded readonly SDK bindings for the isolated DEV owner OAuth bootstrap.

No SDK construction, credentials, files, user enumeration or mutations occur
on import. Context hashes cover security metadata, not tokens or user records.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import math
import re
import time

from scripts.build_aws_dev_owner_oauth import REGION
from scripts.aws_dev_oauth_setup_readback import _branding_id_matches

IDENTITY_STACK = "honda-mapit-mcp-identity"
APP_STACK = "honda-mapit-mcp-dev-retained"
DOMAIN = "hm-honda-mapit-mcp-identity"
_POOL_SECURITY = (
    "Id", "Name", "Arn", "Policies", "DeletionProtection", "LambdaConfig", "Status",
    "SchemaAttributes", "AutoVerifiedAttributes", "AliasAttributes", "UsernameAttributes",
    "VerificationMessageTemplate", "UserAttributeUpdateSettings", "MfaConfiguration",
    "DeviceConfiguration", "EmailConfiguration", "SmsConfiguration", "Domain", "CustomDomain",
    "AdminCreateUserConfig", "UserPoolAddOns", "UsernameConfiguration", "UserPoolTags",
    "AccountRecoverySetting", "UserPoolTier", "KeyConfiguration", "IssuerConfiguration",
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False,
        default=lambda item: item.isoformat() if isinstance(item, datetime) else (_ for _ in ()).throw(ValueError())).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


class OwnerOAuthSdkError(ValueError):
    def __init__(self):
        super().__init__("owner_oauth_readback_invalid")


class OwnerOAuthSdkBindings:
    """One bounded operator phase; use the same explicit client map for STS.

    Client construction/source/protection checks belong to the runner. The
    shared counter includes context, coordinator and candidate reads/writes
    when the runner routes its client calls through ``call``.
    """
    def __init__(self, clients, *, account_id, operator_user_arn, until_epoch,
                 wall_clock=time.time, monotonic=time.monotonic, max_calls=64):
        if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or type(operator_user_arn) is not str
                or re.fullmatch(rf"arn:aws:iam::{account_id}:user/[A-Za-z0-9+=,.@_/-]+", operator_user_arn) is None
                or type(until_epoch) is not int or type(max_calls) is not int or not 1 <= max_calls <= 96):
            raise OwnerOAuthSdkError()
        self.clients, self.account, self.caller = clients, account_id, operator_user_arn
        self.until, self.wall, self.mono, self.ceiling = until_epoch, wall_clock, monotonic, max_calls
        self.calls = 0
        self._last_wall = self.wall()
        self._last_mono = self.mono()
        self._mono_end = self._last_mono + 90

    def _budget(self):
        wall, mono = self.wall(), self.mono()
        if (type(wall) not in (int, float) or type(mono) not in (int, float)
                or not math.isfinite(wall) or not math.isfinite(mono)
                or wall < self._last_wall or mono < self._last_mono
                or wall + 5 >= self.until or mono + 5 >= self._mono_end):
            raise OwnerOAuthSdkError()
        self._last_wall, self._last_mono = wall, mono

    def call(self, service, method, **kwargs):
        self._budget()
        if self.calls >= self.ceiling:
            raise OwnerOAuthSdkError()
        self.calls += 1
        reply = getattr(self.clients[service], method)(**kwargs)
        self._budget()
        if (type(reply) is not dict or type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or reply["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise OwnerOAuthSdkError()
        return reply

    def proxy(self, service):
        owner = self
        class Proxy:
            def __getattr__(self, method):
                return lambda **kwargs: owner.call(service, method, **kwargs)
        return Proxy()

    def _stack(self, name, count):
        reply = self.call("cloudformation", "describe_stacks", StackName=name)
        rows = reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1:
            raise OwnerOAuthSdkError()
        stack = rows[0]
        arn = stack.get("StackId")
        if (stack.get("StackName") != name or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or type(arn) is not str
                or re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{self.account}:stack/{name}/[0-9a-f-]{{36}}", arn) is None
                or stack.get("EnableTerminationProtection") is not True):
            raise OwnerOAuthSdkError()
        inventory = self.call("cloudformation", "list_stack_resources", StackName=arn)
        resources = inventory.get("StackResourceSummaries")
        if inventory.get("NextToken") or type(resources) is not list or len(resources) != count:
            raise OwnerOAuthSdkError()
        by_name = {}
        for row in resources:
            logical = row.get("LogicalResourceId")
            if (type(logical) is not str or logical in by_name
                    or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                    or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
                raise OwnerOAuthSdkError()
            by_name[logical] = {key: row.get(key) for key in ("PhysicalResourceId", "ResourceType")}
        template = self.call("cloudformation", "get_template", StackName=arn, TemplateStage="Original").get("TemplateBody")
        if type(template) is str:
            template = json.loads(template)
        if not isinstance(template, Mapping):
            raise OwnerOAuthSdkError()
        return by_name, {"stack_id": arn, "resources": by_name, "template_sha256": _digest(template)}

    def capture_context(self, exclude_client_id=None):
        identity = self.call("sts", "get_caller_identity")
        if identity.get("Account") != self.account or identity.get("Arn") != self.caller:
            raise OwnerOAuthSdkError()
        owner, owner_stack = self._stack(IDENTITY_STACK, 4)
        app, app_stack = self._stack(APP_STACK, 19)
        if set(owner) != {"McpUserPool", "McpUserPoolDomain", "McpUserPoolClient", "McpManagedLoginBranding"}:
            raise OwnerOAuthSdkError()
        pool = owner["McpUserPool"]["PhysicalResourceId"]
        api = app["McpApi"]["PhysicalResourceId"]
        handler = app["McpHandler"]["PhysicalResourceId"]
        if (re.fullmatch(r"eu-west-1_[A-Za-z0-9]{9,45}", pool) is None
                or re.fullmatch(r"[a-z0-9]{10}", api) is None
                or handler != "honda-mapit-mcp-dev-retained-handler"):
            raise OwnerOAuthSdkError()
        user_pool = self.call("cognito", "describe_user_pool", UserPoolId=pool).get("UserPool", {})
        if (user_pool.get("Id") != pool or user_pool.get("Arn") != f"arn:aws:cognito-idp:{REGION}:{self.account}:userpool/{pool}"
                or user_pool.get("MfaConfiguration") != "ON"
                or user_pool.get("DeletionProtection") != "ACTIVE"
                or user_pool.get("AdminCreateUserConfig", {}).get("AllowAdminCreateUserOnly") is not True):
            raise OwnerOAuthSdkError()
        mfa = self.call("cognito", "get_user_pool_mfa_config", UserPoolId=pool)
        mfa = {key: value for key, value in mfa.items() if key != "ResponseMetadata"}
        if mfa.get("MfaConfiguration") != "ON" or mfa.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is not True:
            raise OwnerOAuthSdkError()
        domain = self.call("cognito", "describe_user_pool_domain", Domain=DOMAIN).get("DomainDescription", {})
        if (domain.get("UserPoolId") != pool or domain.get("AWSAccountId") != self.account
                or domain.get("Status") != "ACTIVE" or domain.get("ManagedLoginVersion") != 2):
            raise OwnerOAuthSdkError()
        clients = self.call("cognito", "list_user_pool_clients", UserPoolId=pool, MaxResults=60)
        rows = clients.get("UserPoolClients")
        if clients.get("NextToken") or type(rows) is not list or not 1 <= len(rows) <= 9:
            raise OwnerOAuthSdkError()
        ids = [row.get("ClientId") for row in rows]
        if (any(type(value) is not str or re.fullmatch(r"[A-Za-z0-9]{1,128}", value) is None for value in ids)
                or len(ids) != len(set(ids)) or owner["McpUserPoolClient"]["PhysicalResourceId"] not in ids
                or (exclude_client_id is not None and exclude_client_id not in ids)):
            raise OwnerOAuthSdkError()
        protected = {}
        for client_id in sorted(ids):
            if client_id == exclude_client_id:
                continue
            client = self.call("cognito", "describe_user_pool_client", UserPoolId=pool, ClientId=client_id).get("UserPoolClient", {})
            if client.get("ClientId") != client_id or client.get("UserPoolId") != pool or "ClientSecret" in client:
                raise OwnerOAuthSdkError()
            protected[client_id] = client
        api_state = self.call("apigatewayv2", "get_api", ApiId=api)
        reserve = self.call("lambda", "get_function_concurrency", FunctionName=handler)
        function = self.call("lambda", "get_function_configuration", FunctionName=handler)
        if (api_state.get("ApiId") != api or api_state.get("DisableExecuteApiEndpoint") is not True
                or reserve.get("ReservedConcurrentExecutions") != 0
                or function.get("FunctionName") != handler or function.get("State") != "Active"
                or function.get("LastUpdateStatus") != "Successful"):
            raise OwnerOAuthSdkError()
        # Never hash or retain runtime environment variables: no session/key
        # material is needed to prove this unchanged code/config boundary.
        function_projection = {key: function.get(key) for key in (
            "FunctionArn", "CodeSha256", "Role", "Handler", "Runtime", "Architectures", "Timeout", "MemorySize", "RevisionId")}
        projection = {"identity_stack": owner_stack, "app_stack": app_stack,
            "pool": {key: user_pool[key] for key in _POOL_SECURITY if key in user_pool},
            "mfa": mfa, "domain": domain, "protected_clients": protected,
            "api": {key: value for key, value in api_state.items() if key != "ResponseMetadata"},
            "function": function_projection, "reserved": 0}
        return {"verified": True, "account_id": self.account, "owner_pool_id": pool, "api_id": api,
            "context_sha256": _digest(projection)}

    def validate_candidate(self, stack_id, template, run_id, start, end, physical_ids):
        ids = physical_ids
        client_id = ids["McpUserPoolClient"]
        properties = template["Resources"]["McpUserPoolClient"]["Properties"]
        pool = properties["UserPoolId"]
        client = self.call("cognito", "describe_user_pool_client", UserPoolId=pool, ClientId=client_id).get("UserPoolClient", {})
        expected = {key: value for key, value in properties.items() if key != "GenerateSecret"}
        expected["ClientId"] = client_id
        if "ClientSecret" in client or any(client.get(key) != value for key, value in expected.items()):
            raise OwnerOAuthSdkError()
        created = client.get("CreationDate")
        if not isinstance(created, datetime) or created.tzinfo is None or not start <= created.timestamp() < end:
            raise OwnerOAuthSdkError()
        server_expected = template["Resources"]["McpResourceServer"]["Properties"]
        server = self.call("cognito", "describe_resource_server", UserPoolId=pool, Identifier=server_expected["Identifier"]).get("ResourceServer", {})
        if any(server.get(key) != value for key, value in server_expected.items()):
            raise OwnerOAuthSdkError()
        branding = self.call("cognito", "describe_managed_login_branding_by_client", UserPoolId=pool,
            ClientId=client_id, ReturnMergedResources=False).get("ManagedLoginBranding", {})
        if (branding.get("UseCognitoProvidedValues") is not True
                or branding.get("UserPoolId") != pool
                or not _branding_id_matches(ids["McpManagedLoginBranding"], pool,
                                            branding.get("ManagedLoginBrandingId"))):
            raise OwnerOAuthSdkError()
        return {"verified": True, "client_id": client_id,
            "readback_sha256": _digest({"client": client, "server": server, "branding_id": branding["ManagedLoginBrandingId"]})}
