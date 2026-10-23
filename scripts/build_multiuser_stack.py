"""Pure CloudFormation factories for the invitation-only multiuser stacks.

Contract: docs/multiuser-production.md. These functions perform no I/O and
embed no private value: every deployment-specific value (artifact key, login
domain prefix, Codex loopback callback, MAPIT public configuration, privacy
contact, budget email) is a CloudFormation parameter supplied by
``scripts/deploy_multiuser.py`` from a private config file.

Dependency cycle and its resolution
-----------------------------------
``UserPool.LambdaConfig`` references ``IdentityFunction.Arn`` (migration and
pre-token-generation triggers). The app clients reference ``UserPool``. So the
identity function's environment cannot reference the client ids
(``IdentityFunction -> Client -> UserPool -> IdentityFunction``).

Resolution: the stack writes one public, non-secret SSM *String* parameter
``/honda-mapit-mcp/{env}/multiuser/public-config`` whose value is the JSON
object ``{"resource_url": str, "claude_client_id": str, "codex_client_id":
str, "codex_callback_port": int}``. Nothing references that parameter
resource, so it may depend on the clients. The identity function receives
only its *name* in ``MULTIUSER_PUBLIC_CONFIG_PARAMETER`` and reads it lazily
(``ssm:GetParameter`` without decryption, exact ARN only) when it renders the
connection instructions. The identity function therefore has no
``MULTIUSER_CLAUDE_CLIENT_ID``/``MULTIUSER_CODEX_CLIENT_ID`` variables.

``MULTIUSER_RESOURCE_URL`` is *not* cyclic: it only references ``HttpApi``
(an ``AWS::ApiGatewayV2::Api`` with no dependencies); the authorizer, not the
API, references the pool. It stays an environment variable for both
functions (and is duplicated in the public-config JSON for convenience).

The MCP function is not referenced by the pool, so it receives the client ids
directly (``MULTIUSER_CLIENT_IDS``). ``tests/test_build_multiuser_stack.py``
checks the whole template for reference cycles.
"""

from __future__ import annotations

import copy
from typing import Any

from mapit.multiuser_common import (
    CLAUDE_CALLBACK_URL, REGION, artifacts_stack_name, stack_name, table_name,
    users_parameter_prefix, validate_environment,
)

PROJECT = "honda-mapit-mcp"
METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
RUNTIME = "python3.13"
MCP_HANDLER = "mapit.multiuser_entrypoint.handler"
IDENTITY_HANDLER = "mapit.multiuser_identity.handler"
LOG_RETENTION_DAYS = 14
BUDGET_USD = 5
# Claude may redirect through either first-party domain.
CLAUDE_CALLBACK_URLS = (CLAUDE_CALLBACK_URL, "https://claude.com/api/mcp/auth_callback")
CODEX_CALLBACK_PATTERN = r"^http://(localhost|127\.0\.0\.1):[1-9][0-9]{0,4}/[A-Za-z0-9._~/-]{0,200}$"
_RESOURCE_URL = {"Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/mcp"}
_API_BASE_URL = {"Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com"}
_SCOPE = {"Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/mcp/use"}
_ISSUER = {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"}


def artifacts_export_name(env: str) -> str:
    return f"{artifacts_stack_name(env)}-bucket"


def public_config_parameter_name(env: str) -> str:
    return f"/{PROJECT}/{validate_environment(env)}/multiuser/public-config"


def mcp_function_name(env: str) -> str:
    return f"{PROJECT}-{validate_environment(env)}-mcp"


def identity_function_name(env: str) -> str:
    return f"{PROJECT}-{validate_environment(env)}-identity"


def _tags(env: str) -> list[dict[str, str]]:
    return [{"Key": "Project", "Value": PROJECT}, {"Key": "Environment", "Value": env}]


def _condition(name: str) -> dict[str, Any]:
    return {"Fn::And": [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, name]},
    ]}


def build_artifacts_template(env: str) -> dict[str, Any]:
    """Private versioned SSE-S3 bucket for content-addressed Lambda ZIPs."""
    env = validate_environment(env)
    resources = {
        "ArtifactBucket": {
            "Type": "AWS::S3::Bucket",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True, "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
                },
                "BucketEncryption": {"ServerSideEncryptionConfiguration": [{
                    "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                }]},
                "VersioningConfiguration": {"Status": "Enabled"},
                "OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]},
                "Tags": _tags(env),
            },
        },
        "ArtifactBucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Bucket": {"Ref": "ArtifactBucket"},
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        {"Fn::GetAtt": ["ArtifactBucket", "Arn"]},
                        {"Fn::Sub": "${ArtifactBucket.Arn}/*"},
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }]},
            },
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Private Lambda artifact bucket for the {env} invitation-only multiuser MCP.",
        "Conditions": {"SupportedDeployment": _condition(artifacts_stack_name(env))},
        "Resources": resources,
        "Outputs": {
            "BucketName": {
                "Condition": "SupportedDeployment",
                "Value": {"Ref": "ArtifactBucket"},
                "Export": {"Name": artifacts_export_name(env)},
            },
        },
    }


def _parameters(env: str) -> dict[str, Any]:
    params: dict[str, Any] = {
        "ArtifactKey": {
            "Type": "String",
            "AllowedPattern": "^runtime/[0-9a-f]{64}\\.zip$",
            "Description": "Content-addressed Lambda ZIP key in the artifacts bucket.",
        },
        "DomainPrefix": {
            "Type": "String",
            "AllowedPattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
            "Description": "Cognito managed-login domain prefix (private config).",
        },
        "CodexCallbackUrl": {
            "Type": "String",
            "AllowedPattern": CODEX_CALLBACK_PATTERN,
            "Description": "Exact Codex loopback OAuth callback URL (private config).",
        },
        "CodexCallbackPort": {
            "Type": "String",
            "AllowedPattern": "^[1-9][0-9]{0,4}$",
            "Description": "Port of CodexCallbackUrl, shown in connection instructions.",
        },
        "MapitConfigJson": {
            "Type": "String",
            "NoEcho": True,
            "MinLength": 2,
            "MaxLength": 2048,
            "Description": "Public MAPIT identifiers as JSON (discovery disabled).",
        },
        "PrivacyContact": {
            "Type": "String",
            "NoEcho": True,
            "MinLength": 3,
            "MaxLength": 254,
            "Description": "Controller contact shown on the privacy page.",
        },
        "Geography": {
            "Type": "String",
            "AllowedValues": ["0", "1"],
            "Default": "0",
            "Description": "Enable the opt-in geographic tools.",
        },
    }
    if env == "prod":
        params["BudgetEmail"] = {
            "Type": "String",
            "NoEcho": True,
            "AllowedPattern": "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$",
            "Description": "Recipient of the monthly budget notifications.",
        }
    return params


def _log_group(name: str, env: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Logs::LogGroup",
        "Condition": "SupportedDeployment",
        "DeletionPolicy": "Delete",
        "UpdateReplacePolicy": "Delete",
        "Properties": {
            "LogGroupName": f"/aws/lambda/{name}",
            "RetentionInDays": LOG_RETENTION_DAYS,
            "Tags": _tags(env),
        },
    }


def _log_statement(function_name: str) -> dict[str, Any]:
    return {
        "Sid": "OwnLogGroupOnly",
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{function_name}:*"},
    }


def _kms_via_ssm(action: str) -> dict[str, Any]:
    # Only the AWS-managed alias/aws/ssm key, and only when SSM calls KMS.
    return {
        "Sid": "SsmDefaultKeyViaSsmOnly",
        "Effect": "Allow",
        "Action": action,
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/*"},
        "Condition": {
            "StringEquals": {"kms:ViaService": f"ssm.{REGION}.amazonaws.com"},
            "ForAnyValue:StringEquals": {"kms:ResourceAliases": "alias/aws/ssm"},
        },
    }


def _users_parameters(env: str) -> dict[str, Any]:
    prefix = users_parameter_prefix(env)  # "/honda-mapit-mcp/{env}/users/"
    return {"Fn::Sub": f"arn:${{AWS::Partition}}:ssm:${{AWS::Region}}:${{AWS::AccountId}}:parameter{prefix}*"}


def _role(env: str, statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "Type": "AWS::IAM::Role",
        "Condition": "SupportedDeployment",
        "Properties": {
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }]},
            "Policies": [{
                "PolicyName": "least-privilege",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": statements},
            }],
            "Tags": _tags(env),
        },
    }


def _client(name: str, callbacks: list[Any], env: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Cognito::UserPoolClient",
        "Condition": "SupportedDeployment",
        "DependsOn": ["ResourceServer", "UserPoolDomain"],
        "Properties": {
            "ClientName": f"{PROJECT}-{env}-{name}",
            "UserPoolId": {"Ref": "UserPool"},
            "GenerateSecret": False,
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthScopes": ["openid", _SCOPE],
            "CallbackURLs": callbacks,
            "SupportedIdentityProviders": ["COGNITO"],
            # ALLOW_USER_PASSWORD_AUTH is kept only until DEV verifies whether the
            # user-migration trigger needs it under managed login; remove it if not.
            "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
            "AccessTokenValidity": 60,
            "IdTokenValidity": 60,
            "RefreshTokenValidity": 30,
            "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
            "EnableTokenRevocation": True,
            "PreventUserExistenceErrors": "ENABLED",
            "ReadAttributes": ["email", "email_verified", "custom:tenant_id"],
            # Never "email" (a user could rename to another invited address) or
            # custom:tenant_id. Omitting WriteAttributes makes every standard
            # attribute writable (CloudFormation docs), and the docs do not define an
            # empty list, so grant one harmless standard attribute explicitly.
            "WriteAttributes": ["locale"],
        },
    }


def _branding(client: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Cognito::ManagedLoginBranding",
        "Condition": "SupportedDeployment",
        "DependsOn": ["UserPoolDomain"],
        "Properties": {
            "UserPoolId": {"Ref": "UserPool"},
            "ClientId": {"Ref": client},
            "UseCognitoProvidedValues": True,
        },
    }


def _integration(function: str, timeout_ms: int) -> dict[str, Any]:
    return {
        "Type": "AWS::ApiGatewayV2::Integration",
        "Condition": "SupportedDeployment",
        "Properties": {
            "ApiId": {"Ref": "HttpApi"},
            "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST",
            "PayloadFormatVersion": "2.0",
            "TimeoutInMillis": timeout_ms,
            "IntegrationUri": {"Fn::GetAtt": [function, "Arn"]},
        },
    }


def _route(route_key: str, integration: str, *, jwt: bool = False) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "ApiId": {"Ref": "HttpApi"},
        "RouteKey": route_key,
        "Target": {"Fn::Join": ["/", ["integrations", {"Ref": integration}]]},
    }
    if jwt:
        properties.update(AuthorizationType="JWT", AuthorizerId={"Ref": "JwtAuthorizer"},
                          AuthorizationScopes=[_SCOPE])
    else:
        properties["AuthorizationType"] = "NONE"
    return {"Type": "AWS::ApiGatewayV2::Route", "Condition": "SupportedDeployment", "Properties": properties}


def _api_permission(function: str, source_suffix: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Lambda::Permission",
        "Condition": "SupportedDeployment",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": function},
            "Principal": "apigateway.amazonaws.com",
            "SourceAccount": {"Ref": "AWS::AccountId"},
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${HttpApi}/" + source_suffix},
        },
    }


def _function(env: str, name: str, handler: str, timeout: int, role: str, log_group: str,
              variables: dict[str, Any]) -> dict[str, Any]:
    return {
        "Type": "AWS::Lambda::Function",
        "Condition": "SupportedDeployment",
        "DependsOn": [log_group],
        "Properties": {
            "FunctionName": name,
            "Runtime": RUNTIME,
            "Architectures": ["arm64"],
            "Handler": handler,
            "MemorySize": 512,
            "Timeout": timeout,
            "Role": {"Fn::GetAtt": [role, "Arn"]},
            "Code": {
                "S3Bucket": {"Fn::ImportValue": artifacts_export_name(env)},
                "S3Key": {"Ref": "ArtifactKey"},
            },
            "Environment": {"Variables": variables},
            "Tags": _tags(env),
        },
    }


def build_multiuser_template(env: str) -> dict[str, Any]:
    """Return the main invitation-only multiuser stack template for ``env``."""
    env = validate_environment(env)
    prod = env == "prod"
    retain = "Retain" if prod else "Delete"
    mcp_name = mcp_function_name(env)
    identity_name = identity_function_name(env)
    public_config = public_config_parameter_name(env)

    resources: dict[str, Any] = {
        "UserPool": {
            "Type": "AWS::Cognito::UserPool",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": retain,
            "UpdateReplacePolicy": retain,
            "Properties": {
                "UserPoolName": f"{PROJECT}-{env}-users",
                "UserPoolTier": "ESSENTIALS",
                "UsernameAttributes": ["email"],
                "UsernameConfiguration": {"CaseSensitive": False},
                "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
                # Migrated MAPIT passwords must not be rejected by Cognito's default
                # policy; MAPIT, not this pool, owns password strength.
                "Policies": {"PasswordPolicy": {
                    "MinimumLength": 6,
                    "RequireUppercase": False,
                    "RequireLowercase": False,
                    "RequireNumbers": False,
                    "RequireSymbols": False,
                    "TemporaryPasswordValidityDays": 1,
                }},
                "MfaConfiguration": "OPTIONAL",
                "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
                "Schema": [{
                    "Name": "tenant_id",
                    "AttributeDataType": "String",
                    "Mutable": False,
                    "Required": False,
                    "StringAttributeConstraints": {"MinLength": "32", "MaxLength": "32"},
                }],
                "AccountRecoverySetting": {"RecoveryMechanisms": [{"Name": "admin_only", "Priority": 1}]},
                "DeletionProtection": "ACTIVE" if prod else "INACTIVE",
                "LambdaConfig": {
                    "UserMigration": {"Fn::GetAtt": ["IdentityFunction", "Arn"]},
                    "PreTokenGenerationConfig": {
                        "LambdaArn": {"Fn::GetAtt": ["IdentityFunction", "Arn"]},
                        "LambdaVersion": "V2_0",
                    },
                },
                "UserPoolTags": {"Project": PROJECT, "Environment": env},
            },
        },
        "UserPoolDomain": {
            "Type": "AWS::Cognito::UserPoolDomain",
            "Condition": "SupportedDeployment",
            "Properties": {
                "UserPoolId": {"Ref": "UserPool"},
                "Domain": {"Ref": "DomainPrefix"},
                "ManagedLoginVersion": 2,
            },
        },
        "ResourceServer": {
            "Type": "AWS::Cognito::UserPoolResourceServer",
            "Condition": "SupportedDeployment",
            "Properties": {
                "UserPoolId": {"Ref": "UserPool"},
                "Identifier": _RESOURCE_URL,
                "Name": f"{PROJECT}-{env}-mcp",
                "Scopes": [{"ScopeName": "use", "ScopeDescription": "Use the MCP server."}],
            },
        },
        "ClaudeClient": _client("claude", list(CLAUDE_CALLBACK_URLS), env),
        "CodexClient": _client("codex", [{"Ref": "CodexCallbackUrl"}], env),
        "ClaudeManagedLoginBranding": _branding("ClaudeClient"),
        "CodexManagedLoginBranding": _branding("CodexClient"),
        "IdentityCognitoInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Action": "lambda:InvokeFunction",
                "FunctionName": {"Ref": "IdentityFunction"},
                "Principal": "cognito-idp.amazonaws.com",
                "SourceAccount": {"Ref": "AWS::AccountId"},
                "SourceArn": {"Fn::GetAtt": ["UserPool", "Arn"]},
            },
        },
        "InvitationsTable": {
            "Type": "AWS::DynamoDB::Table",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": retain,
            "UpdateReplacePolicy": retain,
            "Properties": {
                "TableName": table_name(env),
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "email", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "email", "KeyType": "HASH"}],
                "DeletionProtectionEnabled": prod,
                "Tags": _tags(env),
            },
        },
        "PublicConfigParameter": {
            "Type": "AWS::SSM::Parameter",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Name": public_config,
                "Type": "String",
                "Tier": "Standard",
                "Description": "Public connection settings for the identity Lambda (no secrets).",
                "Value": {"Fn::Sub": (
                    '{"resource_url":"https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/mcp",'
                    '"claude_client_id":"${ClaudeClient}","codex_client_id":"${CodexClient}",'
                    '"codex_callback_port":${CodexCallbackPort}}'
                )},
                "Tags": {"Project": PROJECT, "Environment": env},
            },
        },
        "HttpApi": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Name": f"{PROJECT}-{env}-multiuser",
                "ProtocolType": "HTTP",
                "Tags": {"Project": PROJECT, "Environment": env},
            },
        },
        "HttpApiStage": {
            "Type": "AWS::ApiGatewayV2::Stage",
            "Condition": "SupportedDeployment",
            "Properties": {
                "ApiId": {"Ref": "HttpApi"},
                "StageName": "$default",
                "AutoDeploy": True,
                "DefaultRouteSettings": {
                    "ThrottlingRateLimit": 10,
                    "ThrottlingBurstLimit": 20,
                    "DetailedMetricsEnabled": False,
                },
            },
        },
        "JwtAuthorizer": {
            "Type": "AWS::ApiGatewayV2::Authorizer",
            "Condition": "SupportedDeployment",
            "Properties": {
                "ApiId": {"Ref": "HttpApi"},
                "Name": f"{PROJECT}-{env}-jwt",
                "AuthorizerType": "JWT",
                "IdentitySource": ["$request.header.Authorization"],
                "JwtConfiguration": {"Issuer": _ISSUER, "Audience": [_RESOURCE_URL]},
            },
        },
        "McpIntegration": _integration("McpFunction", 20000),
        "IdentityIntegration": _integration("IdentityFunction", 6000),
        "McpPostRoute": _route("POST /mcp", "McpIntegration", jwt=True),
        "McpMetadataRoute": _route(f"GET {METADATA_PATH}", "McpIntegration"),
        "InvitationGetRoute": _route("GET /invitacion", "IdentityIntegration"),
        "InvitationPostRoute": _route("POST /invitacion", "IdentityIntegration"),
        "PrivacyGetRoute": _route("GET /privacidad", "IdentityIntegration"),
        "McpPostInvokePermission": _api_permission("McpFunction", "$default/POST/mcp"),
        "McpMetadataInvokePermission": _api_permission("McpFunction", "$default/GET" + METADATA_PATH),
        "IdentityInvitationInvokePermission": _api_permission("IdentityFunction", "$default/*/invitacion"),
        "IdentityPrivacyInvokePermission": _api_permission("IdentityFunction", "$default/GET/privacidad"),
        "McpLogGroup": _log_group(mcp_name, env),
        "IdentityLogGroup": _log_group(identity_name, env),
        "IdentityRole": _role(env, [
            {"Sid": "InvitationsReadUpdate", "Effect": "Allow",
             "Action": ["dynamodb:GetItem", "dynamodb:UpdateItem"],
             "Resource": {"Fn::GetAtt": ["InvitationsTable", "Arn"]}},
            {"Sid": "WriteUserSessions", "Effect": "Allow", "Action": "ssm:PutParameter",
             "Resource": _users_parameters(env)},
            {"Sid": "ReadPublicConfig", "Effect": "Allow", "Action": "ssm:GetParameter",
             "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:ssm:${{AWS::Region}}:${{AWS::AccountId}}:parameter{public_config}"}},
            _kms_via_ssm("kms:Encrypt"),
            _log_statement(identity_name),
        ]),
        "McpRole": _role(env, [
            {"Sid": "ReadDeleteUserSessions", "Effect": "Allow",
             "Action": ["ssm:GetParameter", "ssm:DeleteParameter"],
             "Resource": _users_parameters(env)},
            _kms_via_ssm("kms:Decrypt"),
            {"Sid": "InvitationsScanUpdateDelete", "Effect": "Allow",
             "Action": ["dynamodb:Scan", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
             "Resource": {"Fn::GetAtt": ["InvitationsTable", "Arn"]}},
            {"Sid": "DeleteOwnPoolUsers", "Effect": "Allow", "Action": "cognito-idp:AdminDeleteUser",
             "Resource": {"Fn::GetAtt": ["UserPool", "Arn"]}},
            _log_statement(mcp_name),
        ]),
        "McpFunction": _function(env, mcp_name, MCP_HANDLER, 20, "McpRole", "McpLogGroup", {
            "MAPIT_MCP_ENV": env,
            "MULTIUSER_ISSUER_URL": _ISSUER,
            "MULTIUSER_RESOURCE_URL": _RESOURCE_URL,
            "MULTIUSER_CLIENT_IDS": {"Fn::Join": [",", [{"Ref": "ClaudeClient"}, {"Ref": "CodexClient"}]]},
            "MULTIUSER_USER_POOL_ID": {"Ref": "UserPool"},
            "MULTIUSER_TABLE": {"Ref": "InvitationsTable"},
            "MAPIT_CONFIG_JSON": {"Ref": "MapitConfigJson"},
            "MULTIUSER_GEOGRAPHY": {"Ref": "Geography"},
        }),
        "IdentityFunction": _function(env, identity_name, IDENTITY_HANDLER, 5, "IdentityRole", "IdentityLogGroup", {
            "MAPIT_MCP_ENV": env,
            "MULTIUSER_TABLE": {"Ref": "InvitationsTable"},
            "MAPIT_CONFIG_JSON": {"Ref": "MapitConfigJson"},
            "MULTIUSER_RESOURCE_URL": _RESOURCE_URL,
            "MULTIUSER_PUBLIC_CONFIG_PARAMETER": public_config,
            "MULTIUSER_CODEX_CALLBACK_PORT": {"Ref": "CodexCallbackPort"},
            "MULTIUSER_PRIVACY_CONTACT": {"Ref": "PrivacyContact"},
        }),
    }
    if prod:
        resources["Budget"] = {
            "Type": "AWS::Budgets::Budget",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Budget": {
                    # Account-wide on purpose: the Project cost-allocation tag is
                    # inactive, so no CostFilters; the name says so.
                    "BudgetName": f"{PROJECT}-{env}-account-wide-monthly",
                    "BudgetType": "COST",
                    "TimeUnit": "MONTHLY",
                    "BudgetLimit": {"Amount": BUDGET_USD, "Unit": "USD"},
                },
                "NotificationsWithSubscribers": [
                    {
                        "Notification": {"NotificationType": notification_type, "ComparisonOperator": "GREATER_THAN",
                                         "Threshold": threshold, "ThresholdType": "PERCENTAGE"},
                        "Subscribers": [{"SubscriptionType": "EMAIL", "Address": {"Ref": "BudgetEmail"}}],
                    }
                    for notification_type, threshold in (("ACTUAL", 80), ("FORECASTED", 100))
                ],
            },
        }

    def output(value: Any) -> dict[str, Any]:
        return {"Condition": "SupportedDeployment", "Value": copy.deepcopy(value)}

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Invitation-only multiuser Honda MAPIT MCP ({env}); see docs/multiuser-production.md.",
        "Parameters": _parameters(env),
        "Conditions": {"SupportedDeployment": _condition(stack_name(env))},
        "Resources": resources,
        "Outputs": {
            "McpUrl": output(_RESOURCE_URL),
            "ApiBaseUrl": output(_API_BASE_URL),
            "UserPoolId": output({"Ref": "UserPool"}),
            "ClaudeClientId": output({"Ref": "ClaudeClient"}),
            "CodexClientId": output({"Ref": "CodexClient"}),
            "IssuerUrl": output(_ISSUER),
            "TableName": output({"Ref": "InvitationsTable"}),
            "LoginDomain": output({"Fn::Sub": "https://${DomainPrefix}.auth.${AWS::Region}.amazoncognito.com"}),
        },
    }


__all__ = [
    "CLAUDE_CALLBACK_URLS", "CODEX_CALLBACK_PATTERN", "IDENTITY_HANDLER", "MCP_HANDLER", "artifacts_export_name",
    "build_artifacts_template", "build_multiuser_template", "identity_function_name",
    "mcp_function_name", "public_config_parameter_name",
]
