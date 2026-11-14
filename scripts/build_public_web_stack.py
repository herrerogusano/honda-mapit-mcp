"""Pure CloudFormation factory for the public web stack ``honda-mapit-mcp-{env}-web``.

Separate from the invitation-only stack (``scripts/build_multiuser_stack.py``,
whose output must not change): its own user pool, login domain, web client,
HTTP API, table, four functions, sweep schedule, alarm topic and alarms. The
same code ZIP runs here with ``MAPIT_WEB_MODE=public``. No I/O, no private
value: deployment values are parameters supplied by
``scripts/deploy_public_web.py``.

Names that cannot change without recreating the resource (and losing its
data): the pool name ``honda-mapit-mcp-{env}-web-users`` (the sweep refuses any
other), the login domain prefix, the table name and its key ``pk``.

Not created here on purpose:

* the fingerprint key ``/honda-mapit-mcp/{env}/web/fingerprint-key``: the deploy
  script creates it before the first stack creation (the pass function cannot
  create it and refuses every pass without it);
* the Turnstile secret ``/honda-mapit-mcp/{env}/web/turnstile-secret``: stored
  by hand with a command that does not echo it; the pass role may only read it.

Log-based alarms use metric filters over the fixed codes the modules write: the
pass prints one JSON line per request (``web_pass_outcome``), the sweep prints
one embedded-metric JSON line per run, and the identity function logs fixed
step codes through ``logging`` (text lines, so plain-term filters).
"""

from __future__ import annotations

import copy
from typing import Any

from mapit.multiuser_common import validate_environment
from mapit.public_pass import turnstile_secret_parameter_name
from mapit.public_sweep import METRIC_DIMENSION, METRIC_NAMESPACE, web_user_pool_name
from mapit.public_web import (
    MODE_PUBLIC, MODE_VARIABLE, fingerprint_key_parameter_name, web_function_name,
    web_session_parameter_prefix, web_stack_name, web_table_name,
)
from scripts.build_multiuser_stack import (
    IDENTITY_HANDLER, MCP_HANDLER, METADATA_PATH, PROJECT, WEB_CALLBACK_PATTERN, _api_permission, _branding,
    _client, _condition, _function, _integration, _kms_via_ssm, _log_group, _log_statement, _origin, _role, _route,
    _tags,
)

PASS_HANDLER = "mapit.public_pass.handler"
SWEEP_HANDLER = "mapit.public_sweep.handler"
DEV_CALLBACK_URL = "http://localhost:5173/"
DEV_ORIGIN = "http://localhost:5173"
DEV_TURNSTILE_HOSTNAMES = "localhost"
PROD_CALLBACK_PATTERN = WEB_CALLBACK_PATTERN.removeprefix("^$|")  # exact https URL, never empty
SWEEP_SCHEDULE = "rate(5 minutes)"
TIMEOUTS = {"identity": 5, "mcp": 20, "pass": 8, "sweep": 60}
INTEGRATION_TIMEOUT_MS = {"mcp": 20000, "identity": 6000, "pass": 9000}
DEFAULT_THROTTLE = {"ThrottlingRateLimit": 10, "ThrottlingBurstLimit": 20}
# Own, lower limits for the two anonymous routes (their functions also serve sign-ins).
ROUTE_THROTTLES = {
    "GET /estado": {"ThrottlingRateLimit": 2, "ThrottlingBurstLimit": 5},
    "POST /pase": {"ThrottlingRateLimit": 2, "ThrottlingBurstLimit": 5},
}
CORS_ALLOW_METHODS = ("GET", "POST")
CORS_ALLOW_HEADERS = ("authorization", "content-type", "mcp-protocol-version")
CORS_MAX_AGE_SECONDS = 7200
RESERVATION_PATTERN = "^$|^[1-9][0-9]{0,2}$"
EMAIL_PATTERN = "^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"
# Outcome codes of the pass that mean "Cloudflare (or its secret) is not answering".
PASS_CLOUDFLARE_CODES = (
    "turnstile_unavailable", "turnstile_http_status", "turnstile_response_too_large",
    "turnstile_response_malformed", "turnstile_failed_unexpected", "turnstile_secret_rejected",
    "turnstile_secret_missing", "turnstile_secret_read_failed", "turnstile_secret_invalid",
)
# Identity step codes that mean a fault of the service (not an expected refusal
# such as a wrong password, a lock, a missing pass or a full cap). Lambda
# ``Errors`` cannot be used for this function: Cognito refusals are raised.
IDENTITY_FAULT_CODES = (
    "config_invalid", "unexpected", "trigger_unknown", "deadline_passed", "state_unprocessed", "state_malformed",
    "state_read_no_time", "state_read_failed", "rejection_write_no_time", "rejection_write_failed",
    "pass_spend_no_time", "pass_spend_failed", "admit_no_time", "admit_failed", "session_write_no_time",
    "session_write_failed", "count_no_time", "count_failed", "cap_count_failed", "fingerprint_key_no_time",
    "fingerprint_key_read_failed", "fingerprint_key_write_failed", "fingerprint_key_invalid",
    "fingerprint_key_unavailable", "fingerprint_key_write_unconfirmed", "fingerprint_key_generation_failed",
    "mapit_failed", "mapit_malformed", "tenant_invalid",
)

_LOGICAL = {"identity": "Identity", "mcp": "Mcp", "pass": "Pass", "sweep": "Sweep"}
_RESOURCE_URL = {"Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/mcp"}
_API_BASE_URL = {"Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com"}
_ISSUER = {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"}
_TABLE_ARN = {"Fn::GetAtt": ["WebStateTable", "Arn"]}
_POOL_ARN = {"Fn::GetAtt": ["UserPool", "Arn"]}


def log_metric_namespace(env: str) -> str:
    """Namespace of the log metric filters; per environment (filters cannot add static dimensions)."""
    return f"{PROJECT}/web-logs/{validate_environment(env)}"


def _parameter_arn(name: str) -> dict[str, Any]:
    return {"Fn::Sub": f"arn:${{AWS::Partition}}:ssm:${{AWS::Region}}:${{AWS::AccountId}}:parameter{name}"}


def _parameters(env: str) -> dict[str, Any]:
    params: dict[str, Any] = {
        "ArtifactKey": {"Type": "String", "AllowedPattern": "^runtime/[0-9a-f]{64}\\.zip$",
                        "Description": "Content-addressed Lambda ZIP key in the multiuser artifacts bucket."},
        "DomainPrefix": {"Type": "String", "AllowedPattern": "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
                         "Description": "Cognito managed-login domain prefix of the web pool (private config)."},
        "MapitConfigJson": {"Type": "String", "NoEcho": True, "MinLength": 2, "MaxLength": 2048,
                            "Description": "Public MAPIT identifiers as JSON (discovery disabled)."},
        "AlarmEmail": {"Type": "String", "NoEcho": True, "AllowedPattern": EMAIL_PATTERN,
                       "Description": "Recipient of the alarm notifications (confirmed by email)."},
    }
    if env == "prod":
        params["WebCallbackUrl"] = {"Type": "String", "AllowedPattern": PROD_CALLBACK_PATTERN,
                                    "Description": "Exact HTTPS URL of the published web (sign-in and sign-out)."}
    for role in ("identity", "mcp", "pass", "sweep"):
        params[f"{_LOGICAL[role]}ReservedConcurrency"] = {
            "Type": "String", "Default": "", "AllowedPattern": RESERVATION_PATTERN,
            "Description": f"Reserved concurrency of the {role} function. Empty: none reserved."}
    return params


def _web_callback(env: str) -> Any:
    return {"Ref": "WebCallbackUrl"} if env == "prod" else DEV_CALLBACK_URL


def _web_origin(env: str) -> Any:
    return _origin("WebCallbackUrl") if env == "prod" else DEV_ORIGIN


def _turnstile_hostnames(env: str) -> Any:
    # The host of the exact callback URL (no port by pattern), so it cannot drift.
    if env == "prod":
        return {"Fn::Select": [2, {"Fn::Split": ["/", {"Ref": "WebCallbackUrl"}]}]}
    return DEV_TURNSTILE_HOSTNAMES


def _web_function(env: str, role: str, handler: str, variables: dict[str, Any]) -> dict[str, Any]:
    logical = _LOGICAL[role]
    function = _function(env, web_function_name(env, role), handler, TIMEOUTS[role], f"{logical}Role",
                         f"{logical}LogGroup", {MODE_VARIABLE: MODE_PUBLIC, "MAPIT_MCP_ENV": env, **variables})
    function["Properties"]["ReservedConcurrentExecutions"] = {"Fn::If": [
        f"Has{logical}Reservation", {"Ref": f"{logical}ReservedConcurrency"}, {"Ref": "AWS::NoValue"}]}
    return function


def _statement(sid: str, actions: list[str], resource: Any) -> dict[str, Any]:
    return {"Sid": sid, "Effect": "Allow", "Action": actions, "Resource": resource}


def _roles(env: str) -> dict[str, Any]:
    sessions = _parameter_arn(f"{web_session_parameter_prefix(env)}*")
    key = _parameter_arn(fingerprint_key_parameter_name(env))
    secret = _parameter_arn(turnstile_secret_parameter_name(env))
    name = {role: web_function_name(env, role) for role in _LOGICAL}
    return {
        "IdentityRole": _role(env, [
            _statement("WebTableLogin", ["dynamodb:BatchGetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
                       _TABLE_ARN),
            _statement("WriteWebSessions", ["ssm:PutParameter"], sessions),
            # The only role that may create the fingerprint key (never overwrite: the code uses Overwrite=False).
            _statement("FingerprintKeyReadCreate", ["ssm:GetParameter", "ssm:PutParameter"], key),
            _kms_via_ssm(["kms:Encrypt", "kms:Decrypt"]),
            _log_statement(name["identity"]),
        ]),
        "McpRole": _role(env, [
            _statement("ReadDeleteWebSessions", ["ssm:GetParameter", "ssm:DeleteParameter"], sessions),
            _kms_via_ssm("kms:Decrypt"),
            _statement("WebTableService", ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
                       _TABLE_ARN),
            _statement("DeleteWebPoolUsers", ["cognito-idp:AdminDeleteUser"], _POOL_ARN),
            _log_statement(name["mcp"]),
        ]),
        "PassRole": _role(env, [
            _statement("ReadKeyAndTurnstileSecret", ["ssm:GetParameter"], [key, secret]),
            _kms_via_ssm("kms:Decrypt"),
            _statement("WebTablePass", ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"], _TABLE_ARN),
            _log_statement(name["pass"]),
        ]),
        "SweepRole": _role(env, [
            _statement("WebPoolSweep", ["cognito-idp:DescribeUserPool", "cognito-idp:ListUsers",
                                        "cognito-idp:AdminDeleteUser"], _POOL_ARN),
            # DescribeParameters has no resource-level permissions; it returns metadata only.
            _statement("ListParameterMetadata", ["ssm:DescribeParameters"], "*"),
            _statement("DeleteWebSessions", ["ssm:DeleteParameter"], sessions),
            _statement("WebTableRecount", ["dynamodb:GetItem", "dynamodb:Scan", "dynamodb:UpdateItem"], _TABLE_ARN),
            _log_statement(name["sweep"]),
        ]),
    }


def _metric_filter(log_group: str, pattern: str, metric: str, env: str) -> dict[str, Any]:
    return {
        "Type": "AWS::Logs::MetricFilter",
        "Condition": "SupportedDeployment",
        "Properties": {
            "LogGroupName": {"Ref": log_group},
            "FilterPattern": pattern,
            "MetricTransformations": [{"MetricNamespace": log_metric_namespace(env), "MetricName": metric,
                                       "MetricValue": "1", "DefaultValue": 0}],
        },
    }


def _alarm(env: str, name: str, description: str, *, namespace: str, metric: str, statistic: str,
           operator: str, threshold: float, period: int = 300, evaluations: int = 1,
           missing: str = "notBreaching", dimensions: list[dict[str, Any]] | None = None,
           depends: str | None = None) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "AlarmName": f"{PROJECT}-{env}-web-{name}",
        "AlarmDescription": description,
        "Namespace": namespace,
        "MetricName": metric,
        "Statistic": statistic,
        "Period": period,
        "EvaluationPeriods": evaluations,
        "DatapointsToAlarm": evaluations,
        "Threshold": threshold,
        "ComparisonOperator": operator,
        "TreatMissingData": missing,
        "AlarmActions": [{"Ref": "AlarmTopic"}],
        "OKActions": [{"Ref": "AlarmTopic"}],
    }
    if dimensions:
        properties["Dimensions"] = dimensions
    alarm: dict[str, Any] = {"Type": "AWS::CloudWatch::Alarm", "Condition": "SupportedDeployment",
                             "Properties": properties}
    if depends:
        alarm["DependsOn"] = [depends]
    return alarm


def _observability(env: str) -> dict[str, Any]:
    logs = log_metric_namespace(env)
    sweep_dimension = [{"Name": METRIC_DIMENSION, "Value": env}]
    at_least_one = {"statistic": "Sum", "operator": "GreaterThanOrEqualToThreshold", "threshold": 1}
    cloudflare = " || ".join(f'($.web_pass_outcome = "{code}")' for code in PASS_CLOUDFLARE_CODES)
    resources: dict[str, Any] = {
        "AlarmTopic": {
            "Type": "AWS::SNS::Topic",
            "Condition": "SupportedDeployment",
            "Properties": {
                "TopicName": f"{PROJECT}-{env}-web-alarms",
                "Subscription": [{"Protocol": "email", "Endpoint": {"Ref": "AlarmEmail"}}],
                "Tags": _tags(env),
            },
        },
        "SweepFailedAlarm": _alarm(env, "sweep-failed", "A sweep run failed (see its codes).",
                                   namespace=METRIC_NAMESPACE, metric="SweepFailed", dimensions=sweep_dimension,
                                   **at_least_one),
        # A sweep that never runs emits nothing: missing data alarms too.
        "OldestItemAgeAlarm": _alarm(env, "oldest-item-age", "A web user or session is older than 60 minutes, "
                                     "or the sweep has not reported.", namespace=METRIC_NAMESPACE,
                                     metric="OldestItemAgeSeconds", statistic="Maximum",
                                     operator="GreaterThanThreshold", threshold=3600, period=600,
                                     missing="breaching", dimensions=sweep_dimension),
        "InvalidDatesAlarm": _alarm(env, "invalid-dates", "The sweep keeps deleting items whose date it cannot read.",
                                    namespace=METRIC_NAMESPACE, metric="InvalidDates", statistic="Sum",
                                    operator="GreaterThanThreshold", threshold=0, evaluations=3,
                                    dimensions=sweep_dimension),
        "PassCloudflareFilter": _metric_filter("PassLogGroup", "{ " + cloudflare + " }",
                                               "PassCloudflareUnavailable", env),
        "PassCloudflareAlarm": _alarm(env, "pass-cloudflare", "Turnstile validation is not answering: no new "
                                      "sign-in can get a pass.", namespace=logs, metric="PassCloudflareUnavailable",
                                      depends="PassCloudflareFilter", **at_least_one),
        "PassKeyMissingFilter": _metric_filter("PassLogGroup", '{ $.web_pass_outcome = "fingerprint_key_missing" }',
                                               "PassFingerprintKeyMissing", env),
        "PassKeyMissingAlarm": _alarm(env, "fingerprint-key-missing", "The pass cannot read the fingerprint key.",
                                      namespace=logs, metric="PassFingerprintKeyMissing",
                                      depends="PassKeyMissingFilter", **at_least_one),
        "IdentityKeyCreatedFilter": _metric_filter("IdentityLogGroup", "fingerprint_key_created",
                                                   "IdentityFingerprintKeyCreated", env),
        "IdentityKeyCreatedAlarm": _alarm(env, "fingerprint-key-created", "The identity function created a new "
                                          "fingerprint key: every count and pass was reset.", namespace=logs,
                                          metric="IdentityFingerprintKeyCreated",
                                          depends="IdentityKeyCreatedFilter", **at_least_one),
        "IdentityBreakerFilter": _metric_filter("IdentityLogGroup", "breaker_open", "IdentityBreakerOpen", env),
        "IdentityBreakerAlarm": _alarm(env, "breaker-open", "Sign-ins are refused because the breaker is open.",
                                       namespace=logs, metric="IdentityBreakerOpen", depends="IdentityBreakerFilter",
                                       **at_least_one),
        "IdentityFaultsFilter": _metric_filter("IdentityLogGroup", " ".join(f"?{code}" for code in IDENTITY_FAULT_CODES),
                                               "IdentityFaults", env),
        "IdentityFaultsAlarm": _alarm(env, "identity-faults", "The identity function failed for a reason other "
                                      "than an expected refusal.", namespace=logs, metric="IdentityFaults",
                                      depends="IdentityFaultsFilter", **at_least_one),
    }
    for role, logical in _LOGICAL.items():
        if role != "identity":
            resources[f"{logical}ErrorsAlarm"] = _alarm(
                env, f"{role}-errors", f"The {role} function returned a function error.", namespace="AWS/Lambda",
                metric="Errors", dimensions=[{"Name": "FunctionName", "Value": {"Ref": f"{logical}Function"}}],
                **at_least_one)
        resources[f"{logical}TimeoutFilter"] = _metric_filter(f"{logical}LogGroup", '"Task timed out"',
                                                              f"{logical}Timeouts", env)
        resources[f"{logical}TimeoutAlarm"] = _alarm(
            env, f"{role}-timeouts", f"The {role} function timed out.", namespace=logs, metric=f"{logical}Timeouts",
            depends=f"{logical}TimeoutFilter", **at_least_one)
    return resources


def build_public_web_template(env: str) -> dict[str, Any]:
    """Return the public web stack template for ``env``."""
    env = validate_environment(env)
    prod = env == "prod"
    retain = "Retain" if prod else "Delete"
    callback = _web_callback(env)

    client = _client("public-web", [callback], env)
    client["Properties"]["LogoutURLs"] = [copy.deepcopy(callback)]
    # The web keeps only the access token; the refresh token gets the shortest life
    # Cognito allows (the identity function also refuses every refresh).
    client["Properties"]["RefreshTokenValidity"] = 1
    client["Properties"]["TokenValidityUnits"] = {"AccessToken": "minutes", "IdToken": "minutes",
                                                  "RefreshToken": "hours"}
    identity_arn = {"Fn::GetAtt": ["IdentityFunction", "Arn"]}

    resources: dict[str, Any] = {
        "UserPool": {
            "Type": "AWS::Cognito::UserPool",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": retain,
            "UpdateReplacePolicy": retain,
            "Properties": {
                "UserPoolName": web_user_pool_name(env),
                "UserPoolTier": "ESSENTIALS",
                "UsernameAttributes": ["email"],
                "UsernameConfiguration": {"CaseSensitive": False},
                # No self sign-up: users are created only by the migration trigger.
                "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
                "Policies": {"PasswordPolicy": {
                    "MinimumLength": 6, "RequireUppercase": False, "RequireLowercase": False,
                    "RequireNumbers": False, "RequireSymbols": False, "TemporaryPasswordValidityDays": 1,
                }},
                "MfaConfiguration": "OFF",
                "Schema": [{
                    "Name": "tenant_id", "AttributeDataType": "String", "Mutable": False, "Required": False,
                    "StringAttributeConstraints": {"MinLength": "32", "MaxLength": "32"},
                }],
                "AccountRecoverySetting": {"RecoveryMechanisms": [{"Name": "admin_only", "Priority": 1}]},
                "DeletionProtection": "ACTIVE" if prod else "INACTIVE",
                "LambdaConfig": {
                    "UserMigration": identity_arn,
                    "PreAuthentication": copy.deepcopy(identity_arn),
                    "PreTokenGenerationConfig": {"LambdaArn": copy.deepcopy(identity_arn), "LambdaVersion": "V2_0"},
                },
                "UserPoolTags": {"Project": PROJECT, "Environment": env},
            },
        },
        "UserPoolDomain": {
            "Type": "AWS::Cognito::UserPoolDomain",
            "Condition": "SupportedDeployment",
            "Properties": {"UserPoolId": {"Ref": "UserPool"}, "Domain": {"Ref": "DomainPrefix"},
                           "ManagedLoginVersion": 2},
        },
        "ResourceServer": {
            "Type": "AWS::Cognito::UserPoolResourceServer",
            "Condition": "SupportedDeployment",
            "Properties": {
                "UserPoolId": {"Ref": "UserPool"},
                "Identifier": _RESOURCE_URL,
                "Name": f"{PROJECT}-{env}-web-mcp",
                "Scopes": [{"ScopeName": "use", "ScopeDescription": "Use the MCP server."}],
            },
        },
        "WebClient": client,
        "WebManagedLoginBranding": _branding("WebClient"),
        "IdentityCognitoInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Condition": "SupportedDeployment",
            "Properties": {"Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "IdentityFunction"},
                           "Principal": "cognito-idp.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
                           "SourceArn": _POOL_ARN},
        },
        "WebStateTable": {
            "Type": "AWS::DynamoDB::Table",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": retain,
            "UpdateReplacePolicy": retain,
            "Properties": {
                "TableName": web_table_name(env),
                "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "TimeToLiveSpecification": {"AttributeName": "expires_at", "Enabled": True},
                "DeletionProtectionEnabled": prod,
                "Tags": _tags(env),
            },
        },
        "HttpApi": {
            "Type": "AWS::ApiGatewayV2::Api",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Name": web_stack_name(env),
                "ProtocolType": "HTTP",
                # Only the web origin. No OPTIONS/ANY/$default route: API Gateway answers
                # the preflight itself, without the authorizer or a Lambda.
                "CorsConfiguration": {"AllowOrigins": [_web_origin(env)], "AllowMethods": list(CORS_ALLOW_METHODS),
                                      "AllowHeaders": list(CORS_ALLOW_HEADERS), "MaxAge": CORS_MAX_AGE_SECONDS},
                "Tags": {"Project": PROJECT, "Environment": env},
            },
        },
        "HttpApiStage": {
            "Type": "AWS::ApiGatewayV2::Stage",
            "Condition": "SupportedDeployment",
            # Route settings name routes by key; they must exist first.
            "DependsOn": ["EstadoRoute", "PaseRoute"],
            "Properties": {
                "ApiId": {"Ref": "HttpApi"},
                "StageName": "$default",
                "AutoDeploy": True,
                "DefaultRouteSettings": {**DEFAULT_THROTTLE, "DetailedMetricsEnabled": False},
                "RouteSettings": {key: {**value, "DetailedMetricsEnabled": False}
                                  for key, value in ROUTE_THROTTLES.items()},
            },
        },
        "JwtAuthorizer": {
            "Type": "AWS::ApiGatewayV2::Authorizer",
            "Condition": "SupportedDeployment",
            "Properties": {
                "ApiId": {"Ref": "HttpApi"},
                "Name": f"{PROJECT}-{env}-web-jwt",
                "AuthorizerType": "JWT",
                "IdentitySource": ["$request.header.Authorization"],
                "JwtConfiguration": {"Issuer": _ISSUER, "Audience": [_RESOURCE_URL]},
            },
        },
        "McpIntegration": _integration("McpFunction", INTEGRATION_TIMEOUT_MS["mcp"]),
        "IdentityIntegration": _integration("IdentityFunction", INTEGRATION_TIMEOUT_MS["identity"]),
        "PassIntegration": _integration("PassFunction", INTEGRATION_TIMEOUT_MS["pass"]),
        "McpPostRoute": _route("POST /mcp", "McpIntegration", jwt=True),
        "McpMetadataRoute": _route(f"GET {METADATA_PATH}", "McpIntegration"),
        "EstadoRoute": _route("GET /estado", "IdentityIntegration"),
        "PaseRoute": _route("POST /pase", "PassIntegration"),
        "McpPostInvokePermission": _api_permission("McpFunction", "$default/POST/mcp"),
        "McpMetadataInvokePermission": _api_permission("McpFunction", "$default/GET" + METADATA_PATH),
        "IdentityEstadoInvokePermission": _api_permission("IdentityFunction", "$default/GET/estado"),
        "PassInvokePermission": _api_permission("PassFunction", "$default/POST/pase"),
        **{f"{logical}LogGroup": _log_group(web_function_name(env, role), env) for role, logical in _LOGICAL.items()},
        **_roles(env),
        "IdentityFunction": _web_function(env, "identity", IDENTITY_HANDLER, {
            # No MULTIUSER_TABLE: public identity derives its table and refuses that variable.
            "MAPIT_CONFIG_JSON": {"Ref": "MapitConfigJson"},
        }),
        "McpFunction": _web_function(env, "mcp", MCP_HANDLER, {
            "MULTIUSER_ISSUER_URL": _ISSUER,
            "MULTIUSER_RESOURCE_URL": _RESOURCE_URL,
            "MULTIUSER_CLIENT_IDS": {"Ref": "WebClient"},
            "MULTIUSER_WEB_ORIGINS": _web_origin(env),
            "MULTIUSER_USER_POOL_ID": {"Ref": "UserPool"},
            "MULTIUSER_TABLE": {"Ref": "WebStateTable"},
            "MAPIT_CONFIG_JSON": {"Ref": "MapitConfigJson"},
            "MULTIUSER_GEOGRAPHY": "0",
        }),
        "PassFunction": _web_function(env, "pass", PASS_HANDLER, {
            "MAPIT_WEB_TABLE": {"Ref": "WebStateTable"},
            "MAPIT_WEB_TURNSTILE_HOSTNAMES": _turnstile_hostnames(env),
        }),
        "SweepFunction": _web_function(env, "sweep", SWEEP_HANDLER, {
            "MAPIT_WEB_USER_POOL_ID": {"Ref": "UserPool"},
        }),
        "SweepEventInvokeConfig": {
            "Type": "AWS::Lambda::EventInvokeConfig",
            "Condition": "SupportedDeployment",
            # The handler reports failures and returns; a retry would only repeat the run.
            "Properties": {"FunctionName": {"Ref": "SweepFunction"}, "Qualifier": "$LATEST",
                           "MaximumRetryAttempts": 0},
        },
        "SweepSchedule": {
            "Type": "AWS::Events::Rule",
            "Condition": "SupportedDeployment",
            "Properties": {
                "Name": f"{PROJECT}-{env}-web-sweep",
                "ScheduleExpression": SWEEP_SCHEDULE,
                "State": "ENABLED",
                "Targets": [{"Id": "sweep", "Arn": {"Fn::GetAtt": ["SweepFunction", "Arn"]}}],
            },
        },
        "SweepScheduleInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Condition": "SupportedDeployment",
            "Properties": {"Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "SweepFunction"},
                           "Principal": "events.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
                           "SourceArn": {"Fn::GetAtt": ["SweepSchedule", "Arn"]}},
        },
        **_observability(env),
    }

    def output(value: Any) -> dict[str, Any]:
        return {"Condition": "SupportedDeployment", "Value": copy.deepcopy(value)}

    conditions: dict[str, Any] = {"SupportedDeployment": _condition(web_stack_name(env))}
    for logical in _LOGICAL.values():
        conditions[f"Has{logical}Reservation"] = {
            "Fn::Not": [{"Fn::Equals": [{"Ref": f"{logical}ReservedConcurrency"}, ""]}]}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Public web mode of Honda MAPIT MCP ({env}); separate from the invitation-only stack.",
        "Parameters": _parameters(env),
        "Conditions": conditions,
        "Resources": resources,
        "Outputs": {
            "ApiBaseUrl": output(_API_BASE_URL),
            "McpUrl": output(_RESOURCE_URL),
            "UserPoolId": output({"Ref": "UserPool"}),
            "WebClientId": output({"Ref": "WebClient"}),
            "IssuerUrl": output(_ISSUER),
            "TableName": output({"Ref": "WebStateTable"}),
            "LoginDomain": output({"Fn::Sub": "https://${DomainPrefix}.auth.${AWS::Region}.amazoncognito.com"}),
            "AlarmTopicArn": output({"Ref": "AlarmTopic"}),
        },
    }


__all__ = [
    "CORS_ALLOW_HEADERS", "CORS_ALLOW_METHODS", "DEV_CALLBACK_URL", "IDENTITY_FAULT_CODES", "PASS_CLOUDFLARE_CODES",
    "PASS_HANDLER", "PROD_CALLBACK_PATTERN", "ROUTE_THROTTLES", "SWEEP_HANDLER", "SWEEP_SCHEDULE",
    "TIMEOUTS", "build_public_web_template", "log_metric_namespace",
]
