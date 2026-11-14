"""Offline checks of the public web stack template (no AWS, no network)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from mapit import public_identity, public_pass, public_sweep, public_web
from mapit import multiuser_entrypoint, multiuser_identity
from scripts import build_multiuser_stack as invitation
from scripts import build_public_web_stack as stack

PSEUDO = {"AWS::Region", "AWS::AccountId", "AWS::Partition", "AWS::StackName", "AWS::URLSuffix", "AWS::NoValue"}
ROOT = Path(__file__).resolve().parents[1]
MAPIT = {"region": "eu-west-1", "user_pool_id": "eu-west-1_Mapit1234", "user_pool_client_id": "MapitClient1",
         "identity_pool_id": "eu-west-1:11111111-2222-4333-8444-555555555555",
         "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
         "discovery_enabled": False, "http_timeout": 2}
PROD_CALLBACK = "https://web.example.org/"
ROLES = {"Identity": "identity", "Mcp": "mcp", "Pass": "pass", "Sweep": "sweep"}


@pytest.fixture(params=["dev", "prod"])
def env(request):
    return request.param


def _resources(env):
    return stack.build_public_web_template(env)["Resources"]


# --- a small offline resolver for the intrinsics this template uses ---------------

_REMOVED = object()


def _physical(env):
    return {"UserPool": "eu-west-1_AbCdEf123", "HttpApi": "a1b2c3d4e5", "WebClient": "webclient123",
            "WebStateTable": public_web.web_table_name(env), "AlarmTopic": "arn:topic",
            **{f"{logical}Function": public_web.web_function_name(env, role) for logical, role in ROLES.items()}}


def _resolve(value, env, parameters):
    ids = _physical(env)
    names = {"AWS::Region": "eu-west-1", "AWS::AccountId": "123456789012", "AWS::Partition": "aws",
             **parameters, **ids}
    if isinstance(value, list):
        return [item for item in (_resolve(item, env, parameters) for item in value) if item is not _REMOVED]
    if not isinstance(value, dict):
        return value
    if len(value) != 1 or not next(iter(value)).startswith(("Ref", "Fn::")):
        resolved = {key: _resolve(item, env, parameters) for key, item in value.items()}
        return {key: item for key, item in resolved.items() if item is not _REMOVED}
    (key, arg), = value.items()
    if key == "Ref":
        return _REMOVED if arg == "AWS::NoValue" else names[arg]
    if key == "Fn::Sub":
        return re.sub(r"\$\{([^}]+)\}", lambda match: names[match.group(1)], arg)
    if key == "Fn::Split":
        return _resolve(arg[1], env, parameters).split(arg[0])
    if key == "Fn::Select":
        return _resolve(arg[1], env, parameters)[arg[0]]
    if key == "Fn::Join":
        return arg[0].join(_resolve(arg[1], env, parameters))
    if key == "Fn::If":
        condition, yes, no = arg
        reserved = parameters.get(condition.removeprefix("Has").replace("Reservation", "ReservedConcurrency"), "")
        return _resolve(yes if reserved else no, env, parameters)
    if key == "Fn::GetAtt":
        return f"arn:{arg[0]}"
    raise AssertionError(key)


def _parameters(env, **extra):
    values = {"MapitConfigJson": json.dumps(MAPIT), "DomainPrefix": "web-login", "AlarmEmail": "alerts@example.org",
              "ArtifactKey": "runtime/" + "a" * 64 + ".zip", **extra}
    if env == "prod":
        values["WebCallbackUrl"] = PROD_CALLBACK
    return values


def _variables(env, logical):
    function = _resources(env)[f"{logical}Function"]["Properties"]
    return _resolve(function["Environment"]["Variables"], env, _parameters(env)), function["FunctionName"]


# --- names, structure ------------------------------------------------------------

def test_names_that_cannot_change_without_recreating(env):
    template = stack.build_public_web_template(env)
    resources = template["Resources"]
    pool = resources["UserPool"]["Properties"]
    assert pool["UserPoolName"] == f"honda-mapit-mcp-{env}-web-users" == public_sweep.web_user_pool_name(env)
    assert resources["UserPoolDomain"]["Properties"]["Domain"] == {"Ref": "DomainPrefix"}
    table = resources["WebStateTable"]["Properties"]
    assert table["TableName"] == f"honda-mapit-mcp-{env}-web-state"
    assert table["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]
    assert table["AttributeDefinitions"] == [{"AttributeName": "pk", "AttributeType": "S"}]
    assert table["TimeToLiveSpecification"] == {"AttributeName": "expires_at", "Enabled": True}
    assert table["BillingMode"] == "PAY_PER_REQUEST"
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"][1] == {
        "Fn::Equals": [{"Ref": "AWS::StackName"}, f"honda-mapit-mcp-{env}-web"]}
    for logical, role in ROLES.items():
        assert resources[f"{logical}Function"]["Properties"]["FunctionName"] == f"honda-mapit-mcp-{env}-web-{role}"
        assert resources[f"{logical}LogGroup"]["Properties"]["LogGroupName"] == f"/aws/lambda/honda-mapit-mcp-{env}-web-{role}"
    retained = "Retain" if env == "prod" else "Delete"
    assert resources["UserPool"]["DeletionPolicy"] == resources["WebStateTable"]["DeletionPolicy"] == retained


def test_no_reference_cycles_and_all_references_known(env):
    from tests.test_build_multiuser_stack import _find_cycle, _graph

    template = stack.build_public_web_template(env)
    assert _find_cycle(_graph(template)) is None
    known = set(template["Resources"]) | set(template["Parameters"]) | PSEUDO
    text = json.dumps(template)
    assert all(ref in known for ref in re.findall(r'"Ref": "([^"]+)"', text))
    assert all(sub.split(".")[0] in known for sub in re.findall(r"\$\{([^}!]+)\}", text))
    assert all(target in known for target, _ in re.findall(r'"Fn::GetAtt": \["([^"]+)", "([^"]+)"\]', text))


def test_pool_has_no_self_signup_and_the_three_triggers(env):
    pool = _resources(env)["UserPool"]["Properties"]
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}
    identity = {"Fn::GetAtt": ["IdentityFunction", "Arn"]}
    assert pool["LambdaConfig"] == {"UserMigration": identity, "PreAuthentication": identity,
                                    "PreTokenGenerationConfig": {"LambdaArn": identity, "LambdaVersion": "V2_0"}}
    assert pool["MfaConfiguration"] == "OFF"


def test_web_client_exact_return_pkce_and_short_tokens(env):
    client = _resources(env)["WebClient"]["Properties"]
    expected = [{"Ref": "WebCallbackUrl"}] if env == "prod" else ["http://localhost:5173/"]
    assert client["CallbackURLs"] == client["LogoutURLs"] == expected
    assert client["GenerateSecret"] is False and client["AllowedOAuthFlows"] == ["code"]
    assert client["PreventUserExistenceErrors"] == "ENABLED"
    assert (client["AccessTokenValidity"], client["RefreshTokenValidity"]) == (60, 1)
    assert client["TokenValidityUnits"] == {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "hours"}
    assert client["SupportedIdentityProviders"] == ["COGNITO"]
    assert _resources(env)["WebManagedLoginBranding"]["Properties"]["ClientId"] == {"Ref": "WebClient"}
    parameters = stack.build_public_web_template(env)["Parameters"]
    assert ("WebCallbackUrl" in parameters) is (env == "prod")
    if env == "prod":
        pattern = parameters["WebCallbackUrl"]["AllowedPattern"]
        assert re.fullmatch(pattern, PROD_CALLBACK)
        for bad in ("", "http://web.example.org/", "https://web.example.org:8443/", "https://web.example.org/?a=1"):
            assert not re.fullmatch(pattern, bad)


def test_api_routes_authorizer_cors_and_route_limits(env):
    resources = _resources(env)
    routes = {item["Properties"]["RouteKey"]: item["Properties"] for item in resources.values()
              if item["Type"] == "AWS::ApiGatewayV2::Route"}
    assert set(routes) == {"POST /mcp", "GET /estado", "POST /pase", f"GET {invitation.METADATA_PATH}"}
    assert {key for key, route in routes.items() if route["AuthorizationType"] != "NONE"} == {"POST /mcp"}
    assert routes["POST /mcp"]["AuthorizerId"] == {"Ref": "JwtAuthorizer"}
    jwt = resources["JwtAuthorizer"]["Properties"]["JwtConfiguration"]
    assert jwt["Issuer"] == {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"}
    target = {"GET /estado": "IdentityIntegration", "POST /pase": "PassIntegration", "POST /mcp": "McpIntegration"}
    for key, integration in target.items():
        assert routes[key]["Target"]["Fn::Join"][1][1] == {"Ref": integration}
    cors = _resolve(resources["HttpApi"]["Properties"]["CorsConfiguration"], env, _parameters(env))
    assert cors["AllowOrigins"] == ["https://web.example.org" if env == "prod" else "http://localhost:5173"]
    assert "*" not in json.dumps(cors) and "AllowCredentials" not in cors
    stage = resources["HttpApiStage"]
    default = stage["Properties"]["DefaultRouteSettings"]
    for key in ("GET /estado", "POST /pase"):
        own = stage["Properties"]["RouteSettings"][key]
        assert own["ThrottlingRateLimit"] < default["ThrottlingRateLimit"]
        assert own["ThrottlingBurstLimit"] < default["ThrottlingBurstLimit"]
    assert set(stage["DependsOn"]) == {"EstadoRoute", "PaseRoute"}


def test_reserved_concurrency_is_optional_and_never_defaulted(env):
    template = stack.build_public_web_template(env)
    for logical, role in ROLES.items():
        parameter = template["Parameters"][f"{logical}ReservedConcurrency"]
        assert parameter["Default"] == ""
        assert not re.fullmatch(parameter["AllowedPattern"], "0")
        value = template["Resources"][f"{logical}Function"]["Properties"]["ReservedConcurrentExecutions"]
        assert _resolve(value, env, _parameters(env)) is _REMOVED
        assert _resolve(value, env, _parameters(env, **{f"{logical}ReservedConcurrency": "5"})) == "5"


def test_sweep_schedule_timeout_and_no_retries(env):
    resources = _resources(env)
    assert resources["SweepSchedule"]["Properties"]["ScheduleExpression"] == "rate(5 minutes)"
    assert resources["SweepSchedule"]["Properties"]["Targets"][0]["Arn"] == {"Fn::GetAtt": ["SweepFunction", "Arn"]}
    assert resources["SweepFunction"]["Properties"]["Timeout"] == 60
    assert resources["SweepEventInvokeConfig"]["Properties"]["MaximumRetryAttempts"] == 0
    assert resources["SweepScheduleInvokePermission"]["Properties"]["Principal"] == "events.amazonaws.com"


def test_no_parameter_resource_and_no_secret_or_private_literal(env):
    template = stack.build_public_web_template(env)
    assert not [r for r in template["Resources"].values() if r["Type"] == "AWS::SSM::Parameter"]
    for name in ("MapitConfigJson", "AlarmEmail"):
        assert template["Parameters"][name]["NoEcho"] is True and "Default" not in template["Parameters"][name]
    text = json.dumps(template)
    assert not re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]", text)
    assert not re.search(r"[0-9]{12}", text)
    assert template["Resources"]["AlarmTopic"]["Properties"]["Subscription"] == [
        {"Protocol": "email", "Endpoint": {"Ref": "AlarmEmail"}}]


# --- environment contract with the modules ---------------------------------------

def test_every_function_runs_in_public_mode(env):
    for logical in ROLES:
        variables, _ = _variables(env, logical)
        assert variables["MAPIT_WEB_MODE"] == "public" and variables["MAPIT_MCP_ENV"] == env


def test_mcp_environment_is_accepted_by_the_entrypoint(env):
    variables, name = _variables(env, "Mcp")
    settings = multiuser_entrypoint._settings({**variables, "AWS_REGION": "eu-west-1",
                                               "AWS_LAMBDA_FUNCTION_NAME": name})
    assert settings["public"] is True and settings["geography"] is False
    assert settings["table"] == public_web.web_table_name(env)
    assert variables["MULTIUSER_CLIENT_IDS"] == "webclient123"


def test_pass_environment_is_accepted_and_names_only_the_web_host(env):
    variables, _ = _variables(env, "Pass")
    settings = public_pass.load_settings({**variables, "AWS_REGION": "eu-west-1"})
    assert settings.hostnames == frozenset({"web.example.org" if env == "prod" else "localhost"})


def test_identity_environment_is_accepted_and_has_no_invitation_table(env):
    variables, _ = _variables(env, "Identity")
    assert "MULTIUSER_TABLE" not in variables
    assert public_identity._environment({**variables, "AWS_REGION": "eu-west-1"}) == env
    multiuser_identity._mapit_config(variables)


def test_sweep_environment_passes_its_configuration_check(env, monkeypatch):
    variables, _ = _variables(env, "Sweep")

    def no_clients(_service):
        raise RuntimeError("no AWS in tests")

    monkeypatch.setattr(public_sweep, "_client_factory", no_clients)
    result = public_sweep.run_sweep(variables, None)
    assert result.codes == ["sweep_clients_unavailable"]


# --- IAM -------------------------------------------------------------------------

EXPECTED_ACTIONS = {
    "IdentityRole": {"dynamodb:BatchGetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "ssm:PutParameter",
                     "ssm:GetParameter", "kms:Encrypt", "kms:Decrypt", "logs:CreateLogStream", "logs:PutLogEvents"},
    "McpRole": {"ssm:GetParameter", "ssm:DeleteParameter", "kms:Decrypt", "dynamodb:GetItem", "dynamodb:UpdateItem",
                "dynamodb:DeleteItem", "cognito-idp:AdminDeleteUser", "logs:CreateLogStream", "logs:PutLogEvents"},
    "PassRole": {"ssm:GetParameter", "kms:Decrypt", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
                 "logs:CreateLogStream", "logs:PutLogEvents"},
    "SweepRole": {"cognito-idp:DescribeUserPool", "cognito-idp:ListUsers", "cognito-idp:AdminDeleteUser",
                  "ssm:DescribeParameters", "ssm:DeleteParameter", "dynamodb:GetItem", "dynamodb:Scan",
                  "dynamodb:UpdateItem", "logs:CreateLogStream", "logs:PutLogEvents"},
}


def _grants(env, role):
    """(action, resolved resource) pairs of one role."""
    statements = _resources(env)[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    pairs = set()
    for statement in statements:
        assert statement["Effect"] == "Allow"
        actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        resources = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
        for action in actions:
            for resource in resources:
                pairs.add((action, _resolve(resource, env, {})))
    return pairs


def test_roles_have_exactly_the_minimal_actions(env):
    roles = {name for name, item in _resources(env).items() if item["Type"] == "AWS::IAM::Role"}
    assert roles == set(EXPECTED_ACTIONS)
    for role, actions in EXPECTED_ACTIONS.items():
        assert {action for action, _ in _grants(env, role)} == actions


def test_no_wildcards_except_describe_parameters(env):
    for role in EXPECTED_ACTIONS:
        for action, resource in _grants(env, role):
            assert "*" not in action
            if resource == "*":
                assert action == "ssm:DescribeParameters"
            elif "*" in resource:
                allowed = (resource.endswith(f"parameter/honda-mapit-mcp/{env}/web/sessions/*")
                           or (action.startswith("logs:") and resource.endswith(":*"))
                           or (action.startswith("kms:") and resource.endswith(":key/*")))
                assert allowed, (role, action, resource)


def test_fingerprint_key_and_turnstile_secret_permissions(env):
    key = f"arn:aws:ssm:eu-west-1:123456789012:parameter{public_web.fingerprint_key_parameter_name(env)}"
    secret = f"arn:aws:ssm:eu-west-1:123456789012:parameter{public_pass.turnstile_secret_parameter_name(env)}"
    on_key = {role: {a for a, r in _grants(env, role) if r == key} for role in EXPECTED_ACTIONS}
    assert on_key == {"IdentityRole": {"ssm:GetParameter", "ssm:PutParameter"}, "McpRole": set(),
                      "PassRole": {"ssm:GetParameter"}, "SweepRole": set()}
    on_secret = {role: {a for a, r in _grants(env, role) if r == secret} for role in EXPECTED_ACTIONS}
    assert on_secret == {"IdentityRole": set(), "McpRole": set(), "PassRole": {"ssm:GetParameter"},
                         "SweepRole": set()}
    # Every SSM grant stays under the web root of this environment.
    for role in EXPECTED_ACTIONS:
        for action, resource in _grants(env, role):
            if action.startswith("ssm:") and resource != "*":
                assert f"parameter/honda-mapit-mcp/{env}/web/" in resource


def test_roles_never_touch_invitation_resources(env):
    text = json.dumps(stack.build_public_web_template(env))
    for forbidden in (f"honda-mapit-mcp-{env}-users\"", f"/honda-mapit-mcp/{env}/users/", "InvitationsTable",
                      "/multiuser/", f"honda-mapit-mcp-{env}-multiuser-invitations"):
        assert forbidden not in text


# --- alarms ----------------------------------------------------------------------

def _alarms(env):
    return {name: item["Properties"] for name, item in _resources(env).items()
            if item["Type"] == "AWS::CloudWatch::Alarm"}


def test_alarm_set_and_thresholds(env):
    alarms = _alarms(env)
    assert set(alarms) == {
        "SweepFailedAlarm", "OldestItemAgeAlarm", "InvalidDatesAlarm", "PassCloudflareAlarm", "PassKeyMissingAlarm",
        "IdentityKeyCreatedAlarm", "IdentityBreakerAlarm", "IdentityFaultsAlarm", "McpErrorsAlarm",
        "PassErrorsAlarm", "SweepErrorsAlarm", "IdentityTimeoutAlarm", "McpTimeoutAlarm", "PassTimeoutAlarm",
        "SweepTimeoutAlarm"}
    for alarm in alarms.values():
        assert alarm["AlarmActions"] == [{"Ref": "AlarmTopic"}]
    oldest = alarms["OldestItemAgeAlarm"]
    assert (oldest["MetricName"], oldest["Statistic"], oldest["Threshold"]) == ("OldestItemAgeSeconds", "Maximum", 3600)
    assert oldest["ComparisonOperator"] == "GreaterThanThreshold" and oldest["TreatMissingData"] == "breaching"
    for name in ("SweepFailedAlarm", "OldestItemAgeAlarm", "InvalidDatesAlarm"):
        assert alarms[name]["Namespace"] == public_sweep.METRIC_NAMESPACE
        assert alarms[name]["Dimensions"] == [{"Name": public_sweep.METRIC_DIMENSION, "Value": env}]
    invalid = alarms["InvalidDatesAlarm"]
    assert (invalid["EvaluationPeriods"], invalid["DatapointsToAlarm"], invalid["Threshold"]) == (3, 3, 0)
    failed = alarms["SweepFailedAlarm"]
    assert (failed["MetricName"], failed["Threshold"], failed["ComparisonOperator"]) == (
        "SweepFailed", 1, "GreaterThanOrEqualToThreshold")
    for logical in ("Mcp", "Pass", "Sweep"):
        errors = alarms[f"{logical}ErrorsAlarm"]
        assert (errors["Namespace"], errors["MetricName"]) == ("AWS/Lambda", "Errors")
        assert errors["Dimensions"] == [{"Name": "FunctionName", "Value": {"Ref": f"{logical}Function"}}]


def _filters(env):
    return {name: item["Properties"] for name, item in _resources(env).items()
            if item["Type"] == "AWS::Logs::MetricFilter"}


def test_metric_filters_feed_their_alarms(env):
    filters, alarms = _filters(env), _alarms(env)
    for name, item in _resources(env).items():
        if item["Type"] == "AWS::CloudWatch::Alarm" and "DependsOn" in item:
            (source,) = item["DependsOn"]
            transformation = filters[source]["MetricTransformations"][0]
            assert alarms[name]["MetricName"] == transformation["MetricName"]
            assert alarms[name]["Namespace"] == transformation["MetricNamespace"] == stack.log_metric_namespace(env)
    assert filters["PassCloudflareFilter"]["LogGroupName"] == {"Ref": "PassLogGroup"}
    for logical in ROLES:
        assert filters[f"{logical}TimeoutFilter"]["FilterPattern"] == '"Task timed out"'
        assert filters[f"{logical}TimeoutFilter"]["LogGroupName"] == {"Ref": f"{logical}LogGroup"}
    for name in ("IdentityKeyCreatedFilter", "IdentityBreakerFilter", "IdentityFaultsFilter"):
        assert filters[name]["LogGroupName"] == {"Ref": "IdentityLogGroup"}
    assert stack.log_metric_namespace("dev") != stack.log_metric_namespace("prod")


def test_filter_codes_are_codes_the_modules_write(env):
    filters = _filters(env)
    pass_source = (ROOT / "src/mapit/public_pass.py").read_text(encoding="utf-8")
    identity_source = (ROOT / "src/mapit/public_identity.py").read_text(encoding="utf-8")
    web_source = (ROOT / "src/mapit/public_web.py").read_text(encoding="utf-8")
    cloudflare = re.findall(r'\$\.web_pass_outcome = "([a-z_]+)"', filters["PassCloudflareFilter"]["FilterPattern"])
    assert cloudflare == list(stack.PASS_CLOUDFLARE_CODES)
    # Every pass outcome that means "Cloudflare or its secret does not answer" (pass PR contract).
    assert set(cloudflare) == {
        "turnstile_unavailable", "turnstile_http_status", "turnstile_response_too_large",
        "turnstile_response_malformed", "turnstile_failed_unexpected", "turnstile_secret_rejected",
        "turnstile_secret_missing", "turnstile_secret_read_failed", "turnstile_secret_invalid"}
    for code in cloudflare + ["fingerprint_key_missing"]:
        assert f'"{code}"' in pass_source, code
    assert public_pass.LOG_FIELD == "web_pass_outcome"
    assert filters["PassKeyMissingFilter"]["FilterPattern"] == '{ $.web_pass_outcome = "fingerprint_key_missing" }'
    assert filters["IdentityKeyCreatedFilter"]["FilterPattern"] == public_web.EVENT_FINGERPRINT_KEY_CREATED
    assert '"breaker_open"' in identity_source and filters["IdentityBreakerFilter"]["FilterPattern"] == "breaker_open"
    faults = filters["IdentityFaultsFilter"]["FilterPattern"].split(" ")
    assert [term.removeprefix("?") for term in faults] == list(stack.IDENTITY_FAULT_CODES)
    for code in stack.IDENTITY_FAULT_CODES:
        # Literal codes, or "<step>_no_time" / "<step>_failed" built by _call("<step>", ...).
        base = re.sub(r"_(no_time|failed)$", "", code)
        assert f'"{code}"' in identity_source + web_source or f'_call("{base}"' in identity_source, code
    # Expected refusals never count as faults.
    for refusal in ("mapit_rejected", "pass_missing", "locked", "closed", "cap_full", "daily_limit", "breaker_open"):
        assert refusal not in stack.IDENTITY_FAULT_CODES


def test_filter_patterns_fit_cloudwatch_limits(env):
    for item in _filters(env).values():
        assert 0 < len(item["FilterPattern"]) <= 1024


# --- the invitation-only stack does not change ------------------------------------

def test_building_the_web_template_leaves_the_invitation_template_unchanged():
    from tests.test_multiuser_template_pinned import PINNED, _digest

    for env in ("dev", "prod"):
        stack.build_public_web_template(env)
        assert _digest(invitation.build_multiuser_template(env)) == PINNED[("multiuser", env)]
        assert _digest(invitation.build_artifacts_template(env)) == PINNED[("artifacts", env)]


def test_web_and_invitation_templates_share_no_named_resource():
    for env in ("dev", "prod"):
        web = stack.build_public_web_template(env)["Resources"]
        old = invitation.build_multiuser_template(env)["Resources"]
        keys = ("UserPoolName", "TableName", "FunctionName", "LogGroupName", "Name", "ClientName", "TopicName")

        def names(resources):
            return {(item["Type"], item["Properties"][key]) for item in resources.values() for key in keys
                    if isinstance(item.get("Properties", {}).get(key), str)}

        assert not names(web) & names(old)


def test_template_is_deterministic_and_env_validated():
    first = json.dumps(stack.build_public_web_template("prod"), separators=(",", ":"))
    assert hashlib.sha256(first.encode()).digest() == hashlib.sha256(
        json.dumps(stack.build_public_web_template("prod"), separators=(",", ":")).encode()).digest()
    with pytest.raises(ValueError):
        stack.build_public_web_template("staging")
