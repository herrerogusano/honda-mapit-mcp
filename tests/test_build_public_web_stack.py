"""Offline checks of the public web stack template (no AWS, no network)."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

from mapit import public_identity, public_pass, public_sweep, public_web, public_web_service
from mapit import multiuser_common, multiuser_entrypoint, multiuser_identity
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
                      "/multiuser/", multiuser_common.table_name(env)):
        assert forbidden not in text


def _raw_statements(env, role):
    return _resources(env)[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def _listed(value):
    return value if isinstance(value, list) else [value]


def test_every_table_and_pool_grant_is_exactly_this_stack(env):
    for role in EXPECTED_ACTIONS:
        for statement in _raw_statements(env, role):
            services = {action.split(":")[0] for action in _listed(statement["Action"])}
            if services & {"dynamodb", "cognito-idp"}:
                assert len(services) == 1, (role, statement["Sid"])
            if services == {"dynamodb"}:
                assert statement["Resource"] == {"Fn::GetAtt": ["WebStateTable", "Arn"]}, (role, statement["Sid"])
            if services == {"cognito-idp"}:
                assert statement["Resource"] == {"Fn::GetAtt": ["UserPool", "Arn"]}, (role, statement["Sid"])


def test_every_ssm_grant_is_in_the_exact_list_of_its_role(env):
    root = f"arn:aws:ssm:eu-west-1:123456789012:parameter/honda-mapit-mcp/{env}/web/"
    sessions, key, secret = root + "sessions/*", root + "fingerprint-key", root + "turnstile-secret"
    expected = {
        "IdentityRole": {("ssm:PutParameter", sessions), ("ssm:GetParameter", key), ("ssm:PutParameter", key)},
        "McpRole": {("ssm:GetParameter", sessions), ("ssm:DeleteParameter", sessions)},
        "PassRole": {("ssm:GetParameter", key), ("ssm:GetParameter", secret)},
        "SweepRole": {("ssm:DescribeParameters", "*"), ("ssm:DeleteParameter", sessions)},
    }
    for role, grants in expected.items():
        assert {(a, r) for a, r in _grants(env, role) if a.startswith("ssm:")} == grants, role


def test_put_parameter_requires_no_overwrite_in_iam(env):
    for role in EXPECTED_ACTIONS:
        for statement in _raw_statements(env, role):
            if "ssm:PutParameter" in _listed(statement["Action"]):
                assert _listed(statement["Action"]) == ["ssm:PutParameter"]
                assert statement["Condition"] == {"StringEquals": {"ssm:Overwrite": "false"}}


def test_retention_and_deletion_protection_by_environment(env):
    resources = _resources(env)
    prod = env == "prod"
    retained = "Retain" if prod else "Delete"
    for name in ("UserPool", "WebStateTable"):
        assert resources[name]["DeletionPolicy"] == resources[name]["UpdateReplacePolicy"] == retained
    assert resources["UserPool"]["Properties"]["DeletionProtection"] == ("ACTIVE" if prod else "INACTIVE")
    assert resources["WebStateTable"]["Properties"]["DeletionProtectionEnabled"] is prod


# --- alarms ----------------------------------------------------------------------

def _alarms(env):
    return {name: item["Properties"] for name, item in _resources(env).items()
            if item["Type"] == "AWS::CloudWatch::Alarm"}


def test_alarm_set_and_thresholds(env):
    alarms = _alarms(env)
    assert set(alarms) == {"FaultsAlarm", "OldestItemAgeAlarm", "McpDailyCeilingAlarm"}
    assert {alarm["AlarmName"] for alarm in alarms.values()} == {
        f"honda-mapit-mcp-{env}-web-{name}" for name in ("faults", "oldest-item-age", "daily-ceiling")}
    for alarm in alarms.values():
        assert alarm["AlarmActions"] == alarm["OKActions"] == [{"Ref": "AlarmTopic"}]
        assert alarm["Period"] >= 60  # standard resolution: high-resolution alarms are outside the free tier
    oldest = alarms["OldestItemAgeAlarm"]
    assert (oldest["MetricName"], oldest["Statistic"], oldest["Threshold"]) == ("OldestItemAgeSeconds", "Maximum", 3600)
    assert oldest["ComparisonOperator"] == "GreaterThanThreshold" and oldest["TreatMissingData"] == "breaching"
    assert oldest["Namespace"] == public_sweep.METRIC_NAMESPACE
    assert oldest["Dimensions"] == [{"Name": public_sweep.METRIC_DIMENSION, "Value": env}]
    faults = alarms["FaultsAlarm"]
    assert (faults["Namespace"], faults["MetricName"]) == (stack.log_metric_namespace(env), "WebFaults")
    assert (faults["Statistic"], faults["Threshold"], faults["ComparisonOperator"]) == (
        "Sum", 1, "GreaterThanOrEqualToThreshold")
    assert (faults["Period"], faults["EvaluationPeriods"], faults["TreatMissingData"]) == (300, 1, "notBreaching")
    assert "Dimensions" not in faults


def _filters(env):
    return {name: item["Properties"] for name, item in _resources(env).items()
            if item["Type"] == "AWS::Logs::MetricFilter"}


def _custom_metrics(env):
    """Every custom metric the stack can produce: filter outputs plus the sweep's EMF metrics."""
    metrics = set()
    for item in _filters(env).values():
        (transformation,) = item["MetricTransformations"]
        assert "Dimensions" not in transformation
        metrics.add((transformation["MetricNamespace"], transformation["MetricName"], ()))
    record = public_sweep.emf_record(public_sweep.SweepResult(recount_ran=True), env, 1)
    for directive in record["_aws"]["CloudWatchMetrics"]:
        for metric in directive["Metrics"]:
            for dimensions in directive["Dimensions"]:
                metrics.add((directive["Namespace"], metric["Name"], tuple((d, record[d]) for d in dimensions)))
    return metrics


def test_both_stacks_together_fit_the_cloudwatch_free_tier():
    # Free tier: 10 alarm metrics (standard-resolution alarms that list metrics
    # directly; metric math is counted per listed metric) and 10 custom metrics
    # (each name and dimension combination is one). Lambda's own metrics are not custom.
    alarm_metrics, custom = 0, set()
    for env in ("dev", "prod"):
        for alarm in _alarms(env).values():
            assert "Metrics" not in alarm and "MetricName" in alarm  # no metric math, no Metrics Insights
            alarm_metrics += 1
        custom |= _custom_metrics(env)
    assert alarm_metrics == 6 and len(custom) == 6
    assert alarm_metrics <= 10 and len(custom) <= 10
    for env in ("dev", "prod"):
        assert _custom_metrics(env) == {
            (stack.log_metric_namespace(env), "WebFaults", ()),
            (stack.log_metric_namespace(env), "McpDailyCeilingReached", ()),
            (public_sweep.METRIC_NAMESPACE, "OldestItemAgeSeconds", ((public_sweep.METRIC_DIMENSION, env),)),
        }


def test_fault_filters_feed_the_one_faults_alarm(env):
    filters, resources = _filters(env), _resources(env)
    fault_filters = {name for name, item in filters.items()
                     if item["MetricTransformations"][0]["MetricName"] == "WebFaults"}
    assert fault_filters == {"IdentityFaultsFilter", "PassFaultsFilter", "SweepFaultsFilter", "McpTimeoutFilter",
                             "PassTimeoutFilter", "SweepTimeoutFilter"}
    assert resources["FaultsAlarm"]["DependsOn"] == sorted(fault_filters)
    for name in fault_filters:
        transformation = filters[name]["MetricTransformations"][0]
        assert transformation["MetricNamespace"] == stack.log_metric_namespace(env)
        assert (transformation["MetricValue"], transformation["DefaultValue"]) == ("1", 0)
    # Every function's log group is covered, including a timeout in each.
    groups = {filters[name]["LogGroupName"]["Ref"] for name in fault_filters}
    assert groups == {f"{logical}LogGroup" for logical in ROLES}
    for logical in ("Mcp", "Pass", "Sweep"):
        assert filters[f"{logical}TimeoutFilter"]["FilterPattern"] == '"Task timed out"'
        assert filters[f"{logical}TimeoutFilter"]["LogGroupName"] == {"Ref": f"{logical}LogGroup"}
    assert filters["IdentityFaultsFilter"]["FilterPattern"].endswith(' ?"Task timed out"')
    assert stack.log_metric_namespace("dev") != stack.log_metric_namespace("prod")


def test_sweep_fault_filter_reads_fields_of_the_sweep_line(env):
    pattern = _filters(env)["SweepFaultsFilter"]["FilterPattern"]
    assert pattern == stack.SWEEP_FAULT_PATTERN
    fields = set(re.findall(r"\$\.([A-Za-z_]+)", pattern))
    assert fields == {"event", "SweepFailed", "InvalidDates"}
    ok = public_sweep.emf_record(public_sweep.SweepResult(), env, 1)
    failed = public_sweep.emf_record(public_sweep.SweepResult(codes=["sweep_users_delete_failed"]), env, 1)
    invalid = public_sweep.emf_record(public_sweep.SweepResult(invalid_dates=2), env, 1)

    def matches(record):  # the pattern's logic, over the same fields
        return record["event"] == "web_sweep" and (record["SweepFailed"] == 1 or record["InvalidDates"] > 0)

    assert '$.event = "web_sweep"' in pattern and "$.SweepFailed = 1" in pattern and "$.InvalidDates > 0" in pattern
    assert (matches(ok), matches(failed), matches(invalid)) == (False, True, True)


def test_filter_codes_are_codes_the_modules_write(env):
    filters = _filters(env)
    pass_source = (ROOT / "src/mapit/public_pass.py").read_text(encoding="utf-8")
    identity_source = (ROOT / "src/mapit/public_identity.py").read_text(encoding="utf-8")
    web_source = (ROOT / "src/mapit/public_web.py").read_text(encoding="utf-8")
    pass_codes = re.findall(r'\$\.web_pass_outcome = "([a-z_]+)"', filters["PassFaultsFilter"]["FilterPattern"])
    assert pass_codes == list(stack.PASS_FAULT_CODES)
    assert pass_codes == list(stack.PASS_CLOUDFLARE_CODES) + ["fingerprint_key_missing", "pass_internal_error"]
    # Every pass outcome that means "Cloudflare or its secret does not answer" (pass PR contract).
    assert set(stack.PASS_CLOUDFLARE_CODES) == {
        "turnstile_unavailable", "turnstile_http_status", "turnstile_response_too_large",
        "turnstile_response_malformed", "turnstile_failed_unexpected", "turnstile_secret_rejected",
        "turnstile_secret_missing", "turnstile_secret_read_failed", "turnstile_secret_invalid"}
    for code in pass_codes:
        assert f'"{code}"' in pass_source, code
    assert public_pass.LOG_FIELD == "web_pass_outcome"
    assert stack.IDENTITY_ALARM_EVENTS == (public_web.EVENT_FINGERPRINT_KEY_CREATED, "breaker_open")
    assert '"breaker_open"' in identity_source
    terms = filters["IdentityFaultsFilter"]["FilterPattern"].removesuffix(' ?"Task timed out"').split(" ")
    assert [term.removeprefix("?") for term in terms] == list(stack.IDENTITY_FAULT_CODES + stack.IDENTITY_ALARM_EVENTS)
    assert all(term.startswith("?") for term in terms)
    # Every code public_identity can log is classified exactly once: fault or expected refusal.
    logged = set(re.findall(r'_Stop\("([a-z_]+)"', identity_source))
    logged |= set(re.findall(r'_log\([^,]+, "([a-z_]+)"', identity_source))
    logged |= {f"{step}_{suffix}" for step in re.findall(r'_call\("([a-z_]+)"', identity_source)
               for suffix in ("no_time", "failed")}
    logged |= set(re.findall(r'PublicWebError\("([a-z_]+)"', web_source))  # logged by _run as exc.code
    assert 'raise _Stop(f"{step}_no_time")' in identity_source and 'raise _Stop(f"{step}_failed"' in identity_source
    faults, refusals = set(stack.IDENTITY_FAULT_CODES), set(stack.IDENTITY_REFUSAL_CODES)
    assert len(faults) == len(stack.IDENTITY_FAULT_CODES) and not faults & refusals
    assert faults | refusals == logged, (sorted(logged - faults - refusals), sorted(faults | refusals - logged))
    for refusal in ("mapit_rejected", "pass_missing", "locked", "closed", "cap_full", "daily_limit", "breaker_open"):
        assert refusal in refusals


def test_daily_ceiling_alarm_counts_the_fixed_event_of_the_service(env):
    filters, alarms = _filters(env), _alarms(env)
    ceiling = filters["McpDailyCeilingFilter"]
    assert ceiling["LogGroupName"] == {"Ref": "McpLogGroup"}
    assert ceiling["FilterPattern"] == '{ $.event = "public_daily_ceiling_reached" }'
    assert public_web_service.EVENT_DAILY_CEILING_REACHED == "public_daily_ceiling_reached"
    service_source = (ROOT / "src/mapit/public_web_service.py").read_text(encoding="utf-8")
    assert '{"event": EVENT_DAILY_CEILING_REACHED}' in service_source
    alarm = alarms["McpDailyCeilingAlarm"]
    assert alarm["AlarmName"] == f"honda-mapit-mcp-{env}-web-daily-ceiling"
    assert (alarm["MetricName"], alarm["Namespace"]) == ("McpDailyCeilingReached", stack.log_metric_namespace(env))
    assert (alarm["Statistic"], alarm["Threshold"], alarm["ComparisonOperator"]) == (
        "Sum", 1, "GreaterThanOrEqualToThreshold")
    assert alarm["TreatMissingData"] == "notBreaching"
    assert _resources(env)["McpDailyCeilingAlarm"]["DependsOn"] == ["McpDailyCeilingFilter"]
    assert ceiling["MetricTransformations"][0]["MetricName"] == "McpDailyCeilingReached"


def test_daily_ceiling_filter_matches_the_line_the_service_writes(env):
    """The JSON line the gate logs, parsed as CloudWatch would for ``{ $.event = "..." }``."""
    import json as _json

    from mapit.public_web_service import PublicSessionGate

    lines = []

    class _Dynamo:
        def get_item(self, **kwargs):
            return {"Item": {"pk": {"S": "config"}, "open": {"BOOL": True}}}

        def update_item(self, **kwargs):
            if kwargs["Key"]["pk"]["S"].startswith("day#"):
                return {"Attributes": {"mcp_calls": {"N": str(public_web.DAILY_CALL_LIMIT)}}}
            return {}

    gate = PublicSessionGate(env=env, pool="eu-west-1_Pool12345", client=lambda name: _Dynamo(),
                             clock=lambda: 1_800_000_000, log=lines.append)
    gate.admit("a" * 32, "user", 1_800_000_000 - 60)
    (line,) = lines
    wanted = re.fullmatch(r'\{ \$\.event = "([a-z_]+)" \}', _filters(env)["McpDailyCeilingFilter"]["FilterPattern"])
    assert _json.loads(line)["event"] == wanted.group(1)


def test_filter_patterns_fit_cloudwatch_limits(env):
    for item in _filters(env).values():
        assert 0 < len(item["FilterPattern"]) <= 1024


# --- managed login style: the Ride Log look, dark only ------------------------------

# Accepted extensions per asset category, from the Cognito developer guide
# ("The branding editor and customizing managed login", Image assets).
_ASSET_EXTENSIONS = {"FORM_LOGO": {"PNG", "SVG", "JPEG"}, "PAGE_BACKGROUND": {"PNG", "SVG", "JPEG"},
                     "FAVICON_SVG": {"SVG"}}
# Subset of the SVG elements and attributes that guide lists as supported.
_SVG_ELEMENTS = {"svg", "g", "path", "polygon", "rect", "title"}
_SVG_ATTRIBUTES = {"xmlns", "viewBox", "width", "height", "preserveAspectRatio", "points", "fill", "fill-opacity",
                   "fill-rule", "d", "transform"}
# CloudFormation quota for a template sent as TemplateBody (the deploy script sends it so).
_TEMPLATE_BODY_LIMIT = 51_200


def _branding(env):
    return _resources(env)["WebManagedLoginBranding"]["Properties"]


def _relative_luminance(hex_colour):
    channels = [int(hex_colour[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(first, second):
    high, low = sorted((_relative_luminance(first), _relative_luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def test_login_style_is_the_web_look_not_the_cognito_default(env):
    from scripts import public_web_branding as brand

    branding = _branding(env)
    assert "UseCognitoProvidedValues" not in branding
    assert branding["Settings"] == brand.web_branding_settings()
    settings = branding["Settings"]
    assert settings["categories"]["global"]["colorSchemeMode"] == "DARK"
    components = settings["components"]
    assert components["pageBackground"]["darkMode"]["color"] == brand.BG + "ff"
    assert components["form"]["darkMode"]["backgroundColor"] == brand.SURFACE + "ff"
    assert components["form"]["logo"]["enabled"] is True
    assert components["primaryButton"]["darkMode"]["defaults"] == {"backgroundColor": brand.RED + "ff",
                                                                   "textColor": brand.ON_RED + "ff"}
    assert settings["componentClasses"]["link"]["darkMode"]["defaults"]["textColor"] == brand.RED_HI + "ff"
    assert settings["componentClasses"]["buttons"]["borderRadius"] == brand.RADIUS
    # Dark only: light mode, if Cognito ever shows it, carries the same colours.
    for group in (settings["components"], settings["componentClasses"]):
        for value in group.values():
            if isinstance(value, dict) and "darkMode" in value:
                assert value["lightMode"] == value["darkMode"]


def test_login_style_colours_are_cognito_hex_and_text_stays_readable(env):
    from scripts import public_web_branding as brand

    text = json.dumps(_branding(env)["Settings"])
    colours = re.findall(r'"(?:\w*[cC]olor)": "([^"]*)"', text)
    assert colours and all(re.fullmatch(r"[0-9a-f]{8}", colour) for colour in colours)
    # The pairs the web's own contrast test checks (text 4.5:1, control borders and focus 3:1).
    pairs = [(fg, bg, 4.5) for fg in (brand.FG, brand.FG_2, brand.FG_3, brand.RED_HI)
             for bg in (brand.BG, brand.SURFACE, brand.SURFACE_2)]
    pairs += [(brand.ON_RED, brand.RED, 4.5), (brand.AMBER, brand.AMBER_BG, 4.5),
              (brand.CONTROL_LINE, brand.BG, 3), (brand.CONTROL_LINE, brand.SURFACE, 3),
              (brand.RED_HI, brand.SURFACE_2, 3)]
    for foreground, background, minimum in pairs:
        assert _contrast(foreground, background) >= minimum, (foreground, background)


def test_login_style_assets_are_small_own_svgs(env):
    import base64
    import xml.etree.ElementTree as ElementTree

    assets = _branding(env)["Assets"]
    assert {asset["Category"] for asset in assets} == set(_ASSET_EXTENSIONS) and len(assets) == 3
    for asset in assets:
        assert set(asset) == {"Category", "ColorMode", "Extension", "Bytes"}
        assert asset["ColorMode"] == "DYNAMIC"
        assert asset["Extension"] in _ASSET_EXTENSIONS[asset["Category"]]
        assert len(asset["Bytes"]) <= 1_000_000
        svg = base64.b64decode(asset["Bytes"], validate=True).decode("utf-8")
        lowered = svg.lower()
        # Nothing fetched at run time, no script, no third-party name.
        for banned in ("href", "url(", "http:", "<script", "<image", "<style", "@import", "honda", "mapit"):
            assert banned not in lowered.replace('xmlns="http://www.w3.org/2000/svg"', ""), banned
        root = ElementTree.fromstring(svg)
        for element in root.iter():
            assert element.tag.removeprefix("{http://www.w3.org/2000/svg}") in _SVG_ELEMENTS
            assert set(element.attrib) <= _SVG_ATTRIBUTES


def test_template_fits_a_template_body_request(env):
    assert len(json.dumps(stack.build_public_web_template(env), separators=(",", ":"))) < _TEMPLATE_BODY_LIMIT


def test_invitation_stack_keeps_the_cognito_default_style():
    for env in ("dev", "prod"):
        branding = invitation.build_multiuser_template(env)["Resources"]
        styles = [item["Properties"] for item in branding.values() if item["Type"] == "AWS::Cognito::ManagedLoginBranding"]
        assert styles and all(style.get("UseCognitoProvidedValues") is True and "Settings" not in style
                              and "Assets" not in style for style in styles)


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
