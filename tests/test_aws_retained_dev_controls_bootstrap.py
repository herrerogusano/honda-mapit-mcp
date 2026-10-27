from __future__ import annotations

from contextlib import contextmanager
import copy
import json
import pytest

from scripts.aws_retained_dev_controls_bootstrap import RetainedDevControlsCoordinator, RetainedDevControlsError, _resolve_internal_template
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_support import build_retained_dev_controls

ACCOUNT = "123456789012"
SOURCE = "a" * 40
API = "a1b2c3d4e5"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-controls-operator"
STACK_NAME = "honda-mapit-mcp-dev-retained-controls"
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/11111111-2222-4333-8444-555555555555"
APP_STACK_NAME = "honda-mapit-mcp-dev-retained"
APP_STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{APP_STACK_NAME}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
RUN_ID = 2026100606


def _ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


class AwsError(Exception):
    def __init__(self, code, status, message):
        self.response = {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Journal:
    def __init__(self):
        self.state = None
        self.saved = []

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, value):
        self.state = copy.deepcopy(value)
        self.saved.append(copy.deepcopy(value))


class Sts:
    def get_caller_identity(self):
        return _ok(Account=ACCOUNT, Arn=CALLER)


class ApiGateway:
    def get_api(self, **kwargs):
        return _ok(ApiId=API, Name="honda-mapit-mcp-dev-retained-api", ProtocolType="HTTP", DisableExecuteApiEndpoint=True)

    def get_routes(self, **kwargs):
        return _ok(Items=[])


class Lambda:
    def get_function_configuration(self, **kwargs):
        return _ok(FunctionName="honda-mapit-mcp-dev-retained-handler", Role=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role", Runtime="python3.13", Architectures=["arm64"], MemorySize=256, Timeout=20, State="Active")

    def get_function_concurrency(self, **kwargs):
        return _ok(ReservedConcurrentExecutions=0)


def _physical():
    prefix = "honda-mapit-mcp-dev-retained"
    return {
        "ShutdownWorkflowRole": f"{prefix}-shutdown-workflow",
        "ShutdownStateMachine": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{prefix}-shutdown",
        "RequestTripwireAlarm": f"{prefix}-request-tripwire",
        "RequestTripwireEventRole": f"{prefix}-request-tripwire",
        "RequestTripwireAlarmRule": f"{prefix}-request-tripwire-alarm-rule",
    }


def _service_arns():
    prefix = "honda-mapit-mcp-dev-retained"
    return {
        "ShutdownWorkflowRole": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-shutdown-workflow",
        "ShutdownStateMachine": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{prefix}-shutdown",
        "RequestTripwireAlarm": f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:{prefix}-request-tripwire",
        "RequestTripwireEventRole": f"arn:aws:iam::{ACCOUNT}:role/{prefix}-request-tripwire",
        "RequestTripwireAlarmRule": f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/{prefix}-request-tripwire-alarm-rule",
    }


class CloudFormation:
    def __init__(self):
        self.created = False
        self.calls = []

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        if kwargs.get("StackName") == APP_STACK_ID:
            return _ok(Stacks=[{"StackId": APP_STACK_ID, "StackName": APP_STACK_NAME, "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True}])
        if not self.created:
            raise AwsError("ValidationError", 400, f"Stack with id {STACK_NAME} does not exist")
        return _ok(Stacks=[{
            "StackId": STACK_ID, "StackName": STACK_NAME, "StackStatus": "CREATE_COMPLETE",
            "EnableTerminationProtection": True,
            "Tags": [
                {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
                {"Key": "Purpose", "Value": "retained-dev-controls"}, {"Key": "OperatorRunId", "Value": str(RUN_ID)},
            ],
        }])

    def create_stack(self, **kwargs):
        self.calls.append(("create_stack", kwargs))
        self.created = True
        return _ok(StackId=STACK_ID)

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        if kwargs.get("StackName") == APP_STACK_ID:
            return _ok(TemplateBody=build_retained_dev_template())
        return _ok(TemplateBody=build_retained_dev_controls(API))

    def describe_stack_events(self, **kwargs):
        self.calls.append(("describe_stack_events", kwargs))
        from scripts.aws_retained_dev_controls_bootstrap import _token
        return _ok(StackEvents=[{"StackId": STACK_ID, "ClientRequestToken": _token(ACCOUNT, SOURCE, RUN_ID)}])

    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs))
        if kwargs.get("StackName") == APP_STACK_ID:
            return _ok(StackResources=[
                {"LogicalResourceId": "McpApi", "ResourceType": "AWS::ApiGatewayV2::Api", "PhysicalResourceId": API, "ResourceStatus": "CREATE_COMPLETE", "StackId": APP_STACK_ID, "StackName": APP_STACK_NAME},
                {"LogicalResourceId": "McpApiStage", "ResourceType": "AWS::ApiGatewayV2::Stage", "PhysicalResourceId": "$default", "ResourceStatus": "CREATE_COMPLETE", "StackId": APP_STACK_ID, "StackName": APP_STACK_NAME},
                {"LogicalResourceId": "McpHandlerRole", "ResourceType": "AWS::IAM::Role", "PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler-role", "ResourceStatus": "CREATE_COMPLETE", "StackId": APP_STACK_ID, "StackName": APP_STACK_NAME},
                {"LogicalResourceId": "McpHandlerLogGroup", "ResourceType": "AWS::Logs::LogGroup", "PhysicalResourceId": "/aws/lambda/honda-mapit-mcp-dev-retained-handler", "ResourceStatus": "CREATE_COMPLETE", "StackId": APP_STACK_ID, "StackName": APP_STACK_NAME},
                {"LogicalResourceId": "McpHandler", "ResourceType": "AWS::Lambda::Function", "PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler", "ResourceStatus": "CREATE_COMPLETE", "StackId": APP_STACK_ID, "StackName": APP_STACK_NAME},
            ])
        return _ok(StackResources=[
            {"LogicalResourceId": logical, "ResourceType": kind, "PhysicalResourceId": _physical()[logical], "ResourceStatus": "CREATE_COMPLETE", "StackId": STACK_ID, "StackName": STACK_NAME}
            for logical, kind in {
                "ShutdownWorkflowRole": "AWS::IAM::Role", "ShutdownStateMachine": "AWS::StepFunctions::StateMachine",
                "RequestTripwireAlarm": "AWS::CloudWatch::Alarm", "RequestTripwireEventRole": "AWS::IAM::Role",
                "RequestTripwireAlarmRule": "AWS::Events::Rule",
            }.items()
        ])


class Iam:
    def get_role(self, *, RoleName):
        logical = "ShutdownWorkflowRole" if RoleName.endswith("shutdown-workflow") else "RequestTripwireEventRole"
        props = build_retained_dev_controls(API)["Resources"][logical]["Properties"]
        resolved = _resolve_internal_template(props, ACCOUNT)
        return _ok(Role={"RoleName": RoleName, "Arn": _service_arns()[logical], "AssumeRolePolicyDocument": resolved["AssumeRolePolicyDocument"], "Tags": resolved["Tags"]})

    def list_role_policies(self, *, RoleName):
        logical = "ShutdownWorkflowRole" if RoleName.endswith("shutdown-workflow") else "RequestTripwireEventRole"
        return _ok(PolicyNames=[build_retained_dev_controls(API)["Resources"][logical]["Properties"]["Policies"][0]["PolicyName"]], IsTruncated=False)

    def get_role_policy(self, *, RoleName, PolicyName):
        logical = "ShutdownWorkflowRole" if RoleName.endswith("shutdown-workflow") else "RequestTripwireEventRole"
        props = build_retained_dev_controls(API)["Resources"][logical]["Properties"]
        resolved = _resolve_internal_template(props, ACCOUNT)
        return _ok(PolicyDocument=resolved["Policies"][0]["PolicyDocument"])

    def list_attached_role_policies(self, *, RoleName):
        return _ok(AttachedPolicies=[], IsTruncated=False)


class Sfn:
    def describe_state_machine(self, **kwargs):
        props = build_retained_dev_controls(API)["Resources"]["ShutdownStateMachine"]["Properties"]
        return _ok(stateMachineArn=_service_arns()["ShutdownStateMachine"], name="honda-mapit-mcp-dev-retained-shutdown", status="ACTIVE", type="STANDARD", roleArn=_service_arns()["ShutdownWorkflowRole"], definition=props["DefinitionString"], loggingConfiguration={"level": "OFF", "includeExecutionData": False}, tracingConfiguration={"enabled": False})

    def list_tags_for_resource(self, **kwargs):
        return _ok(tags=build_retained_dev_controls(API)["Resources"]["ShutdownStateMachine"]["Properties"]["Tags"])


class Events:
    def describe_rule(self, **kwargs):
        props = build_retained_dev_controls(API)["Resources"]["RequestTripwireAlarmRule"]["Properties"]
        resolved = _resolve_internal_template(props, ACCOUNT)
        return _ok(Name="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule", Arn=_service_arns()["RequestTripwireAlarmRule"], State="DISABLED", EventPattern=json.dumps(resolved["EventPattern"], separators=(",", ":")))

    def list_targets_by_rule(self, **kwargs):
        props = build_retained_dev_controls(API)["Resources"]["RequestTripwireAlarmRule"]["Properties"]
        resolved = _resolve_internal_template(props, ACCOUNT)
        return _ok(Targets=[resolved["Targets"][0]], IsTruncated=False)

    def list_tags_for_resource(self, **kwargs):
        return _ok(Tags=build_retained_dev_controls(API)["Resources"]["RequestTripwireAlarmRule"]["Properties"]["Tags"])


class CloudWatch:
    def describe_alarms(self, **kwargs):
        props = build_retained_dev_controls(API)["Resources"]["RequestTripwireAlarm"]["Properties"]
        return _ok(MetricAlarms=[{
            "AlarmName": "honda-mapit-mcp-dev-retained-request-tripwire", "Namespace": "AWS/ApiGateway",
            "MetricName": "Count", "ActionsEnabled": False, "AlarmArn": _service_arns()["RequestTripwireAlarm"],
            "Period": 60, "Statistic": "SampleCount", "Threshold": 100, "ComparisonOperator": "GreaterThanOrEqualToThreshold", "EvaluationPeriods": 1, "DatapointsToAlarm": 1, "TreatMissingData": "notBreaching",
            "Dimensions": [{"Name": "ApiId", "Value": API}, {"Name": "Stage", "Value": "$default"}],
        }])

    def list_tags_for_resource(self, **kwargs):
        return _ok(Tags=build_retained_dev_controls(API)["Resources"]["RequestTripwireAlarm"]["Properties"]["Tags"])


def _clients(cfn=None, iam=None, sfn=None, events=None, cloudwatch=None, apigatewayv2=None, lambda_client=None):
    return {"sts": Sts(), "cloudformation": cfn or CloudFormation(), "iam": iam or Iam(), "sfn": sfn or Sfn(), "events": events or Events(), "cloudwatch": cloudwatch or CloudWatch(), "apigatewayv2": apigatewayv2 or ApiGateway(), "lambda": lambda_client or Lambda()}


def _coordinator(journal=None, *, clients=None, wall=lambda: 1_900_000_000, mono=lambda: 1.0):
    return RetainedDevControlsCoordinator(
        clients or _clients(),
        journal or Journal(), account_id=ACCOUNT, api_id=API, app_stack_id=APP_STACK_ID, source_sha=SOURCE, run_id=RUN_ID,
        expected_caller_arn=CALLER, authorized_from_epoch=1_899_999_000, authorized_until_epoch=1_900_002_000,
        wall_clock=wall, monotonic=mono,
    )


def _seed_preflight(c, journal):
    from scripts.aws_retained_dev_controls_bootstrap import _token
    journal.state = {
        "schema": 1, "kind": "retained-dev-controls", "account": ACCOUNT, "api_id": API, "app_stack_id": APP_STACK_ID, "source_sha": SOURCE,
        "run_id": RUN_ID, "template_sha256": c.template_sha256, "expected_caller_arn": CALLER,
        "authorized_from_epoch": 1_899_999_000, "authorized_until_epoch": 1_900_002_000,
        "last_observed_epoch": 1_900_000_000, "preflight": True, "intent": None, "acknowledged": False,
        "acknowledged_stack_id": None, "readback": False, "readback_receipt": None,
    }


def _readback_with(clients):
    journal = Journal(); cfn = clients["cloudformation"]
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal); c.run_step("create")
    return c.run_step("readback")


def test_factory_is_fixed_five_resource_shape():
    template = build_retained_dev_controls(API)
    assert set(template["Resources"]) == {"ShutdownWorkflowRole", "ShutdownStateMachine", "RequestTripwireAlarm", "RequestTripwireEventRole", "RequestTripwireAlarmRule"}
    assert template["Metadata"]["NoActivation"] is True
    assert all("Scheduler" not in key for key in template["Resources"])


def test_preflight_requires_exact_absence_and_does_not_write():
    journal = Journal()
    cfn = CloudFormation()
    c = _coordinator(journal, clients=_clients(cfn=cfn))
    result = c.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 9}
    assert journal.state["intent"] is None
    assert [name for name, _ in cfn.calls] == ["describe_stacks", "get_template", "describe_stack_resources", "describe_stacks"]


def test_create_saves_intent_and_never_replays():
    journal = Journal(); cfn = CloudFormation()
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal)
    assert c.run_step("create")["category"] == "create_acknowledged"
    assert [name for name, _ in cfn.calls].count("create_stack") == 1
    create_args = next(kwargs for name, kwargs in cfn.calls if name == "create_stack")
    assert create_args["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert c.run_step("create")["category"] == "create_intent_present"
    assert [name for name, _ in cfn.calls].count("create_stack") == 1


def test_readback_checks_all_control_surfaces():
    journal = Journal(); cfn = CloudFormation()
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal); c.run_step("create")
    result = c.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["readback_receipt"]["api_id"] == API
    assert result["calls"] == 27


def test_unknown_create_keeps_intent_and_readback_can_reconcile():
    journal = Journal(); cfn = CloudFormation()
    def ambiguous(**kwargs):
        cfn.created = True
        raise AwsError("InternalError", 500, "ambiguous")
    cfn.create_stack = ambiguous
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal)
    assert c.run_step("create")["category"] == "create_outcome_unknown"
    assert c.run_step("readback")["category"] == "readback_verified"
    assert journal.state["acknowledged"] is False
    assert journal.state["readback_receipt"]["token"]
    assert c.run_step("readback")["category"] == "readback_verified"


def test_wrong_disabled_rule_fails_closed():
    class BadEvents(Events):
        def describe_rule(self, **kwargs):
            return _ok(Name="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule", State="ENABLED")
    journal = Journal(); cfn = CloudFormation()
    clients = _clients(cfn=cfn, events=BadEvents())
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal); c.run_step("create")
    assert c.run_step("readback")["category"] == "stack_readback_mismatch"


def test_app_stack_identity_is_checked_before_control_create():
    class WrongApp(CloudFormation):
        def describe_stacks(self, **kwargs):
            if kwargs.get("StackName") == APP_STACK_ID:
                return _ok(Stacks=[{"StackId": APP_STACK_ID.replace("aaaaaaaa", "bbbbbbbb"), "StackName": APP_STACK_NAME, "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True}])
            return super().describe_stacks(**kwargs)
    journal = Journal(); cfn = WrongApp()
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients)
    assert c.run_step("preflight")["category"] == "binding_invalid"
    assert not any(name == "create_stack" for name, _ in cfn.calls)


def test_role_trust_policy_and_boundary_are_strict():
    class BadIam(Iam):
        def get_role(self, *, RoleName):
            reply = super().get_role(RoleName=RoleName)
            reply["Role"]["AssumeRolePolicyDocument"] = {"Version": "2012-10-17", "Statement": []}
            reply["Role"]["PermissionsBoundary"] = {"PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/unexpected"}
            return reply
    clients = _clients(iam=BadIam())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_inline_and_attached_role_policy_sets_are_strict():
    class BadIam(Iam):
        def list_role_policies(self, *, RoleName):
            return _ok(PolicyNames=["unexpected-policy"], IsTruncated=False)
        def list_attached_role_policies(self, *, RoleName):
            return _ok(AttachedPolicies=[{"PolicyArn": "arn:aws:iam::123456789012:policy/unexpected"}], IsTruncated=False)
    clients = _clients(iam=BadIam())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_state_machine_definition_and_role_are_strict():
    class BadSfn(Sfn):
        def describe_state_machine(self, **kwargs):
            reply = super().describe_state_machine(**kwargs)
            reply["roleArn"] = "arn:aws:iam::123456789012:role/unexpected"
            reply["definition"] = json.dumps({"StartAt": "unexpected"})
            return reply
    clients = _clients(sfn=BadSfn())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_event_pattern_and_target_are_strict():
    class BadEvents(Events):
        def describe_rule(self, **kwargs):
            reply = super().describe_rule(**kwargs)
            reply["EventPattern"] = "{}"
            return reply
        def list_targets_by_rule(self, **kwargs):
            reply = super().list_targets_by_rule(**kwargs)
            reply["Targets"][0]["RoleArn"] = "arn:aws:iam::123456789012:role/unexpected"
            return reply
    clients = _clients(events=BadEvents())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_unknown_template_intrinsic_fails_closed():
    with pytest.raises(RetainedDevControlsError, match="stack_readback_mismatch"):
        _resolve_internal_template({"Fn::Join": ["", ["unexpected"]]}, ACCOUNT)


def test_unmatched_substitution_token_fails_closed():
    with pytest.raises(RetainedDevControlsError, match="stack_readback_mismatch"):
        _resolve_internal_template({"Fn::Sub": "arn:${AWS::Region"}, ACCOUNT)


def test_alarm_shape_and_tags_are_strict():
    class BadCloudWatch(CloudWatch):
        def describe_alarms(self, **kwargs):
            reply = super().describe_alarms(**kwargs)
            reply["MetricAlarms"][0]["Threshold"] = 101
            return reply
        def list_tags_for_resource(self, **kwargs):
            return _ok(Tags=[])
    clients = _clients(cloudwatch=BadCloudWatch())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_resource_tags_are_order_insensitive_but_unique():
    class ReorderedIam(Iam):
        def get_role(self, *, RoleName):
            reply = super().get_role(RoleName=RoleName)
            reply["Role"]["Tags"] = list(reversed(reply["Role"]["Tags"]))
            return reply
    class ReorderedSfn(Sfn):
        def list_tags_for_resource(self, **kwargs):
            reply = super().list_tags_for_resource(**kwargs)
            reply["tags"] = list(reversed(reply["tags"]))
            return reply
    class ReorderedEvents(Events):
        def list_tags_for_resource(self, **kwargs):
            reply = super().list_tags_for_resource(**kwargs)
            reply["Tags"] = list(reversed(reply["Tags"]))
            return reply
    class ReorderedCloudWatch(CloudWatch):
        def list_tags_for_resource(self, **kwargs):
            reply = super().list_tags_for_resource(**kwargs)
            reply["Tags"] = list(reversed(reply["Tags"]))
            return reply
    clients = _clients(iam=ReorderedIam(), sfn=ReorderedSfn(), events=ReorderedEvents(), cloudwatch=ReorderedCloudWatch())
    assert _readback_with(clients)["category"] == "readback_verified"

    class DuplicateIam(Iam):
        def get_role(self, *, RoleName):
            reply = super().get_role(RoleName=RoleName)
            reply["Role"]["Tags"].append(dict(reply["Role"]["Tags"][0]))
            return reply
    clients["iam"] = DuplicateIam()
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_malformed_or_duplicate_encoded_iam_documents_fail_closed():
    class BadIam(Iam):
        def get_role(self, *, RoleName):
            reply = super().get_role(RoleName=RoleName)
            reply["Role"]["AssumeRolePolicyDocument"] = "%ZZ"
            return reply
    clients = _clients(iam=BadIam())
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"

    class DuplicateIam(Iam):
        def get_role(self, *, RoleName):
            reply = super().get_role(RoleName=RoleName)
            reply["Role"]["AssumeRolePolicyDocument"] = '{"Version":"2012-10-17","Version":"2012-10-17","Statement":[]}'
            return reply
    clients["iam"] = DuplicateIam()
    assert _readback_with(clients)["category"] == "stack_readback_mismatch"


def test_app_binding_is_revalidated_after_intent_save():
    class ChangesAfterPreflight(CloudFormation):
        def __init__(self):
            super().__init__(); self.app_reads = 0
        def describe_stack_resources(self, **kwargs):
            if kwargs.get("StackName") == APP_STACK_ID:
                self.app_reads += 1
                result = super().describe_stack_resources(**kwargs)
                if self.app_reads >= 2:
                    result["StackResources"][0]["PhysicalResourceId"] = "badapi0000"
                return result
            return super().describe_stack_resources(**kwargs)
    journal = Journal(); cfn = ChangesAfterPreflight()
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients)
    assert c.run_step("preflight")["ok"]
    result = c.run_step("create")
    assert result["category"] == "binding_invalid"
    assert journal.state["intent"] is not None
    assert not any(name == "create_stack" for name, _ in cfn.calls)


def test_drift_metadata_accepts_only_not_checked():
    journal = Journal(); cfn = CloudFormation()
    original = cfn.describe_stack_resources
    def with_drift(**kwargs):
        result = original(**kwargs)
        result["StackResources"][0]["DriftInformation"] = {"StackResourceDriftStatus": "NOT_CHECKED"}
        return result
    cfn.describe_stack_resources = with_drift
    clients = _clients(cfn=cfn)
    c = _coordinator(journal, clients=clients); _seed_preflight(c, journal); c.run_step("create")
    assert c.run_step("readback")["category"] == "readback_verified"


def test_invalid_api_id_rejected_before_factory():
    import pytest
    with pytest.raises(ValueError):
        _coordinator().__class__(_clients(), Journal(), account_id=ACCOUNT, api_id="../../bad", app_stack_id=APP_STACK_ID, source_sha=SOURCE, run_id=RUN_ID, expected_caller_arn=CALLER, authorized_from_epoch=1, authorized_until_epoch=2)
