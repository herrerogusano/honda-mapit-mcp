"""Independent synthetic integration check for recurrent IAM update wiring."""
from __future__ import annotations

import time

from scripts import run_dev_multiuser_runtime_update as runtime
from tests.test_run_dev_multiuser_closed_update import BINDINGS, CALLER, ROLES_STACK, APP_STACK


POOL = "eu-west-1_ABCDEFGHI"
TOKEN = "dev-multiuser-" + "c" * 32


class _Journal:
    def __init__(self):
        self.state = None

    class _Lock:
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    def locked(self): return self._Lock()
    def load(self): return self.state
    def save(self, value): self.state = value


class _STS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": CALLER}


class _Lambda:
    def get_function_concurrency(self, *, FunctionName):
        assert FunctionName == "honda-mapit-mcp-dev-retained-handler"
        return {"ReservedConcurrentExecutions": 0}


class _API:
    def get_api(self, *, ApiId):
        assert ApiId == "a1b2c3d4e5"
        return {"ApiId": ApiId, "DisableExecuteApiEndpoint": True}


class _CloudFormation:
    def __init__(self, bootstrap, recurrent):
        self.bootstrap = bootstrap
        self.recurrent = recurrent
        self.status = "CREATE_COMPLETE"
        self.updated = False
        self.update_requests = []

    def describe_stacks(self, *, StackName):
        if StackName == ROLES_STACK:
            return {"Stacks": [{
                "StackId": ROLES_STACK,
                "StackName": "honda-mapit-mcp-dev-retained-cd-delivery",
                "StackStatus": self.status,
                "RoleARN": None,
                "Tags": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "dev"},
                ],
            }]}
        raise AssertionError("unexpected stack lookup")

    def describe_stack_resources(self, *, StackName):
        assert StackName == "honda-mapit-mcp-dev-retained"
        return {"StackResources": [{
            "LogicalResourceId": "McpApi",
            "ResourceType": "AWS::ApiGatewayV2::Api",
            "PhysicalResourceId": "a1b2c3d4e5",
        }]}

    def get_template(self, *, StackName, TemplateStage):
        assert StackName == ROLES_STACK
        assert TemplateStage == "Original"
        return {"TemplateBody": self.recurrent if self.updated else self.bootstrap}

    def update_stack(self, **kwargs):
        self.update_requests.append(kwargs)
        return {"StackId": ROLES_STACK}

    def describe_stack_events(self, *, StackName):
        assert StackName == ROLES_STACK
        return {"StackEvents": [{
            "PhysicalResourceId": ROLES_STACK,
            "ResourceType": "AWS::CloudFormation::Stack",
            "ResourceStatus": "UPDATE_COMPLETE",
            "ClientRequestToken": TOKEN,
        }]}


def test_recurrent_core_happy_path_uses_closed_stack_and_one_update_request():
    bootstrap = runtime.build_cd_retained_dev_multiuser_roles(
        **dict(BINDINGS), observed_user_pool_id=None,
    )
    recurrent = runtime.build_recurrent_iam_template(
        BINDINGS, observed_user_pool_id=POOL,
    )
    cfn = _CloudFormation(bootstrap, recurrent)
    clients = {"sts": _STS(), "cloudformation": cfn,
               "lambda": _Lambda(), "apigatewayv2": _API()}
    journal = _Journal()
    start = int(time.time()) - 1
    end = start + 300
    args = dict(
        account_id="123456789012", stack_arn=ROLES_STACK, caller_arn=CALLER,
        source_sha="1" * 40, run_token=TOKEN, role_bindings=BINDINGS,
        observed_user_pool_id=POOL, authorized_from_epoch=start,
        authorized_until_epoch=end,
    )

    ready = runtime.run_recurrent_iam_step(clients, journal, step="preflight", **args)
    assert ready == {"success": True, "category": "preflight_verified"}
    assert journal.state["phase"] == "ready"

    acknowledged = runtime.run_recurrent_iam_step(clients, journal, step="request-update", **args)
    assert acknowledged == {"success": True, "category": "update_acknowledged"}
    assert len(cfn.update_requests) == 1
    request = cfn.update_requests[0]
    assert request["StackName"] == ROLES_STACK
    assert request["ClientRequestToken"] == TOKEN
    assert request["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert "RoleARN" not in request

    cfn.updated = True
    cfn.status = "UPDATE_COMPLETE"
    accepted = runtime.run_recurrent_iam_step(clients, journal, step="check-update", **args)
    assert accepted == {"success": True, "category": "readback_verified"}
    assert journal.state["phase"] == "accepted"
    assert len(cfn.update_requests) == 1
