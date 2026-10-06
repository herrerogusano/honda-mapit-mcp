"""Injected, read-only binding discovery for the closed retained-dev scaffold.

No SDK construction, persistence, credential discovery or write operations.
Bindings are private inputs to later reviewed operators, not log output.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time
from typing import Any, Callable, Mapping

from scripts.aws_retained_dev_bootstrap import (
    FUNCTION_NAME, LOG_GROUP_NAME, REGION, ROLE_NAME, STACK_NAME,
    _canonical, _strict_mapping,
)
from scripts.build_aws_retained_dev import build_retained_dev_template


class RetainedDevBindingError(ValueError):
    def __init__(self) -> None:
        super().__init__("retained_dev_binding_unverified")


@dataclass(frozen=True, repr=False)
class RetainedDevBinding:
    account: str
    stack_id: str
    api_id: str
    execution_role_arn: str

    def __repr__(self) -> str:
        return "RetainedDevBinding(private=True)"


def read_bootstrap_resource_binding(
    clients: Mapping[str, Any], *, account: str, caller_arn: str,
    stack_id: str, creation_run_id: int,
    monotonic: Callable[[], float] = time.monotonic,
) -> RetainedDevBinding:
    """Four single-attempt reads; reject drift, pagination and late results.

    The caller supplies already configured direct TLS clients. This proof is
    limited to the exact original CloudFormation scaffold and resource IDs.
    It does not establish current runtime closure (out-of-band drift is possible),
    verify deployed code or authorize activation. Later operators must perform
    their own full runtime/control readbacks before any action.
    """
    try:
        if (
            type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None
            or type(creation_run_id) is not int or creation_run_id <= 0
            or type(caller_arn) is not str
            or re.fullmatch(
                rf"arn:aws:(?:iam|sts)::{account}:(?:user|role)/[^\s:/]+|"
                rf"arn:aws:sts::{account}:assumed-role/[^\s:/]+/[^\s:/]+", caller_arn,
            ) is None
            or type(stack_id) is not str
            or re.fullmatch(
                rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK_NAME}/"
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", stack_id,
            ) is None
            or not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation"}
        ):
            raise RetainedDevBindingError()
        start = monotonic()
        if type(start) not in (int, float) or not math.isfinite(start):
            raise RetainedDevBindingError()
        last = start

        def call(service: str, operation: str, **kwargs: Any) -> Mapping[str, Any]:
            nonlocal last
            for before in (True, False):
                now = monotonic()
                if type(now) not in (int, float) or not math.isfinite(now) or now < last or now - start >= 30:
                    raise RetainedDevBindingError()
                last = now
                if before:
                    reply = getattr(clients[service], operation)(**kwargs)
            if (
                not isinstance(reply, Mapping)
                or not isinstance(reply.get("ResponseMetadata"), Mapping)
                or type(reply["ResponseMetadata"].get("HTTPStatusCode")) is not int
                or reply["ResponseMetadata"]["HTTPStatusCode"] != 200
                or any(key in reply for key in ("NextToken", "NextMarker", "Marker"))
            ):
                raise RetainedDevBindingError()
            return reply

        identity = call("sts", "get_caller_identity")
        if identity.get("Account") != account or identity.get("Arn") != caller_arn:
            raise RetainedDevBindingError()
        stacks = call("cloudformation", "describe_stacks", StackName=stack_id).get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevBindingError()
        stack = stacks[0]
        expected_tags = {
            "Project": "honda-mapit-mcp", "Environment": "dev",
            "Purpose": "retained-dev", "OperatorRunId": str(creation_run_id),
        }
        tags = stack.get("Tags")
        if type(tags) is not list or len(tags) != len(expected_tags):
            raise RetainedDevBindingError()
        actual_tags = {}
        for tag in tags:
            if not isinstance(tag, Mapping) or type(tag.get("Key")) is not str or tag["Key"] in actual_tags:
                raise RetainedDevBindingError()
            actual_tags[tag["Key"]] = tag.get("Value")
        if (
            stack.get("StackId") != stack_id or stack.get("StackName") != STACK_NAME
            or stack.get("StackStatus") != "CREATE_COMPLETE"
            or stack.get("EnableTerminationProtection") is not True
            or stack.get("RoleARN") not in (None, "") or actual_tags != expected_tags
        ):
            raise RetainedDevBindingError()
        template = call("cloudformation", "get_template", StackName=stack_id, TemplateStage="Original")
        actual = _strict_mapping(template.get("TemplateBody"))
        if actual is None or _canonical(actual) != _canonical(build_retained_dev_template()):
            raise RetainedDevBindingError()
        rows = call("cloudformation", "describe_stack_resources", StackName=stack_id).get("StackResources")
        expected = {
            "McpApi": ("AWS::ApiGatewayV2::Api", None),
            "McpApiStage": ("AWS::ApiGatewayV2::Stage", "$default"),
            "McpHandlerRole": ("AWS::IAM::Role", ROLE_NAME),
            "McpHandlerLogGroup": ("AWS::Logs::LogGroup", LOG_GROUP_NAME),
            "McpHandler": ("AWS::Lambda::Function", FUNCTION_NAME),
        }
        if type(rows) is not list or len(rows) != len(expected):
            raise RetainedDevBindingError()
        physical = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise RetainedDevBindingError()
            logical = row.get("LogicalResourceId")
            if type(logical) is not str or logical not in expected or logical in physical:
                raise RetainedDevBindingError()
            kind, name = expected[logical]
            value = row.get("PhysicalResourceId")
            if (
                row.get("ResourceType") != kind or row.get("ResourceStatus") != "CREATE_COMPLETE"
                or row.get("StackId") != stack_id or row.get("StackName") != STACK_NAME
                or type(value) is not str or (name is not None and value != name)
            ):
                raise RetainedDevBindingError()
            physical[logical] = value
        api_id = physical["McpApi"]
        if re.fullmatch(r"[a-z0-9]{10}", api_id) is None:
            raise RetainedDevBindingError()
        return RetainedDevBinding(account, stack_id, api_id, f"arn:aws:iam::{account}:role/{ROLE_NAME}")
    except RetainedDevBindingError:
        raise
    except Exception:
        raise RetainedDevBindingError() from None
