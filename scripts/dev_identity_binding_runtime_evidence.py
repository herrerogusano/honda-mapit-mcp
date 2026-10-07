"""Read-only closure evidence for the separate DEV enrollment bootstrap."""
from __future__ import annotations

import base64
import hashlib
import json
import math
from pathlib import Path
import re
import time

from scripts.dev_multiuser_closed_update import _digest
from scripts.dev_multiuser_readback import verify_closed_setup
from scripts.run_dev_multiuser_runtime_update import CasFileJournal as FileJournal
from scripts.run_aws_retained_dev_bootstrap import validate_private_location
from scripts.run_dev_multiuser_accepted_continuation import _verify_multiuser_runtime_children
from scripts.run_dev_multiuser_hosted_acceptance import CALLBACK_URL
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap

FUNCTION = "honda-mapit-mcp-dev-retained-handler"
ROLE = "honda-mapit-mcp-dev-retained-handler-role"


def _resolve_context(node, *, account, resource_rows):
    if type(node) is list:
        return [_resolve_context(value, account=account, resource_rows=resource_rows) for value in node]
    if isinstance(node, dict):
        replacements = {"AWS::Partition": "aws", "AWS::Region": "eu-west-1", "AWS::AccountId": account}
        if set(node) == {"Ref"}:
            name = node["Ref"]
            if name in replacements:
                return replacements[name]
            if name in {"McpApi", "McpUserPool", "McpUserPoolClient"}:
                return resource_rows[name]["PhysicalResourceId"]
            if name == "ObservedApiId":
                return resource_rows["McpApi"]["PhysicalResourceId"]
            raise ValueError
        if set(node) == {"Fn::Sub"}:
            value = node["Fn::Sub"]
            if type(value) is not str:
                raise ValueError
            for name, text in replacements.items():
                value = value.replace("${" + name + "}", text)
            if "${" in value:
                raise ValueError
            return value
        if set(node) == {"Fn::GetAtt"} and node["Fn::GetAtt"] == ["McpTenantsTable", "Arn"]:
            return f"arn:aws:dynamodb:eu-west-1:{account}:table/honda-mapit-mcp-dev-tenants"
        if any(name == "Ref" or name.startswith("Fn::") for name in node):
            raise ValueError
        return {name: _resolve_context(value, account=account, resource_rows=resource_rows)
                for name, value in node.items()}
    return node


def verify_accepted_runtime(clients, binding):
    """Bind fresh reads to consumed historical evidence, never resume that journal.

    Expected fingerprints are private reviewed inputs, not caller-selected CLI
    flags. The new attachment is allowed only on post-create verification and
    only if its complete policy document matches independently reviewed input.
    """
    calls = 0
    stage = "journal"
    started = time.monotonic()
    if type(started) not in (int, float) or not math.isfinite(started):
        return {"verified": False, "calls": 0, "category": "accepted_runtime_unverified"}
    last = started
    def check():
        nonlocal last
        now = time.monotonic()
        if type(now) not in (int, float) or not math.isfinite(now) or now < last or now - started >= 60:
            raise ValueError
        last = now
    class ReadOnly:
        def __init__(self, service):
            self.service = service
        def __getattr__(self, operation):
            if not operation.startswith(("get_", "describe_", "list_")):
                raise ValueError
            def read(**kwargs):
                nonlocal calls
                check()
                if calls >= 48:
                    raise ValueError
                calls += 1
                reply = getattr(clients[self.service], operation)(**kwargs)
                check()
                if (type(reply) is not dict
                        or type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                        or reply["ResponseMetadata"]["HTTPStatusCode"] != 200
                        or any(reply.get(k) not in (None, "") for k in ("NextToken", "NextMarker", "Marker"))
                        or "IsTruncated" in reply and (type(reply["IsTruncated"]) is not bool or reply["IsTruncated"])):
                    raise ValueError
                return reply
            return read
    try:
        account = binding["account_id"]
        if type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None or account == "0" * 12:
            raise ValueError
        expected_role = f"arn:aws:iam::{account}:role/{ROLE}"
        if binding["handler_role_arn"] != expected_role:
            raise ValueError
        path = validate_private_location(Path(binding["accepted_runtime_journal_path"]))
        journal = FileJournal(path).load()
        prior = journal["binding"]
        if (journal.get("phase") != "accepted" or prior.get("operation") != "dev_multiuser_closed_update"
                or prior.get("account") != account or prior.get("stack") != binding["app_stack_arn"]
                or prior.get("target") != binding["template_sha256"]):
            raise ValueError
        readers = {key: ReadOnly(key) for key in clients}
        stage = "template"
        body = readers["cloudformation"].get_template(StackName=binding["app_stack_arn"],
            TemplateStage="Original")["TemplateBody"]
        template = json.loads(body) if type(body) is str else json.loads(json.dumps(body, allow_nan=False))
        if type(template) is not dict or _digest(template) != prior["target"] or len(template["Resources"]) != 19:
            raise ValueError
        stage = "setup"
        result = verify_closed_setup({"cloudformation": readers["cloudformation"],
            "cognito": readers["cognito"], "apigateway": readers["apigatewayv2"],
            "dynamodb": readers["dynamodb"]}, account=account, stack_arn=binding["app_stack_arn"],
            api_id=binding["api_id"], user_pool_id=binding["user_pool_id"], client_id=binding["client_id"],
            callback_url=CALLBACK_URL, original_creation_run_id=binding["app_run_id"],
            expected_runtime_template=template,
            expected_route_keys=("POST /mcp", "GET /.well-known/oauth-protected-resource/mcp",
                                 "GET /.well-known/oauth-authorization-server"))
        if result.get("success") is not True:
            raise ValueError
        stage = "children"
        rows = readers["cloudformation"].list_stack_resources(StackName=binding["app_stack_arn"])["StackResourceSummaries"]
        by_name = {row["LogicalResourceId"]: row for row in rows}
        if len(rows) != 19 or len(by_name) != 19:
            raise ValueError
        _verify_multiuser_runtime_children(readers, template, by_name, account=account, api_id=binding["api_id"])
        stage = "function"
        props = template["Resources"]["McpHandler"]["Properties"]
        key = props["Code"]["S3Key"]
        expected_code = binding["code_sha256"]
        if re.fullmatch(r"[0-9a-f]{64}", expected_code) is None or key != f"runtime/{expected_code}.zip":
            raise ValueError
        config = readers["lambda"].get_function_configuration(FunctionName=FUNCTION)
        for field in ("Runtime", "Handler", "Architectures", "MemorySize", "Timeout", "Environment"):
            if config.get(field) != _resolve_context(props[field], account=account, resource_rows=by_name):
                raise ValueError
        if (config.get("Role") != expected_role or config.get("State") != "Active"
                or config.get("LastUpdateStatus") != "Successful"
                or config.get("CodeSha256") != base64.b64encode(bytes.fromhex(expected_code)).decode("ascii")
                or config.get("FunctionArn") != f"arn:aws:lambda:eu-west-1:{account}:function:{FUNCTION}"):
            raise ValueError
        reserve = readers["lambda"].get_function_concurrency(FunctionName=FUNCTION)
        if type(reserve.get("ReservedConcurrentExecutions")) is not int or reserve["ReservedConcurrentExecutions"] != 0:
            raise ValueError
        quota = readers["lambda"].get_account_settings()["AccountLimit"]
        if any(type(quota.get(k)) is not int or quota[k] != 10
               for k in ("ConcurrentExecutions", "UnreservedConcurrentExecutions")):
            raise ValueError
        stage = "role"
        role = readers["iam"].get_role(RoleName=ROLE)["Role"]
        if role.get("Arn") != expected_role or role.get("PermissionsBoundary") is not None:
            raise ValueError
        trust_digest = _digest(role["AssumeRolePolicyDocument"])
        names = readers["iam"].list_role_policies(RoleName=ROLE)["PolicyNames"]
        if type(names) is not list or len(set(names)) != len(names) or not 2 <= len(names) <= 3:
            raise ValueError
        policies = {}
        for name in names:
            document = readers["iam"].get_role_policy(RoleName=ROLE, PolicyName=name)
            if document.get("RoleName") != ROLE or document.get("PolicyName") != name:
                raise ValueError
            policies[name] = document["PolicyDocument"]
        added = binding.get("added_runtime_policy")
        if added is not None:
            expected = build_dev_identity_binding_bootstrap(account_id=account,
                operator_user_arn=binding["operator_user_arn"], tenant_keys=tuple(binding["tenant_keys"]),
                ssm_key_arn=binding["ssm_key_arn"])[
                    "Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
            if type(added) is not dict or added != {"policy_name": expected["PolicyName"],
                                                   "policy_document": expected["PolicyDocument"]}:
                raise ValueError
            if policies.pop(added["policy_name"], None) != added["policy_document"]:
                raise ValueError
        if set(policies) != {"honda-mapit-mcp-dev-retained-owned-log-writes", "honda-mapit-mcp-dev-retained-tenant-read"}:
            raise ValueError
        expected_policies = {item["PolicyName"]: _resolve_context(item["PolicyDocument"], account=account, resource_rows=by_name)
            for item in template["Resources"]["McpHandlerRole"]["Properties"]["Policies"]}
        if (policies != expected_policies or role["AssumeRolePolicyDocument"] !=
                template["Resources"]["McpHandlerRole"]["Properties"]["AssumeRolePolicyDocument"]):
            raise ValueError
        historical_keys = set()
        for statement in policies["honda-mapit-mcp-dev-retained-tenant-read"]["Statement"]:
            historical_keys.update(statement.get("Condition", {}).get("ForAllValues:StringEquals", {}).get(
                "dynamodb:LeadingKeys", []))
        fresh_keys = binding["tenant_keys"]
        if len(historical_keys) != 2 or len(set(fresh_keys)) != 2 or historical_keys.intersection(fresh_keys):
            raise ValueError
        if readers["iam"].list_attached_role_policies(RoleName=ROLE)["AttachedPolicies"] != []:
            raise ValueError
        policy_digest = _digest(policies)
        if trust_digest != binding["handler_trust_sha256"] or policy_digest != binding["handler_policies_sha256"]:
            raise ValueError
        check()
        return {"verified": True, "calls": calls, **{key: binding[key] for key in (
            "app_stack_arn", "app_run_id", "api_id", "template_sha256", "code_sha256", "handler_role_arn")},
            "handler_trust_sha256": trust_digest, "handler_policies_sha256": policy_digest,
            "resource_count": 19, "api_closed": True, "reserve_zero": True}
    except Exception:
        return {"verified": False, "calls": calls, "category": "accepted_runtime_unverified", "stage": stage}
