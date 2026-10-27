"""Independent read-only contract tests for DEV identity-binding runtime evidence."""

import base64
import json
from pathlib import Path

import pytest

import scripts.dev_identity_binding_runtime_evidence as evidence
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap


ACCOUNT = "123456789012"
SSM_KEY_ARN = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"
APP = "honda-mapit-mcp-dev-retained"
FUNCTION = "honda-mapit-mcp-dev-retained-handler"
ROLE = "honda-mapit-mcp-dev-retained-handler-role"
STACK_ARN = (f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{APP}/"
             "12345678-1234-1234-1234-123456789abc")
CODE_SHA = "a" * 64
API_ID = "abcdefghij"
OPERATOR_ARN = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
TENANT_KEYS = ("tenant-" + "1" * 64, "tenant-" + "2" * 64)
HISTORICAL_KEYS = ("tenant-" + "3" * 64, "tenant-" + "4" * 64)


def _reply(**values):
    return {"ResponseMetadata": {"HTTPStatusCode": 200}, **values}


def _template(*, observed_api_ref=None):
    resources = {f"Other{i}": {"Type": "Synthetic::Resource"} for i in range(16)}
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    policies = [
        {"PolicyName": "honda-mapit-mcp-dev-retained-owned-log-writes",
         "PolicyDocument": {"Version": "2012-10-17", "Statement": []}},
        {"PolicyName": "honda-mapit-mcp-dev-retained-tenant-read",
         "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
             "Effect": "Allow", "Action": "dynamodb:GetItem",
             "Resource": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
             "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(HISTORICAL_KEYS)}},
         }]}}
    ]
    resources["McpHandlerRole"] = {"Type": "AWS::IAM::Role", "Properties": {
        "AssumeRolePolicyDocument": trust, "Policies": policies,
    }}
    resources["McpTenantsTable"] = {"Type": "AWS::DynamoDB::Table", "Properties": {}}
    resources["McpHandler"] = {"Type": "AWS::Lambda::Function", "Properties": {
        "Runtime": "python3.13", "Handler": "mapit.aws_entrypoint.handler",
        "Architectures": ["arm64"], "MemorySize": 256, "Timeout": 14,
        "Environment": {"Variables": {"MAPIT_ENVIRONMENT": "dev"}},
        "Role": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}",
        "Code": {"S3Key": f"runtime/{CODE_SHA}.zip"},
    }}
    if observed_api_ref is not None:
        resources["McpHandler"]["Properties"]["Environment"]["Variables"]["OBSERVED_API_ID"] = {
            "Ref": observed_api_ref,
        }
    return {"Resources": resources}


class _Service:
    def __init__(self, service, handlers, calls):
        self.service = service
        self.handlers = handlers
        self.calls = calls

    def __getattr__(self, operation):
        if operation not in self.handlers:
            raise AssertionError(f"unexpected read operation {self.service}.{operation}")

        def invoke(**kwargs):
            self.calls.append((self.service, operation, kwargs))
            return self.handlers[operation](**kwargs)

        return invoke


def _fixture(monkeypatch, *, resource_count=19, quota=(10, 10), policy_names=None,
             extra_policy=None, include_expected_add=False, response_mutator=None,
             observed_api_ref=None, observed_api_resource_id=API_ID, observed_config_api_id=API_ID):
    template = _template(observed_api_ref=observed_api_ref)
    template_sha = evidence._digest(template)
    policies = {row["PolicyName"]: row["PolicyDocument"]
                for row in template["Resources"]["McpHandlerRole"]["Properties"]["Policies"]}
    baseline_policies = dict(policies)
    expected_bootstrap = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=OPERATOR_ARN, tenant_keys=TENANT_KEYS,
        ssm_key_arn=SSM_KEY_ARN,
    )["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
    if include_expected_add:
        extra_policy = (expected_bootstrap["PolicyName"], expected_bootstrap["PolicyDocument"])
    names = list(policy_names or policies)
    if extra_policy is not None:
        extra_name, extra_doc = extra_policy
        policies[extra_name] = extra_doc
        if extra_name not in names:
            names.append(extra_name)

    calls = []
    trust = template["Resources"]["McpHandlerRole"]["Properties"]["AssumeRolePolicyDocument"]
    attached = {name: doc for name, doc in policies.items()}

    handlers = {
        "cloudformation": {
            "get_template": lambda **kw: _reply(TemplateBody=template),
            "list_stack_resources": lambda **kw: _reply(StackResourceSummaries=[
                *[{"LogicalResourceId": f"R{i}"} for i in range(max(0, resource_count - 1))],
                {"LogicalResourceId": "McpApi", "PhysicalResourceId": observed_api_resource_id},
            ]),
        },
        "apigatewayv2": {"get_api": lambda **kw: _reply(ApiId=API_ID)},
        "cognito": {},
        "dynamodb": {},
        "lambda": {
            "get_function_configuration": lambda **kw: _reply(
                Runtime="python3.13", Handler="mapit.aws_entrypoint.handler", Architectures=["arm64"],
                MemorySize=256, Timeout=14, Environment={"Variables": {
                    "MAPIT_ENVIRONMENT": "dev",
                    **({"OBSERVED_API_ID": observed_config_api_id} if observed_api_ref is not None else {}),
                }},
                Role=f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", State="Active", LastUpdateStatus="Successful",
                CodeSha256=base64.b64encode(bytes.fromhex(CODE_SHA)).decode("ascii"),
                FunctionArn=f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:{FUNCTION}",
            ),
            "get_function_concurrency": lambda **kw: _reply(ReservedConcurrentExecutions=0),
            "get_account_settings": lambda **kw: _reply(AccountLimit={
                "ConcurrentExecutions": quota[0], "UnreservedConcurrentExecutions": quota[1],
            }),
        },
        "iam": {
            "get_role": lambda **kw: _reply(Role={
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}", "PermissionsBoundary": None,
                "AssumeRolePolicyDocument": trust,
            }),
            "list_role_policies": lambda **kw: _reply(PolicyNames=names),
            "get_role_policy": lambda **kw: _reply(RoleName=ROLE, PolicyName=kw["PolicyName"],
                                                   PolicyDocument=attached[kw["PolicyName"]]),
            "list_attached_role_policies": lambda **kw: _reply(AttachedPolicies=[]),
        },
    }
    clients = {service: _Service(service, rows, calls) for service, rows in handlers.items()}
    journal = {"phase": "accepted", "binding": {
        "operation": "dev_multiuser_closed_update", "account": ACCOUNT,
        "stack": STACK_ARN, "target": template_sha,
    }}
    monkeypatch.setattr(evidence, "validate_private_location", lambda path: Path(path))
    monkeypatch.setattr(evidence, "FileJournal", lambda path: type("J", (), {"load": lambda self: journal})())
    monkeypatch.setattr(evidence, "verify_closed_setup", lambda supplied, **kw: (
        supplied["apigateway"].get_api(ApiId=API_ID) and {"success": True}
    ))
    monkeypatch.setattr(evidence, "_verify_multiuser_runtime_children", lambda *a, **kw: None)

    binding = {
        "account_id": ACCOUNT,
        "handler_role_arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE}",
        "accepted_runtime_journal_path": "synthetic-private-journal",
        "app_stack_arn": STACK_ARN,
        "template_sha256": template_sha,
        "api_id": API_ID,
        "user_pool_id": "eu-west-1_Synthetic",
        "client_id": "SyntheticClient012345",
        "app_run_id": 1234,
        "code_sha256": CODE_SHA,
        "handler_trust_sha256": evidence._digest(trust),
        "handler_policies_sha256": evidence._digest(baseline_policies),
        "ssm_key_arn": SSM_KEY_ARN,
        "operator_user_arn": OPERATOR_ARN,
        "tenant_keys": TENANT_KEYS,
    }
    if extra_policy is not None:
        binding["added_runtime_policy"] = {"policy_name": extra_policy[0], "policy_document": extra_policy[1]}
    if response_mutator is not None:
        response_mutator(handlers)
    return clients, binding, calls


def test_exact_accepted_runtime_evidence_is_readonly_and_redacted(monkeypatch):
    clients, binding, calls = _fixture(monkeypatch)
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is True, (result, calls)
    assert result["resource_count"] == 19
    assert result["api_closed"] is True and result["reserve_zero"] is True
    assert result["calls"] == len(calls) <= 48
    assert {operation for _, operation, _ in calls} <= {
        "get_template", "get_api", "list_stack_resources", "get_function_configuration",
        "get_function_concurrency", "get_account_settings", "get_role", "list_role_policies",
        "get_role_policy", "list_attached_role_policies",
    }
    assert "synthetic-private-journal" not in json.dumps(result)


def test_observed_api_id_reference_resolves_from_exact_cloudformation_api_resource(monkeypatch):
    clients, binding, _ = _fixture(
        monkeypatch, observed_api_ref="ObservedApiId",
        observed_api_resource_id=API_ID, observed_config_api_id=API_ID,
    )
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is True


def test_unknown_environment_reference_fails_closed(monkeypatch):
    clients, binding, _ = _fixture(
        monkeypatch, observed_api_ref="UnreviewedApiId",
        observed_api_resource_id=API_ID, observed_config_api_id=API_ID,
    )
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is False
    assert result["category"] == "accepted_runtime_unverified"


def test_observed_api_id_must_match_resolved_physical_api_id(monkeypatch):
    clients, binding, _ = _fixture(
        monkeypatch, observed_api_ref="ObservedApiId",
        observed_api_resource_id="wrongapi123", observed_config_api_id=API_ID,
    )
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is False
    assert result["category"] == "accepted_runtime_unverified"


@pytest.mark.parametrize("resource_count", [18, 20])
def test_wrong_resource_count_is_not_accepted(monkeypatch, resource_count):
    clients, binding, _ = _fixture(monkeypatch, resource_count=resource_count)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


@pytest.mark.parametrize("quota", [(10.0, 10), (10, 10.0), (True, 10), (10, False)])
def test_quota_shape_requires_exact_sdk_integers(monkeypatch, quota):
    clients, binding, _ = _fixture(monkeypatch, quota=quota)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_readonly_wrapper_rejects_malformed_pagination_flags(monkeypatch):
    def mutate(handlers):
        handlers["cloudformation"]["get_template"] = lambda **kw: _reply(TemplateBody=_template(), IsTruncated=0)

    clients, binding, _ = _fixture(monkeypatch, response_mutator=mutate)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_readonly_wrapper_rejects_nonempty_pagination_token(monkeypatch):
    def mutate(handlers):
        handlers["lambda"]["get_function_concurrency"] = lambda **kw: _reply(
            ReservedConcurrentExecutions=0, NextToken="unexpected-page",
        )

    clients, binding, _ = _fixture(monkeypatch, response_mutator=mutate)
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is False
    assert "unexpected-page" not in json.dumps(result)


@pytest.mark.parametrize("case", ["handler", "code"])
def test_lambda_code_or_handler_drift_is_rejected(monkeypatch, case):
    def mutate(handlers):
        original = handlers["lambda"]["get_function_configuration"]

        def changed(**kwargs):
            response = original(**kwargs)
            response["Handler" if case == "handler" else "CodeSha256"] = (
                "other.handler" if case == "handler" else "different-code-digest"
            )
            return response

        handlers["lambda"]["get_function_configuration"] = changed

    clients, binding, _ = _fixture(monkeypatch, response_mutator=mutate)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_baseline_role_policy_drift_is_rejected(monkeypatch):
    def mutate(handlers):
        original = handlers["iam"]["get_role_policy"]

        def changed(**kwargs):
            response = original(**kwargs)
            if kwargs["PolicyName"] == "honda-mapit-mcp-dev-retained-tenant-read":
                response["PolicyDocument"] = {"Version": "2012-10-17", "Statement": [
                    {"Effect": "Allow", "Action": "dynamodb:Scan", "Resource": "*"},
                ]}
            return response

        handlers["iam"]["get_role_policy"] = changed

    clients, binding, _ = _fixture(monkeypatch, response_mutator=mutate)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_attached_policy_drift_is_rejected(monkeypatch):
    def mutate(handlers):
        handlers["iam"]["list_attached_role_policies"] = lambda **kw: _reply(
            AttachedPolicies=[{"PolicyName": "unreviewed", "PolicyArn": "arn:aws:iam::123456789012:policy/unreviewed"}],
        )

    clients, binding, _ = _fixture(monkeypatch, response_mutator=mutate)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_private_journal_binding_mismatch_fails_before_reads(monkeypatch):
    clients, binding, calls = _fixture(monkeypatch)
    binding["template_sha256"] = "b" * 64
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is False
    assert calls == []


def test_readonly_facade_blocks_write_operation(monkeypatch):
    clients, binding, calls = _fixture(monkeypatch)

    def attempt_write(supplied, **kwargs):
        supplied["dynamodb"].put_item(TableName="synthetic", Item={})
        return {"success": True}

    monkeypatch.setattr(evidence, "verify_closed_setup", attempt_write)
    result = evidence.verify_accepted_runtime(clients, binding)
    assert result["verified"] is False
    assert all(not operation.startswith(("put_", "update_", "delete_", "create_"))
               for _, operation, _ in calls)


def test_added_runtime_policy_must_be_exact_reviewed_attachment(monkeypatch):
    added = ("unexpected-permissions", {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "iam:*", "Resource": "*"},
    ]})
    clients, binding, _ = _fixture(monkeypatch, extra_policy=added)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is False


def test_factory_exact_added_runtime_policy_is_accepted(monkeypatch):
    clients, binding, _ = _fixture(monkeypatch, include_expected_add=True)
    assert evidence.verify_accepted_runtime(clients, binding)["verified"] is True
