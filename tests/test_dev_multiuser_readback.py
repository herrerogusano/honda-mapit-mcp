from __future__ import annotations

import copy
import hashlib

from scripts.build_cd_retained_dev_multiuser_roles import build_cd_retained_dev_multiuser_roles
from scripts.dev_multiuser_readback import verify_role_pair

ACCOUNT = "123456789012"
RUN_ID = 2026100601
ROLES_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666"
APP_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/33333333-4444-4555-8666-777777777777"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
API = "arn:aws:apigateway:eu-west-1::/apis/abcdefghij"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
BUCKET = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
EXECUTION = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _template():
    subject = "repo:herrerogusano/honda-mapit-mcp:environment:dev"
    return build_cd_retained_dev_multiuser_roles(
        account_id=ACCOUNT, provider_arn=PROVIDER, owner_id="123", repository_id="456",
        observed_dev_subject_format="legacy_environment",
        observed_dev_subject_sha256=hashlib.sha256(subject.encode()).hexdigest(),
        stack_arn=APP_STACK, artifact_stack_arn=ARTIFACT_STACK, handler_arn=HANDLER,
        api_arn=API, shutdown_state_machine_arn=SHUTDOWN, artifact_bucket_arn=BUCKET,
        execution_role_arn=EXECUTION, observed_user_pool_id="eu-west-1_A1b2C3d4E",
    )


class Iam:
    def __init__(self, template):
        self.template = template
        self.calls = []

    def _role(self, name):
        logical = next(k for k, v in {
            "RetainedDevCdExecutorRole": "honda-mapit-mcp-dev-retained-cd-executor",
            "RetainedDevCdCloudFormationRole": "honda-mapit-mcp-dev-retained-cfn-update",
        }.items() if v == name)
        props = self.template["Resources"][logical]["Properties"]
        boundary = props["PermissionsBoundary"]["Fn::GetAtt"][0]
        return {
            "RoleName": name, "Path": "/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
            "MaxSessionDuration": 3600,
            "AssumeRolePolicyDocument": copy.deepcopy(props["AssumeRolePolicyDocument"]),
            "PermissionsBoundary": {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/{self.template['Resources'][boundary]['Properties']['ManagedPolicyName']}", "PermissionsBoundaryType": "Policy"},
        }, logical

    def get_role(self, *, RoleName):
        self.calls.append(("get_role", RoleName)); role, _ = self._role(RoleName); return _ok(Role=role)

    def list_role_policies(self, *, RoleName):
        self.calls.append(("list_role_policies", RoleName)); return _ok(PolicyNames=[f"{RoleName}-policy"], IsTruncated=False)

    def get_role_policy(self, *, RoleName, PolicyName):
        self.calls.append(("get_role_policy", RoleName, PolicyName))
        _, logical = self._role(RoleName)
        return _ok(RoleName=RoleName, PolicyName=PolicyName, PolicyDocument=copy.deepcopy(self.template["Resources"][logical]["Properties"]["Policies"][0]["PolicyDocument"]))

    def list_attached_role_policies(self, *, RoleName):
        self.calls.append(("list_attached_role_policies", RoleName)); return _ok(AttachedPolicies=[], IsTruncated=False)

    def list_role_tags(self, *, RoleName):
        self.calls.append(("list_role_tags", RoleName))
        logical = next(k for k, v in {"RetainedDevCdExecutorRole": "honda-mapit-mcp-dev-retained-cd-executor", "RetainedDevCdCloudFormationRole": "honda-mapit-mcp-dev-retained-cfn-update"}.items() if v == RoleName)
        tags = [{"Key": key, "Value": value} for key, value in {
            "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "CDDeliveryRetainedDev",
            "OperatorRunId": str(RUN_ID),
        }.items()]
        return _ok(Tags=tags, IsTruncated=False)

    def get_policy(self, *, PolicyArn):
        self.calls.append(("get_policy", PolicyArn)); logical = next(k for k, v in {"RetainedDevCdExecutorBoundary": "honda-mapit-mcp-dev-retained-cd-executor-boundary", "RetainedDevCdCloudFormationBoundary": "honda-mapit-mcp-dev-retained-cfn-update-boundary"}.items() if PolicyArn.endswith("/" + v))
        name = self.template["Resources"][logical]["Properties"]["ManagedPolicyName"]
        return _ok(Policy={"PolicyName": name, "Path": "/", "Arn": PolicyArn, "IsAttachable": True, "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 1, "DefaultVersionId": "v2"})

    def get_policy_version(self, *, PolicyArn, VersionId):
        self.calls.append(("get_policy_version", PolicyArn, VersionId)); logical = next(k for k, v in {"RetainedDevCdExecutorBoundary": "honda-mapit-mcp-dev-retained-cd-executor-boundary", "RetainedDevCdCloudFormationBoundary": "honda-mapit-mcp-dev-retained-cfn-update-boundary"}.items() if PolicyArn.endswith("/" + v))
        return _ok(PolicyVersion={"VersionId": VersionId, "IsDefaultVersion": True, "Document": copy.deepcopy(self.template["Resources"][logical]["Properties"]["PolicyDocument"])})


def test_role_pair_readback_is_bounded_and_redacted():
    template = _template(); iam = Iam(template)
    result = verify_role_pair({"iam": iam}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)
    assert result == {"success": True, "category": "role_pair_verified", "calls": 14}
    assert all("123456789012" not in str(result[key]) for key in result)


def test_role_readback_rejects_foreign_arn_and_duplicate_tags():
    template = _template(); iam = Iam(template)
    original = iam.list_role_tags
    def duplicate(**kwargs):
        result = original(**kwargs); result["Tags"].append({"Key": "Project", "Value": "honda-mapit-mcp"}); return result
    iam.list_role_tags = duplicate
    assert verify_role_pair({"iam": iam}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)["category"] == "role_readback_mismatch"
    assert verify_role_pair({"iam": Iam(template)}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK.replace(ACCOUNT, "999999999999"), original_creation_run_id=RUN_ID)["category"] == "binding_invalid"


def test_role_readback_rejects_cloudformation_system_tag_shape():
    template = _template(); iam = Iam(template)
    original = iam.list_role_tags

    def system_tag(**kwargs):
        result = original(**kwargs)
        result["Tags"].append({"Key": "aws:cloudformation:stack-id", "Value": ROLES_STACK})
        return result

    iam.list_role_tags = system_tag
    result = verify_role_pair(
        {"iam": iam}, template, account=ACCOUNT,
        roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID,
    )
    assert result["category"] == "role_readback_mismatch"


def test_role_template_shape_and_pagination_fail_closed():
    template = _template(); template["Resources"]["Unexpected"] = {}
    assert verify_role_pair({"iam": Iam(_template())}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)["category"] == "template_invalid"
    template = _template(); iam = Iam(template)
    def partial(**kwargs): return _ok(PolicyNames=[kwargs["RoleName"] + "-policy"], IsTruncated=True, Marker="next")
    iam.list_role_policies = partial
    assert verify_role_pair({"iam": iam}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)["category"] == "aws_response_invalid"


def test_boundary_version_must_be_bounded_default_and_exact():
    template = _template(); iam = Iam(template)
    original = iam.get_policy
    def foreign_default(**kwargs):
        result = original(**kwargs); result["Policy"]["DefaultVersionId"] = "v9999"; return result
    iam.get_policy = foreign_default
    result = verify_role_pair({"iam": iam}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)
    assert result["category"] == "boundary_readback_mismatch" and result["calls"] == 11

    iam = Iam(template)
    original_version = iam.get_policy_version
    def non_default(**kwargs):
        result = original_version(**kwargs); result["PolicyVersion"]["IsDefaultVersion"] = False; return result
    iam.get_policy_version = non_default
    result = verify_role_pair({"iam": iam}, template, account=ACCOUNT, roles_stack_arn=ROLES_STACK, original_creation_run_id=RUN_ID)
    assert result["category"] == "boundary_readback_mismatch" and result["calls"] == 12
