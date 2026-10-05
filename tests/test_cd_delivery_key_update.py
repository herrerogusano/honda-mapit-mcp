"""Synthetic acceptance of the separate one-shot delivery IAM update."""
import copy
import json

import pytest

from scripts import run_cd_delivery_key_update as operator
from test_cd_delivery_bootstrap import ACCOUNT, SOURCE, STACK_ID, Journal, _state

KEY = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
RUN = "00000000-0000-4000-8000-000000000000"


def reply(**kwargs):
    return {"ResponseMetadata": {"HTTPStatusCode": 200}, **kwargs}


class AWS:
    def __init__(self, journal):
        self.journal = journal
        self.template = operator.bootstrap.template_from_inventory(journal.state["inventory"])
        self.status = "CREATE_COMPLETE"
        self.calls = []
        self.updates = 0
        self.ambiguous = False
        self.tamper = None
        self.key = {"Arn": KEY, "AWSAccountId": ACCOUNT, "KeyManager": "AWS", "KeyState": "Enabled",
                    "KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "MultiRegion": False}
        self.operator_arn = f"arn:aws:iam::{ACCOUNT}:user/synthetic"

    def get_caller_identity(self):
        self.calls.append("identity")
        return reply(Account=ACCOUNT, Arn=self.operator_arn)

    def describe_key(self, **kwargs):
        assert kwargs == {"KeyId": "alias/aws/lambda"}
        self.calls.append("key")
        return reply(KeyMetadata=copy.deepcopy(self.key))

    def get_open_id_connect_provider(self, **kwargs):
        self.calls.append("provider")
        return reply(Url="token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"])

    def describe_stacks(self, **kwargs):
        assert kwargs == {"StackName": STACK_ID}
        self.calls.append("stack")
        return reply(Stacks=[{"StackId": STACK_ID, "StackName": operator.STACK, "StackStatus": self.status,
                              "EnableTerminationProtection": True, "Tags": [
                                  {"Key": "Project", "Value": "honda-mapit-mcp"},
                                  {"Key": "Environment", "Value": "prod"},
                                  {"Key": "UniqueCdDeliveryRunId", "Value": RUN}]}])

    def get_template(self, **kwargs):
        self.calls.append("template")
        template = copy.deepcopy(self.template)
        if self.tamper == "template":
            template["Metadata"]["unexpected"] = True
        return reply(TemplateBody=template)

    def describe_stack_resources(self, **kwargs):
        self.calls.append("resources")
        rows = []
        for logical, resource in self.template["Resources"].items():
            p = resource["Properties"]
            physical = p["RoleName"] if resource["Type"] == "AWS::IAM::Role" else f"arn:aws:iam::{ACCOUNT}:policy/{p['ManagedPolicyName']}"
            rows.append({"LogicalResourceId": logical, "ResourceType": resource["Type"],
                         "PhysicalResourceId": physical, "ResourceStatus": "UPDATE_COMPLETE"})
        if self.tamper == "resources":
            rows.append(copy.deepcopy(rows[0]))
        return reply(StackResources=rows)

    def _resource(self, property_name, name):
        return next(v["Properties"] for v in self.template["Resources"].values()
                    if v["Properties"].get(property_name) == name)

    def get_policy(self, PolicyArn):
        self.calls.append("policy")
        return reply(Policy={"Arn": PolicyArn, "DefaultVersionId": "v1", "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 1})

    def get_policy_version(self, PolicyArn, VersionId):
        self.calls.append("version")
        p = self._resource("ManagedPolicyName", PolicyArn.rsplit("/", 1)[1])
        document = copy.deepcopy(p["PolicyDocument"])
        if self.tamper == "boundary":
            document["Statement"][0]["Resource"] = "*changed*"
        return reply(PolicyVersion={"VersionId": VersionId, "IsDefaultVersion": True, "Document": document})

    def get_role(self, RoleName):
        self.calls.append("role")
        p = self._resource("RoleName", RoleName)
        boundary = self.template["Resources"][p["PermissionsBoundary"]["Fn::GetAtt"][0]]["Properties"]["ManagedPolicyName"]
        trust = copy.deepcopy(p["AssumeRolePolicyDocument"])
        if self.tamper == "trust":
            trust["Statement"][0]["Principal"] = {"AWS": "*"}
        return reply(Role={"Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}", "Path": "/", "MaxSessionDuration": 3600,
                           "PermissionsBoundary": {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/{boundary}",
                                                   "PermissionsBoundaryType": "Policy"},
                           "AssumeRolePolicyDocument": trust, "Tags": p["Tags"]})

    def list_role_policies(self, RoleName):
        self.calls.append("inline_names")
        p = self._resource("RoleName", RoleName)
        return reply(IsTruncated=False, PolicyNames=[p["Policies"][0]["PolicyName"]])

    def list_attached_role_policies(self, **kwargs):
        self.calls.append("attachments")
        return reply(IsTruncated=False, AttachedPolicies=[])

    def get_role_policy(self, RoleName, PolicyName):
        self.calls.append("inline")
        p = self._resource("RoleName", RoleName)
        assert PolicyName == p["Policies"][0]["PolicyName"]
        document = copy.deepcopy(p["Policies"][0]["PolicyDocument"])
        if self.tamper == "inline":
            document["Statement"].append({"Action": "*", "Resource": "*", "Effect": "Allow"})
        return reply(PolicyDocument=document)

    def update_stack(self, **kwargs):
        assert self.journal.state["environment_key_update"]["update_intent"] == kwargs["ClientRequestToken"]
        assert set(kwargs) == {"StackName", "TemplateBody", "Capabilities", "ClientRequestToken"}
        assert kwargs["StackName"] == STACK_ID and kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
        self.calls.append("update")
        self.updates += 1
        self.template = json.loads(kwargs["TemplateBody"])
        self.status = "UPDATE_COMPLETE"
        if self.ambiguous:
            raise TimeoutError("PRIVATE_PROVIDER_CANARY")
        return reply(StackId=STACK_ID)


def fixture():
    state = _state()
    old = operator.bootstrap.template_from_inventory(state["inventory"])
    state["bootstrap"] = {"verified": True, "run_id": RUN, "create_intent": RUN, "stack_arn": STACK_ID,
                          "template_sha256": operator.digest(old), "source_sha": "2" * 40,
                          "start": 10, "end": 3610}
    state["lambda_environment_key"] = {"arn": KEY, "aws_managed": True, "enabled": True, "multi_region": False,
                                       "policy": {"private": "receipt"}, "observed_contexts": []}
    state["lambda_environment_key_context_evidence"] = {
        "contexts": [{"aws:lambda:FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-prod-handler"}] * 3,
        "readback_exact_key": True, "function_context_exact": True}
    journal = Journal(state)
    aws = AWS(journal)
    clients = {service: aws for service in ("sts", "kms", "iam", "cloudformation")}
    return journal, aws, clients


def test_prepared_update_is_one_shot_and_verifies_all_four_existing_resources():
    journal, aws, clients = fixture()
    bootstrap_before = copy.deepcopy(journal.state["bootstrap"])
    assert operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)["category"] == "key_update_prepared"
    binding = journal.state["environment_key_update"]
    assert binding["start"] == 1000 and binding["end"] == 4600
    assert binding["recovery_template"] == aws.template
    assert binding["proposed_template"] != binding["recovery_template"]
    assert operator.run("update", journal, clients, SOURCE, clock=lambda: 1001)["category"] == "key_update_pending"
    assert operator.run("verify", journal, clients, SOURCE, clock=lambda: 1002)["category"] == "key_update_verified"
    assert journal.state["environment_key_update"]["verified"] is True
    assert journal.state["bootstrap"] == bootstrap_before and aws.updates == 1
    with pytest.raises(operator.KeyUpdateError, match="update_consumed"):
        operator.run("update", journal, clients, SOURCE, clock=lambda: 1003)
    assert aws.updates == 1


def test_ambiguous_update_can_only_be_reconciled_by_exact_readback():
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    aws.ambiguous = True
    with pytest.raises(operator.KeyUpdateError, match="update_outcome_unknown"):
        operator.run("update", journal, clients, SOURCE, clock=lambda: 1001)
    with pytest.raises(operator.KeyUpdateError, match="update_consumed"):
        operator.run("update", journal, clients, SOURCE, clock=lambda: 1002)
    assert operator.run("verify", journal, clients, SOURCE, clock=lambda: 1003)["category"] == "key_update_verified"
    assert aws.updates == 1


@pytest.mark.parametrize("tamper,category", [("template", "template_mismatch"), ("resources", "resources_mismatch"),
                                          ("trust", "role_mismatch"), ("inline", "role_mismatch"), ("boundary", "boundary_mismatch")])
def test_prepare_rejects_owned_stack_or_iam_drift_before_any_intent(tamper, category):
    journal, aws, clients = fixture()
    aws.tamper = tamper
    with pytest.raises(operator.KeyUpdateError, match=category):
        operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    assert "environment_key_update" not in journal.state and aws.updates == 0


@pytest.mark.parametrize("change,category", [("source", "binding_changed"), ("operator", "operator_changed"),
                                           ("key", "key_changed"), ("expiry", "window_expired"),
                                           ("recovery", "binding_changed"), ("context", "key_context_invalid")])
def test_update_rechecks_binding_identity_key_and_window_without_writing(change, category):
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    source, now = SOURCE, 1001
    if change == "source":
        source = "3" * 40
    elif change == "operator":
        aws.operator_arn += "other"
    elif change == "key":
        aws.key["Arn"] = KEY.replace("11111111", "aaaaaaaa")
    elif change == "expiry":
        now = 4600
    elif change == "recovery":
        journal.state["environment_key_update"]["recovery_template"]["Metadata"]["extra"] = True
    else:
        journal.state["lambda_environment_key_context_evidence"]["contexts"][0] = {}
    with pytest.raises(operator.KeyUpdateError, match=category):
        operator.run("update", journal, clients, source, clock=lambda: now)
    assert aws.updates == 0 and "update_intent" not in journal.state["environment_key_update"]


@pytest.mark.parametrize("status", ["UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"])
def test_verify_nonterminal_or_failed_update_does_not_claim_acceptance(status):
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    operator.run("update", journal, clients, SOURCE, clock=lambda: 1001)
    aws.status = status
    with pytest.raises(operator.KeyUpdateError, match="stack_not_complete"):
        operator.run("verify", journal, clients, SOURCE, clock=lambda: 1002)
    assert journal.state["environment_key_update"].get("verified") is not True and aws.updates == 1


def test_verify_pending_update_is_read_only_and_does_not_extend_window():
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    operator.run("update", journal, clients, SOURCE, clock=lambda: 1001)
    aws.status = "UPDATE_IN_PROGRESS"
    assert operator.run("verify", journal, clients, SOURCE, clock=lambda: 1002)["category"] == "key_update_pending"
    assert journal.state["environment_key_update"]["end"] == 4600 and aws.updates == 1
