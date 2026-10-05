from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json

import pytest

from mapit.aws_cd_identity_bootstrap import (
    CdIdentityBootstrapCoordinator,
    CdIdentityBootstrapError,
    REGION,
    STACK_NAME,
)
from scripts.build_cd_identity_bootstrap import build_cd_identity_bootstrap


ACCOUNT = "123456789012"  # Synthetic fixture only.
OWNER = "1234567"  # Synthetic fixture only.
REPO = "7654321"  # Synthetic fixture only.
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
SOURCE_SHA = "a" * 40
RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
STACK_ARN = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/{RUN_ID}"


def _observations():
    result = {}
    for target, form in (("dev", "legacy_environment"), ("prod", "immutable_environment")):
        sub = (
            f"repo:herrerogusano/honda-mapit-mcp:environment:{target}"
            if form == "legacy_environment"
            else f"repo:herrerogusano@{OWNER}/honda-mapit-mcp@{REPO}:environment:{target}"
        )
        result[target] = {"format": form, "sha256": hashlib.sha256(sub.encode("ascii")).hexdigest()}
    return result


class Journal:
    def __init__(self):
        self.state = None
        self.saves = 0

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return deepcopy(self.state)

    def save(self, value):
        self.state = deepcopy(value)
        self.saves += 1


class AwsError(Exception):
    def __init__(self, code, message="synthetic failure"):
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


class ScriptedClient:
    def __init__(self, methods=None):
        self.methods = methods or {}
        self.calls = []

    def __getattr__(self, method):
        if method not in self.methods:
            raise AssertionError(f"unexpected method {method}")

        def call(**kwargs):
            self.calls.append((method, kwargs))
            outcome = self.methods[method]
            if isinstance(outcome, list):
                outcome = outcome.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            return deepcopy(outcome)

        return call


def _response(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _coordinator(clients, journal=None, *, wall=lambda: 1000.0, monotonic=lambda: 1.0):
    return CdIdentityBootstrapCoordinator(
        clients,
        journal or Journal(),
        account_id=ACCOUNT,
        provider_arn=PROVIDER,
        owner_id=OWNER,
        repository_id=REPO,
        observed_subjects=_observations(),
        source_sha=SOURCE_SHA,
        authorized_from_epoch=900,
        authorized_until_epoch=1800,
        wall_clock=wall,
        monotonic=monotonic,
    )


def _preflight_clients(*, identity_arn=None, stack=None, role=None, policy=None, provider=None):
    sts = ScriptedClient({"get_caller_identity": _response(
        Account=ACCOUNT,
        Arn=identity_arn or f"arn:aws:sts::{ACCOUNT}:assumed-role/operator/session",
        UserId="synthetic-user",
    )})
    iam = ScriptedClient({
        "get_open_id_connect_provider": provider or _response(
            Url="token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"]
        ),
        "get_role": [role or AwsError("NoSuchEntity"), role or AwsError("NoSuchEntity")],
        "get_policy": [policy or AwsError("NoSuchEntity"), policy or AwsError("NoSuchEntity")],
    })
    cfn_outcome = stack if stack is not None else AwsError("ValidationError", f"Stack with id {STACK_NAME} does not exist")
    cfn = ScriptedClient({"describe_stacks": cfn_outcome})
    return {"sts": sts, "iam": iam, "cloudformation": cfn}


def _readback_clients(coordinator, *, mutate=None):
    template = deepcopy(coordinator.template)
    if mutate == "template":
        template["Metadata"]["tampered"] = True
    resources = []
    for logical, resource in template["Resources"].items():
        target = "dev" if logical.startswith("Dev") else "prod"
        if logical.endswith("PermissionsBoundary"):
            physical = f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-{target}-cd-boundary"
        else:
            physical = f"honda-mapit-mcp-{target}-cd"
        resources.append({
            "LogicalResourceId": logical,
            "ResourceType": resource["Type"],
            "ResourceStatus": "CREATE_COMPLETE",
            "PhysicalResourceId": physical,
        })
    stack = {
        "StackId": STACK_ARN,
        "StackName": STACK_NAME,
        "StackStatus": "CREATE_COMPLETE",
        "EnableTerminationProtection": True,
        "Tags": [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "UniqueCdIdentityRunId", "Value": coordinator._run_id},
        ],
    }
    cfn = ScriptedClient({
        "describe_stacks": _response(Stacks=[stack]),
        "get_template": _response(TemplateBody=template),
        "describe_stack_resources": _response(StackResources=resources),
    })
    iam_methods = {
        "get_open_id_connect_provider": [], "get_role": [],
        "list_attached_role_policies": [], "list_role_policies": [],
        "get_role_policy": [], "get_policy": [], "get_policy_version": [],
    }
    provider_readback = _response(
        Url="token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"]
    )
    if mutate == "provider":
        provider_readback["Url"] = "attacker.example"
    iam_methods["get_open_id_connect_provider"].append(provider_readback)
    for target in ("dev", "prod"):
        logical_role = f"{target.title()}CdIdentityRole"
        logical_boundary = f"{target.title()}CdPermissionsBoundary"
        role_name = f"honda-mapit-mcp-{target}-cd"
        boundary_name = f"{role_name}-boundary"
        role_props = coordinator.template["Resources"][logical_role]["Properties"]
        role_reply = {
            "Role": {
                "RoleName": role_name,
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{role_name}",
                "Path": "/",
                "MaxSessionDuration": 3600,
                "PermissionsBoundary": {
                    "PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/{boundary_name}",
                    "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                },
                "AssumeRolePolicyDocument": deepcopy(role_props["AssumeRolePolicyDocument"]),
                "Tags": deepcopy(role_props["Tags"]),
            }
        }
        if mutate == f"trust-{target}":
            role_reply["Role"]["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = "repo:*"
        if mutate == f"path-{target}":
            role_reply["Role"]["Path"] = "/unexpected/"
        if mutate == f"boundary-type-{target}":
            role_reply["Role"]["PermissionsBoundary"]["PermissionsBoundaryType"] = "Policy"
        iam_methods["get_role"].append(_response(**role_reply))
        attached_readback = _response(AttachedPolicies=[], IsTruncated=False)
        if mutate == f"truncated-attached-{target}":
            attached_readback["IsTruncated"] = True
        iam_methods["list_attached_role_policies"].append(attached_readback)
        iam_methods["list_role_policies"].append(_response(PolicyNames=[f"{role_name}-identity-only"], IsTruncated=False))
        inline = deepcopy(role_props["Policies"][0]["PolicyDocument"])
        inline_readback = _response(
            RoleName=role_name, PolicyName=f"{role_name}-identity-only", PolicyDocument=inline
        )
        if mutate == f"inline-name-{target}":
            inline_readback["PolicyName"] = "unexpected"
        iam_methods["get_role_policy"].append(inline_readback)
        boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/{boundary_name}"
        boundary_props = coordinator.template["Resources"][logical_boundary]["Properties"]
        boundary_readback = {
            "Arn": boundary_arn,
            "PolicyName": boundary_name,
            "Path": "/",
            "DefaultVersionId": "v1",
        }
        iam_methods["get_policy"].append(_response(Policy=boundary_readback))
        iam_methods["get_policy_version"].append(_response(PolicyVersion={
            "VersionId": "v1",
            "IsDefaultVersion": True,
            "Document": deepcopy(boundary_props["PolicyDocument"]),
        }))
    provider_readback = _response(
        Url="token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"]
    )
    if mutate == "provider":
        provider_readback["Url"] = "attacker.example"
    iam_methods["get_open_id_connect_provider"].append(provider_readback)
    iam = ScriptedClient({key: vals * 2 for key, vals in iam_methods.items()})
    return {"sts": ScriptedClient({}), "iam": iam, "cloudformation": cfn}


def test_preflight_binds_nonroot_account_provider_absence_and_private_journal() -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    result = coordinator.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 7}
    state = journal.load()
    assert state["phase"] == "preflight_verified"
    assert state["region"] == "eu-west-1"
    assert state["source_sha"] == SOURCE_SHA
    assert state["template_sha256"] == hashlib.sha256(coordinator.template_bytes).hexdigest()
    assert state["client_request_token"] == state["run_id"]
    assert state["observed_subjects"] == _observations()
    assert "repo:herrerogusano" not in json.dumps(state)
    assert sum(len(client.calls) for client in clients.values()) == 7


@pytest.mark.parametrize(
    "clients",
    [
        _preflight_clients(identity_arn=f"arn:aws:iam::{ACCOUNT}:root"),
        _preflight_clients(provider=_response(Url="token.actions.githubusercontent.com", ClientIDList=["other"])),
        _preflight_clients(stack=_response(Stacks=[{"StackName": STACK_NAME}])),
        _preflight_clients(role=_response(Role={"RoleName": "honda-mapit-mcp-dev-cd"})),
        _preflight_clients(policy=_response(Policy={"PolicyName": "honda-mapit-mcp-dev-cd-boundary"})),
    ],
)
def test_preflight_rejects_conflict_or_unverified_state_before_journal(clients) -> None:
    journal = Journal()
    result = _coordinator(clients, journal).run_step("preflight")
    assert result["ok"] is False
    assert result["category"] in {
        "identity_unverified", "provider_unverified", "preflight_conflict", "iam_name_conflict"
    }
    assert journal.state is None
    assert "123456789012" not in json.dumps(result)


def test_preflight_does_not_treat_unrelated_cloudformation_validation_error_as_absence() -> None:
    clients = _preflight_clients()
    clients["cloudformation"] = ScriptedClient({
        "describe_stacks": AwsError("ValidationError", "malformed request")
    })
    journal = Journal()
    result = _coordinator(clients, journal).run_step("preflight")
    assert result["category"] == "stack_absence_unverified"
    assert journal.state is None


def test_mutated_constructor_binding_fails_before_a_write() -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    before = len(clients["cloudformation"].calls)
    coordinator.provider_arn = f"arn:aws:iam::{ACCOUNT}:oidc-provider/attacker.example"
    result = coordinator.run_step("create")
    assert result["category"] == "binding_invalid"
    assert len(clients["cloudformation"].calls) == before


def test_create_saves_intent_before_single_named_iam_write_and_refuses_replay() -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]

    class CreateClient(ScriptedClient):
        def create_stack(self, **kwargs):
            self.calls.append(("create_stack", kwargs))
            state = journal.load()
            assert state["phase"] == "create_intent_saved"
            assert state["create_intent"]["template_sha256"] == coordinator.template_sha256
            return _response(StackId=STACK_ARN)

    clients["cloudformation"] = CreateClient({})
    coordinator.clients = clients
    result = coordinator.run_step("create")
    assert result["ok"] is True
    assert result["category"] == "create_acknowledged"
    name, kwargs = clients["cloudformation"].calls[0]
    assert name == "create_stack"
    assert kwargs["StackName"] == STACK_NAME
    assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert kwargs["EnableTerminationProtection"] is True
    assert "RoleARN" not in kwargs
    assert len(kwargs["TemplateBody"]) <= 50 * 1024
    assert coordinator.run_step("create")["category"] == "create_intent_conflict"
    assert len(clients["cloudformation"].calls) == 1


def test_ambiguous_create_is_never_replayed_but_readonly_reconciliation_remains_available() -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    cfn = ScriptedClient({"create_stack": AwsError("InternalFailure", "canary-secret")})
    clients["cloudformation"] = cfn
    coordinator.clients = clients
    result = coordinator.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal.load()["phase"] == "create_outcome_unknown"
    assert coordinator.run_step("create")["category"] == "create_intent_conflict"
    assert len(cfn.calls) == 1
    # Only fixed-category output is emitted.
    assert "canary-secret" not in json.dumps(result)


@pytest.mark.parametrize("interrupted_phase", ["create_outcome_unknown", "create_intent_saved"])
def test_ambiguous_create_reconciles_only_with_exact_run_tag_and_event_token(interrupted_phase) -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    readbacks = _readback_clients(coordinator)
    readback_cfn = readbacks["cloudformation"]

    class ReconcileCfn:
        def __init__(self):
            self.calls = []

        def create_stack(self, **kwargs):
            self.calls.append(("create_stack", kwargs))
            raise AwsError("InternalFailure", "ambiguous synthetic outcome")

        def describe_stacks(self, **kwargs):
            self.calls.append(("describe_stacks", kwargs))
            if kwargs.get("StackName") == STACK_NAME:
                return readback_cfn.methods["describe_stacks"]
            return readback_cfn.methods["describe_stacks"]

        def describe_stack_events(self, **kwargs):
            self.calls.append(("describe_stack_events", kwargs))
            return _response(StackEvents=[{
                "StackId": STACK_ARN,
                "ClientRequestToken": journal.load()["client_request_token"],
            }])

        def get_template(self, **kwargs):
            self.calls.append(("get_template", kwargs))
            return readback_cfn.methods["get_template"]

        def describe_stack_resources(self, **kwargs):
            self.calls.append(("describe_stack_resources", kwargs))
            return readback_cfn.methods["describe_stack_resources"]

    clients["cloudformation"] = ReconcileCfn()
    clients["iam"] = readbacks["iam"]
    coordinator.clients = clients
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    if interrupted_phase == "create_intent_saved":
        interrupted = journal.load()
        interrupted["phase"] = "create_intent_saved"
        journal.save(interrupted)
    recovered = coordinator.run_step("check-create")
    assert recovered["ok"] is True, recovered
    assert recovered["category"] == "stack_and_identity_verified"
    assert journal.load()["stack_arn"] == STACK_ARN
    assert [name for name, _ in clients["cloudformation"].calls].count("create_stack") == 1
    assert [name for name, _ in clients["cloudformation"].calls].count("describe_stack_events") == 1


def test_exact_stack_and_iam_readback_then_final_readback_succeed() -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = ScriptedClient({"create_stack": _response(StackId=STACK_ARN)})
    coordinator.clients = clients
    assert coordinator.run_step("create")["ok"]
    readback = _readback_clients(coordinator)
    coordinator.clients = readback
    checked = coordinator.run_step("check-create")
    assert checked["ok"] and checked["category"] == "stack_and_identity_verified"
    final = coordinator.run_step("final-readback")
    assert final["ok"] and final["category"] == "final_readback_verified", final
    assert journal.load()["phase"] == "final_readback_verified"
    safe = json.dumps(final)
    assert ACCOUNT not in safe and PROVIDER not in safe and "honda-mapit" not in safe


@pytest.mark.parametrize("mutation", [
    "template", "trust-dev", "path-dev", "provider", "truncated-attached-dev",
    "inline-name-dev", "boundary-type-dev",
])
def test_readback_rejects_template_or_trust_drift(mutation) -> None:
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = ScriptedClient({"create_stack": _response(StackId=STACK_ARN)})
    coordinator.clients = clients
    assert coordinator.run_step("create")["ok"]
    coordinator.clients = _readback_clients(coordinator, mutate=mutation)
    result = coordinator.run_step("check-create")
    assert result["ok"] is False
    assert result["category"] in {
        "stack_readback_mismatch", "identity_readback_mismatch", "provider_unverified"
    }


def test_no_write_when_window_is_outside_authority() -> None:
    journal = Journal()
    clients = _preflight_clients()
    result = _coordinator(clients, journal, wall=lambda: 1800.0).run_step("preflight")
    assert result["category"] == "window_expired"
    assert sum(len(client.calls) for client in clients.values()) == 0
    assert journal.state is None


@pytest.mark.parametrize("source_sha", ["A" * 40, "a" * 39, "g" * 40, True])
def test_invalid_exact_source_commit_rejected_at_construction(source_sha) -> None:
    with pytest.raises(CdIdentityBootstrapError) as error:
        CdIdentityBootstrapCoordinator(
            _preflight_clients(), Journal(), account_id=ACCOUNT, provider_arn=PROVIDER,
            owner_id=OWNER, repository_id=REPO, observed_subjects=_observations(),
            source_sha=source_sha, authorized_from_epoch=900, authorized_until_epoch=1800,
            wall_clock=lambda: 1000.0,
        )
    assert error.value.category == "binding_invalid"


def test_unknown_step_does_not_echo_input() -> None:
    result = _coordinator(_preflight_clients()).run_step("private-canary-step")
    assert result == {"step": "unknown", "ok": False, "category": "step_invalid", "calls": 0}
    assert "private-canary" not in json.dumps(result)
