from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from scripts.aws_dev_identity_binding_bootstrap import (
    DevIdentityBindingBootstrapCoordinator, _digest, _exact_boundary, _valid_evidence,
)
from scripts.build_aws_dev_identity_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_ROLE_NAME, OPERATOR_BOUNDARY_NAME, RUNTIME_ROLE_NAME,
    STACK_NAME, IdentityBindingBootstrapTemplateError, build_dev_identity_binding_bootstrap,
)


ACCOUNT = "123456789012"
USER = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
KEYS = ("tenant-" + "1" * 64, "tenant-" + "2" * 64)


def _build(**changes):
    args = {"account_id": ACCOUNT, "operator_user_arn": USER, "tenant_keys": KEYS,
            "ssm_key_arn": f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"}
    args.update(changes)
    return build_dev_identity_binding_bootstrap(**args)


def _actions(statement):
    actions = statement["Action"]
    return set(actions if isinstance(actions, list) else [actions])


def test_fixed_stack_contains_only_table_scoped_operator_and_runtime_permissions():
    template = _build()
    resources = template["Resources"]
    assert set(resources) == {
        "MapitIdentityBindings", "IdentityEnrollerBoundary", "IdentityEnrollerRole",
        "RuntimeIdentityBindingPolicy",
    }
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, ACCOUNT]},
    ]
    assert all(row["Condition"] == "SupportedDeployment" for row in resources.values())
    table = resources["MapitIdentityBindings"]
    assert table["Type"] == "AWS::DynamoDB::Table"
    assert table["DeletionPolicy"] == table["UpdateReplacePolicy"] == "Retain"
    props = table["Properties"]
    assert props["TableName"] == "honda-mapit-mcp-dev-identity-bindings"
    assert props["DeletionProtectionEnabled"] is True
    assert props["BillingMode"] == "PAY_PER_REQUEST"
    assert props["OnDemandThroughput"] == {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100}

    role = resources["IdentityEnrollerRole"]["Properties"]
    assert role["RoleName"] == OPERATOR_ROLE_NAME
    assert role["MaxSessionDuration"] == 3600
    assert role["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"AWS": USER}, "Action": "sts:AssumeRole",
    }]
    assert role["PermissionsBoundary"] == {"Fn::GetAtt": ["IdentityEnrollerBoundary", "PolicyArn"]}

    boundary = resources["IdentityEnrollerBoundary"]["Properties"]
    assert boundary["ManagedPolicyName"] == OPERATOR_BOUNDARY_NAME
    boundary_statements = boundary["PolicyDocument"]["Statement"]
    deny = next(row for row in boundary_statements if row.get("Sid") == "DenyUnlistedOperatorCapabilities")
    assert deny["Effect"] == "Deny" and deny["Resource"] == "*"
    assert "iam:PassRole" not in deny.get("NotAction", [])

    operator_statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    runtime = resources["RuntimeIdentityBindingPolicy"]["Properties"]
    assert runtime["Roles"] == [RUNTIME_ROLE_NAME]
    runtime_statements = runtime["PolicyDocument"]["Statement"]
    assert "dynamodb:PutItem" not in set().union(*(_actions(row) for row in runtime_statements))
    assert "ssm:PutParameter" not in set().union(*(_actions(row) for row in runtime_statements))
    assert "sts:GetCallerIdentity" in set().union(*(_actions(row) for row in operator_statements))

    table_arn = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"
    expected_paths = {
        f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
        for key in KEYS
    } | {f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{CONFIG_PARAMETER}"}
    for statement in operator_statements:
        action = _actions(statement)
        if action & {"dynamodb:GetItem", "dynamodb:PutItem"}:
            assert statement["Resource"] == table_arn
            assert statement["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["identity-bindings-v1"]
        if action & {"ssm:GetParameter", "ssm:PutParameter"}:
            assert set(statement["Resource"]) == expected_paths
    assert all("Output" not in str(value) for value in template.values())
    assert template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert template["Metadata"]["ApplicationStackModified"] is False
    assert template["Metadata"]["ConfigSecretMaterialIncluded"] is False
    assert template["Metadata"]["OperatorMustUseWholeFixedDdbItemCas"] is True


@pytest.mark.parametrize("changes", [
    {"account_id": "000000000000"},
    {"account_id": "12345678901x"},
    {"operator_user_arn": f"arn:aws:iam::999999999999:user/dev-operator"},
    {"operator_user_arn": f"arn:aws:iam::{ACCOUNT}:root"},
    {"operator_user_arn": f"arn:aws:iam::{ACCOUNT}:user/*"},
    {"tenant_keys": ()},
    {"tenant_keys": (KEYS[0],)},
    {"tenant_keys": (KEYS[0], KEYS[0])},
    {"tenant_keys": (KEYS[0], "tenant-../prod")},
    {"tenant_keys": [*KEYS]},
])
def test_invalid_account_principal_or_synthetic_key_set_fails_closed(changes):
    with pytest.raises(IdentityBindingBootstrapTemplateError, match="identity_binding_bootstrap_invalid"):
        _build(**changes)


def test_factory_returns_fresh_copy_and_never_embeds_binding_key_material():
    template = _build()
    changed = copy.deepcopy(template)
    changed["Resources"].clear()
    assert set(_build()["Resources"]) == {
        "MapitIdentityBindings", "IdentityEnrollerBoundary", "IdentityEnrollerRole",
        "RuntimeIdentityBindingPolicy",
    }
    assert "binding_mac_key" not in str(template).lower()
    assert "identity_proof_hmac_key" not in str(template).lower()


class _AwsError(Exception):
    def __init__(self, code, status, message=""):
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


class _Journal:
    def __init__(self):
        self.state = None
        self.saves = []

    class _Lock:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False

    def locked(self):
        return self._Lock()

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)
        self.saves.append(copy.deepcopy(state))


class _Client:
    def __init__(self, service, region, endpoint, dispatch):
        self.meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name=service),
            region_name=region, endpoint_url=endpoint,
            config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3),
        )
        self._dispatch = dispatch

    def __getattr__(self, name):
        def call(**kwargs):
            return self._dispatch(name, kwargs)
        return call


def _bootstrap_fixture():
    from scripts.aws_dev_identity_binding_bootstrap import REGION, RUNTIME_POLICY_NAME

    app_stack = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/12345678-1234-1234-1234-123456789abc"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{RUNTIME_ROLE_NAME}"
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
    policies = {
        "honda-mapit-mcp-dev-retained-owned-log-writes": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "logs:PutLogEvents", "Resource": "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/example:*"}]},
        "honda-mapit-mcp-dev-retained-tenant-read": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "arn:aws:dynamodb:eu-west-1:123456789012:table/example"}]},
    }
    binding = {
        "account_id": ACCOUNT, "operator_user_arn": USER, "tenant_keys": KEYS,
        "ssm_key_arn": f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111",
        "accepted_runtime_journal_path": "C:/private/accepted/runtime.json",
        "app_stack_arn": app_stack, "app_run_id": 1234,
        "api_id": "abc123def4", "user_pool_id": "eu-west-1_Abc123", "client_id": "Abc123456789",
        "template_sha256": "a" * 64, "code_sha256": "b" * 64,
        "handler_role_arn": role_arn, "handler_trust_sha256": _digest(trust),
        "handler_policies_sha256": _digest(policies),
    }
    evidence = {
        "verified": True, "calls": 1, "app_stack_arn": app_stack, "app_run_id": 1234,
        "api_id": "abc123def4", "template_sha256": "a" * 64, "code_sha256": "b" * 64,
        "handler_role_arn": role_arn, "handler_trust_sha256": _digest(trust),
        "handler_policies_sha256": _digest(policies), "resource_count": 19,
        "api_closed": True, "reserve_zero": True,
    }
    def reply(**fields):
        return {**fields, "ResponseMetadata": {"HTTPStatusCode": 200}}
    def dispatch(service, method, kwargs):
        if service == "kms" and method == "describe_key":
            assert kwargs == {"KeyId": "alias/aws/ssm"}
            return reply(KeyMetadata={"Arn": binding["ssm_key_arn"], "AWSAccountId": ACCOUNT,
                "KeyManager": "AWS", "Enabled": True, "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"})
        if service == "sts" and method == "get_caller_identity":
            return reply(Account=ACCOUNT, Arn=USER, UserId="AIDEXAMPLE")
        if service == "cloudformation" and method == "describe_stacks":
            raise _AwsError("ValidationError", 400, f"Stack with id {STACK_NAME} does not exist")
        if service == "dynamodb" and method == "describe_table":
            raise _AwsError("ResourceNotFoundException", 400)
        if service == "iam" and method == "get_role" and kwargs["RoleName"] == RUNTIME_ROLE_NAME:
            return reply(Role={"RoleName": RUNTIME_ROLE_NAME, "Arn": role_arn, "Path": "/",
                               "PermissionsBoundary": None, "AssumeRolePolicyDocument": trust})
        if service == "iam" and method == "list_role_policies" and kwargs["RoleName"] == RUNTIME_ROLE_NAME:
            return reply(PolicyNames=sorted(policies), IsTruncated=False)
        if service == "iam" and method == "get_role_policy" and kwargs["RoleName"] == RUNTIME_ROLE_NAME:
            if kwargs["PolicyName"] in policies:
                return reply(RoleName=RUNTIME_ROLE_NAME, PolicyName=kwargs["PolicyName"],
                             PolicyDocument=policies[kwargs["PolicyName"]])
            raise _AwsError("NoSuchEntity", 404)
        if service == "iam" and method == "get_role" and kwargs["RoleName"] != RUNTIME_ROLE_NAME:
            raise _AwsError("NoSuchEntity", 404)
        if service == "iam" and method == "get_policy":
            raise _AwsError("NoSuchEntity", 404)
        if service == "iam" and method == "get_role_policy":
            raise _AwsError("NoSuchEntity", 404)
        if service == "ssm" and method == "get_parameter":
            raise _AwsError("ParameterNotFound", 400)
        raise AssertionError((service, method, kwargs))
    clients = {
        "kms": _Client("kms", REGION, f"https://kms.{REGION}.amazonaws.com", lambda m, k: dispatch("kms", m, k)),
        "sts": _Client("sts", REGION, f"https://sts.{REGION}.amazonaws.com", lambda m, k: dispatch("sts", m, k)),
        "cloudformation": _Client("cloudformation", REGION, f"https://cloudformation.{REGION}.amazonaws.com", lambda m, k: dispatch("cloudformation", m, k)),
        "iam": _Client("iam", "us-east-1", "https://iam.amazonaws.com", lambda m, k: dispatch("iam", m, k)),
        "dynamodb": _Client("dynamodb", REGION, f"https://dynamodb.{REGION}.amazonaws.com", lambda m, k: dispatch("dynamodb", m, k)),
        "ssm": _Client("ssm", REGION, f"https://ssm.{REGION}.amazonaws.com", lambda m, k: dispatch("ssm", m, k)),
        "cognito": _Client("cognito-idp", REGION, f"https://cognito-idp.{REGION}.amazonaws.com", lambda m, k: dispatch("cognito", m, k)),
        "apigatewayv2": _Client("apigatewayv2", REGION, f"https://apigateway.{REGION}.amazonaws.com", lambda m, k: dispatch("apigatewayv2", m, k)),
        "lambda": _Client("lambda", REGION, f"https://lambda.{REGION}.amazonaws.com", lambda m, k: dispatch("lambda", m, k)),
    }
    journal = _Journal()
    def verifier(_clients, _binding):
        return copy.deepcopy(evidence)
    coordinator = DevIdentityBindingBootstrapCoordinator(
        clients, journal, binding=binding, source_sha="c" * 40, run_id=5678,
        expected_caller_arn=USER, authorized_from_epoch=1_700_000_000,
        authorized_until_epoch=1_700_003_600, accepted_runtime_verifier=verifier,
        wall_clock=lambda: 1_700_001_000, monotonic=lambda: 100.0,
    )
    return coordinator, journal, evidence


def test_bootstrap_preflight_binds_accepted_runtime_before_any_write():
    coordinator, journal, _ = _bootstrap_fixture()
    result = coordinator.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 15}
    assert journal.state["preflight"] is True
    assert journal.state["intent"] is None


def test_accepted_runtime_receipt_rejects_bool_integer_coercion():
    _, _, evidence = _bootstrap_fixture()
    binding = {
        "app_stack_arn": evidence["app_stack_arn"], "app_run_id": evidence["app_run_id"],
        "api_id": evidence["api_id"], "template_sha256": evidence["template_sha256"],
        "code_sha256": evidence["code_sha256"], "handler_role_arn": evidence["handler_role_arn"],
        "handler_trust_sha256": evidence["handler_trust_sha256"],
        "handler_policies_sha256": evidence["handler_policies_sha256"],
    }
    assert _valid_evidence(evidence, binding=binding)
    malformed = {**evidence, "app_run_id": True}
    assert not _valid_evidence(malformed, binding=binding)
    malformed = {**evidence, "api_closed": 1}
    assert not _valid_evidence(malformed, binding=binding)


@pytest.mark.parametrize("kind", ["PermissionsBoundaryPolicy", "Policy"])
def test_exact_boundary_readback_accepts_only_sdk_type_alias_for_same_arn(kind):
    arn = f"arn:aws:iam::{ACCOUNT}:policy/{OPERATOR_BOUNDARY_NAME}"
    assert _exact_boundary({"PermissionsBoundaryArn": arn, "PermissionsBoundaryType": kind}, arn)
    assert not _exact_boundary({"PermissionsBoundaryArn": arn, "PermissionsBoundaryType": "Other"}, arn)
    assert not _exact_boundary({"PermissionsBoundaryArn": f"{arn}-other", "PermissionsBoundaryType": kind}, arn)
    assert not _exact_boundary({"PermissionsBoundaryArn": arn, "PermissionsBoundaryType": [kind]}, arn)


def test_create_persists_one_intent_before_single_create_stack_and_never_replays():
    coordinator, journal, _ = _bootstrap_fixture()
    assert coordinator.run_step("preflight")["ok"] is True
    client = coordinator.clients["cloudformation"]
    original_dispatch = client._dispatch
    create_calls = []
    def create(**kwargs):
        assert journal.state["intent"]["token"] == kwargs["ClientRequestToken"]
        create_calls.append(kwargs)
        return {"StackId": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/12345678-1234-1234-1234-123456789abc",
                "ResponseMetadata": {"HTTPStatusCode": 200}}
    client._dispatch = lambda method, kwargs: create(**kwargs) if method == "create_stack" else original_dispatch(method, kwargs)
    result = coordinator.run_step("create")
    assert result["ok"] is True and result["category"] == "create_acknowledged"
    assert len(create_calls) == 1
    assert coordinator.run_step("create")["category"] == "create_intent_present"
    assert len(create_calls) == 1


def test_private_binding_changes_cannot_reuse_a_preflight_journal():
    coordinator, journal, evidence = _bootstrap_fixture()
    assert coordinator.run_step("preflight")["ok"] is True
    changed = dict(coordinator.binding)
    changed["client_id"] = "Different123"
    replacement = DevIdentityBindingBootstrapCoordinator(
        coordinator.clients, journal, binding=changed, source_sha=coordinator.source_sha,
        run_id=coordinator.run_id, expected_caller_arn=coordinator.caller,
        authorized_from_epoch=coordinator.window_start, authorized_until_epoch=coordinator.window_end,
        accepted_runtime_verifier=lambda *_: copy.deepcopy(evidence),
        wall_clock=lambda: 1_700_001_000, monotonic=lambda: 100.0,
    )
    result = replacement.run_step("create")
    assert result["category"] == "journal_invalid"
    assert result["calls"] == 0
