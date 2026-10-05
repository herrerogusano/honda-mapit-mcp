"""Independent policy-boundary assertions for the offline CD role factory."""

from scripts.build_cd_delivery_roles import build_cd_delivery_roles
from test_cd_delivery_roles import _build, _role_policy, EXECUTION_ROLE


def test_optional_lambda_passrole_is_exact_and_only_on_cfn_service_role():
    for enabled in (False, True):
        template = _build(allow_execution_role_passrole=enabled)
        executor = _role_policy(template["Resources"], "ProdCdExecutorRole")
        cfn = _role_policy(template["Resources"], "ProdCdCloudFormationRole")
        executor_pass = [s for s in executor if "iam:PassRole" in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
        cfn_pass = [s for s in cfn if "iam:PassRole" in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]

        assert len(executor_pass) == 1
        assert executor_pass[0]["Resource"] == "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cfn-update"
        assert executor_pass[0]["Condition"] == {
            "StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}
        }
        assert len(cfn_pass) == int(enabled)
        if enabled:
            assert cfn_pass[0]["Resource"] == EXECUTION_ROLE
            assert cfn_pass[0]["Condition"] == {
                "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
            }


def test_every_allow_is_scoped_or_explicitly_documented_global_read():
    template = _build(allow_execution_role_passrole=False)
    for role_id in ("ProdCdExecutorRole", "ProdCdCloudFormationRole"):
        statements = _role_policy(template["Resources"], role_id)
        for statement in statements:
            if statement["Effect"] != "Allow":
                continue
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            resources = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
            if resources == ["*"]:
                assert role_id == "ProdCdExecutorRole"
                assert set(actions) <= {"sts:GetCallerIdentity", "lambda:GetAccountSettings"}
            else:
                assert all(resource not in ("*", "arn:aws:iam::*:*") for resource in resources)


def test_factory_rejects_falsey_or_numeric_passrole_toggles():
    import pytest
    from scripts.build_cd_delivery_roles import DeliveryRoleError

    for value in (None, 0, 1, "false", []):
        with pytest.raises(DeliveryRoleError):
            _build(allow_execution_role_passrole=value)
