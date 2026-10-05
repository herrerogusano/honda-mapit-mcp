"""Independent fail-closed checks of the bounded IAM-only update."""
import pytest

from test_cd_delivery_key_update import fixture, operator, SOURCE


@pytest.mark.parametrize("mutation", ["root", "account", "service_role", "tag", "protection"])
def test_prepare_rejects_identity_or_stack_control_drift(mutation):
    journal, aws, clients = fixture()
    if mutation == "root":
        aws.operator_arn = aws.operator_arn.split(":user/")[0] + ":root"
    elif mutation == "account":
        aws.operator_arn = aws.operator_arn.replace(":123456789012:", ":999999999999:")
    else:
        original = aws.describe_stacks
        def changed(**kwargs):
            result = original(**kwargs)
            stack = result["Stacks"][0]
            if mutation == "service_role":
                stack["RoleARN"] = "unexpected-role"
            elif mutation == "tag":
                stack["Tags"].append(dict(stack["Tags"][0]))
            else:
                stack["EnableTerminationProtection"] = False
            return result
        aws.describe_stacks = changed
    with pytest.raises(operator.KeyUpdateError):
        operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    assert aws.updates == 0 and "environment_key_update" not in journal.state


def test_post_write_boundary_drift_never_marks_verified():
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    operator.run("update", journal, clients, SOURCE, clock=lambda: 1001)
    aws.tamper = "boundary"
    with pytest.raises(operator.KeyUpdateError, match="boundary_mismatch"):
        operator.run("verify", journal, clients, SOURCE, clock=lambda: 1002)
    assert not journal.state["environment_key_update"].get("verified")
    assert aws.updates == 1


def test_backward_clock_cannot_authorize_write():
    journal, aws, clients = fixture()
    operator.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    with pytest.raises(operator.KeyUpdateError, match="window_expired"):
        operator.run("update", journal, clients, SOURCE, clock=lambda: 999)
    assert aws.updates == 0
