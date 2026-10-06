import pytest

from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup, MultiuserTemplateError


def test_setup_preserves_original_closed_runtime_and_has_only_six_new_resources():
    base = build_retained_dev_template()
    setup = build_retained_dev_multiuser_setup(api_id="a1b2c3d4e5", callback_url="http://localhost:39031/callback")
    assert len(setup["Resources"]) == 11
    for key, value in base["Resources"].items():
        assert setup["Resources"][key] == value
    assert {r["Type"] for key, r in setup["Resources"].items() if key not in base["Resources"]} == {
        "AWS::Cognito::UserPool", "AWS::Cognito::UserPoolClient", "AWS::Cognito::UserPoolDomain",
        "AWS::Cognito::UserPoolResourceServer", "AWS::Cognito::ManagedLoginBranding", "AWS::DynamoDB::Table"}
    assert setup["Metadata"]["RuntimeUnchanged"] is True


def test_setup_rejects_remote_callback():
    with pytest.raises(MultiuserTemplateError):
        build_retained_dev_multiuser_setup(api_id="a1b2c3d4e5", callback_url="https://evil.example/callback")
