from copy import deepcopy

import pytest

from scripts.build_aws_retained_dev import build_retained_dev_template, STACK_NAME
from scripts.build_aws_retained_dev_oauth import build_retained_dev_oauth_setup, CHILDREN


def build():
    return build_retained_dev_oauth_setup(
        "abcdef1234", "eu-west-1_AbCdEfGhI", callback_url="http://127.0.0.1:8787/callback",
    )


def test_oauth_adds_only_three_retained_children_to_unchanged_closed_scaffold():
    template = build()
    scaffold = build_retained_dev_template()
    assert set(template["Resources"]) == set(scaffold["Resources"]) | set(CHILDREN)
    for name, resource in scaffold["Resources"].items():
        assert template["Resources"][name] == resource
    for name in CHILDREN:
        child = template["Resources"][name]
        assert child["DeletionPolicy"] == child["UpdateReplacePolicy"] == "Retain"
        assert child["Condition"] == "SupportedDeployment"
        assert child["Properties"]["UserPoolId"] == "eu-west-1_AbCdEfGhI"
    assert set(template["Parameters"]) == {"McpResourceUri", "OAuthCallbackURL"}
    assert template["Resources"]["McpUserPoolClient"]["Properties"]["ClientName"] == STACK_NAME + "-client"
    assert template["Resources"]["McpResourceServer"]["Properties"]["Name"] == STACK_NAME


def test_public_client_is_code_only_revocable_and_no_pool_or_domain_is_created():
    template = build()
    client = template["Resources"]["McpUserPoolClient"]["Properties"]
    assert client["GenerateSecret"] is False
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["EnableTokenRevocation"] is True
    assert client["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert not {"AWS::Cognito::UserPool", "AWS::Cognito::UserPoolDomain"} & {
        child["Type"] for child in template["Resources"].values()
    }
    assert template["Metadata"]["NotDeployReady"] is True


def test_templates_are_fresh_and_bad_bindings_are_rejected():
    template = build()
    baseline = deepcopy(template)
    template["Resources"]["McpUserPoolClient"]["Properties"]["GenerateSecret"] = True
    assert build() == baseline
    for api, pool, callback in [
        ("bad", "eu-west-1_AbCdEfGhI", "http://127.0.0.1:8787/callback"),
        ("abcdef1234", "us-east-1_AbCdEfGhI", "http://127.0.0.1:8787/callback"),
        ("abcdef1234", "eu-west-1_AbCdEfGhI", "https://example.com/callback"),
    ]:
        with pytest.raises(ValueError):
            build_retained_dev_oauth_setup(api, pool, callback_url=callback)
