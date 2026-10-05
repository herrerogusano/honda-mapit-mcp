from __future__ import annotations

import copy

import pytest

from scripts import build_aws_dev_oauth_template as composer
from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template, _read_scaffold


API_ID = "a1b2c3d4e5"
CALLBACK = "http://localhost:39031/callback/synthetic"


def test_setup_is_only_four_oauth_resources_over_the_closed_bootstrap():
    template = composer.build_dev_oauth_setup_template(API_ID, callback_url=CALLBACK)
    base = fixed_bootstrap_template()
    resources = template["Resources"]

    assert set(resources) == set(base["Resources"]) | set(composer._SETUP_RESOURCE_NAMES)
    for name, original in base["Resources"].items():
        updated = resources[name]
        assert updated == original
        if name == "McpHandler":
            assert updated["Properties"]["Code"] == original["Properties"]["Code"]
            assert "Environment" not in updated["Properties"]
        else:
            assert updated == original
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert not {"McpLambdaIntegration", "McpPostRoute", "McpLambdaInvokePermission"} & set(resources)
    assert all(resource["Type"] != "AWS::Cognito::UserPoolUser" for resource in resources.values())
    assert template["Parameters"]["McpResourceUri"]["Default"] == (
        f"https://{API_ID}.execute-api.eu-west-1.amazonaws.com/mcp"
    )
    assert template["Parameters"]["OAuthCallbackURL"]["Default"] == CALLBACK


@pytest.mark.parametrize("value", [False, 0, 5.0, "5", None])
def test_setup_rejects_noncanonical_token_lifetime_values(monkeypatch, value):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"]["McpUserPoolClient"]["Properties"]["AccessTokenValidity"] = value
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)

    with pytest.raises(composer.OAuthTemplateError, match="oauth_client_invalid"):
        composer.build_dev_oauth_setup_template(API_ID, callback_url=CALLBACK)
