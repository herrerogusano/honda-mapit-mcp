from __future__ import annotations

import pytest

from scripts.dev_multiuser_managed_login import ManagedLoginClient, ManagedLoginError
from scripts.dev_multiuser_test_users import (
    DevMultiuserUserError,
    build_pkce_authorization_url,
    exchange_pkce_code,
    new_pkce_challenge,
)


DOMAIN = "honda-mapit-mcp-dev-multiuser.auth.eu-west-1.amazoncognito.com"
CLIENT = "SyntheticClient123"
CALLBACK = "http://localhost:39031/callback"
RESOURCE = "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp"
SCOPE = RESOURCE + "/use"


def test_managed_login_rejects_non_owned_resource_audience():
    """Self-consistent attacker-controlled resource/scope values are not enough."""
    with pytest.raises(ManagedLoginError, match="configuration_invalid"):
        ManagedLoginClient(
            domain=DOMAIN,
            client_id=CLIENT,
            callback_url=CALLBACK,
            resource="https://evil.example/mcp",
            required_scope="https://evil.example/mcp/use",
            transport=lambda *args: None,
        )


def test_pkce_helpers_reject_non_gateway_scope_and_non_cognito_token_endpoint():
    challenge = new_pkce_challenge()
    with pytest.raises(DevMultiuserUserError, match="pkce_configuration_invalid"):
        build_pkce_authorization_url(
            managed_login_domain=DOMAIN,
            client_id=CLIENT,
            callback_url=CALLBACK,
            required_scope="https://evil.example/mcp/use",
            challenge=challenge,
        )

    calls = []

    def post_form(endpoint, form):
        calls.append((endpoint, form))
        return {
            "access_token": "opaque-access",
            "token_type": "Bearer",
            "expires_in": 900,
            "scope": SCOPE,
        }

    with pytest.raises(DevMultiuserUserError, match="pkce_configuration_invalid"):
        exchange_pkce_code(
            token_endpoint="https://evil.example/oauth2/token",
            client_id=CLIENT,
            callback_url=CALLBACK,
            code="one-time-code",
            challenge=challenge,
            post_form=post_form,
        )
    assert calls == []
