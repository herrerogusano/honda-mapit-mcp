"""Independent holdout tests for the invitation-only multiuser stack (offline).

Tests marked ``xfail(strict=True)`` document defects found in review: they
assert the *desired* behaviour and currently fail. When a defect is fixed the
test starts passing and strict xfail turns it into a failure, so remove the
marker then.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mapit import multiuser_entrypoint as entry
from mapit import multiuser_identity as identity
from mapit.multiuser_common import STATUS_INVITED, session_parameter_name, table_name
from scripts import deploy_multiuser as deploy
from scripts import mcp_users
from scripts.build_multiuser_stack import build_multiuser_template

from tests.test_multiuser_identity import (  # reuse the existing offline fakes
    EMAIL, MAPIT_CONFIG, PASSWORD, TENANT, Context, ConditionalCheckFailed, _item, _migration_event,
    fakes,  # noqa: F401  (pytest fixture)
)
from tests.test_mcp_users import FakeCfn as UsersCfn, FakeCognito, FakeDynamo as UsersDynamo, FakeSsm


# --- deploy private config vs. runtime MAPIT config parser -----------------------

def _private(tmp_path: Path, mapit: dict) -> Path:
    path = tmp_path / "private.json"
    path.write_text(json.dumps({
        "domain_prefix": "hm-mapit-dev", "codex_callback_url": "http://127.0.0.1:1455/auth/callback",
        "codex_callback_port": 1455, "mapit_config": mapit, "privacy_contact": "owner@example.com",
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize("mapit", [
    {**MAPIT_CONFIG, "frontend_url": "https://app.mapit.me"},           # allowed key, rejected at runtime
    {k: v for k, v in MAPIT_CONFIG.items() if k != "http_timeout"},     # subset accepted by deploy
])
def test_deploy_rejects_mapit_config_that_runtime_cannot_parse(tmp_path, mapit):
    accepted = True
    try:
        config = deploy.load_private_config(_private(tmp_path, mapit), "dev")
    except deploy.DeployError:
        accepted = False
    if accepted:
        # If deploy accepts it, both runtime parsers must accept it too.
        entry._parse_mapit_config(config.mapit_config_json)
        identity._mapit_config({"MAPIT_CONFIG_JSON": config.mapit_config_json})


# --- migration trigger -----------------------------------------------------------

def test_migration_password_not_in_returned_attributes_and_tenant_from_table(fakes):
    dynamo, ssm, _ = fakes
    dynamo.items[EMAIL] = _item("accepted")
    event = _migration_event()
    event["request"]["clientMetadata"] = {"custom:tenant_id": "f" * 32}  # attacker-supplied
    result = identity.handler(event, Context())
    attrs = result["response"]["userAttributes"]
    assert attrs["custom:tenant_id"] == TENANT
    assert PASSWORD not in json.dumps(result["response"])
    assert list(ssm.parameters) == [session_parameter_name("dev", TENANT)]


def test_token_generation_ignores_client_metadata(fakes):
    event = {"triggerSource": "TokenGeneration_HostedAuth",
             "request": {"userAttributes": {"custom:tenant_id": TENANT},
                         "clientMetadata": {"mapit_tenant": "f" * 32}}, "response": {}}
    claims = identity.handler(event, Context())["response"]["claimsAndScopeOverrideDetails"]
    assert claims["accessTokenGeneration"]["claimsToAddOrOverride"] == {"mapit_tenant": TENANT}


def test_migration_does_not_leave_session_when_item_update_fails(fakes):
    dynamo, ssm, _ = fakes
    dynamo.items[EMAIL] = _item("accepted")
    original = dynamo.update_item

    def revoked_meanwhile(**kwargs):
        dynamo.items.pop(EMAIL, None)  # owner revoke between put_parameter and update_item
        return original(**kwargs)

    dynamo.update_item = revoked_meanwhile
    with pytest.raises(identity.IdentityError):
        identity.handler(_migration_event(), Context())
    assert ssm.parameters == {}


def test_migration_messages_do_not_reveal_invited_emails(fakes):
    """Fixed property: not-invited and wrong password share one message."""
    dynamo, _, mapit = fakes
    with pytest.raises(identity.IdentityError) as missing:
        identity.handler(_migration_event(user="nobody@example.com"), Context())
    dynamo.items[EMAIL] = _item("accepted")
    mapit.mode = "reject"
    with pytest.raises(identity.IdentityError) as wrong:
        identity.handler(_migration_event(), Context())
    assert str(missing.value) == str(wrong.value)  # invitation existence is not observable


def test_migration_sends_typed_email_to_mapit(fakes):
    """Fixed property: MAPIT receives the email as typed (trimmed); the table uses the normalized one."""
    dynamo, _, mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    identity.handler(_migration_event(user="Friend@Example.com"), Context())
    assert mapit.calls[0][0] == "Friend@Example.com"


# --- invitation page -----------------------------------------------------------------

def test_invitation_link_with_plus_address_roundtrips(fakes):
    dynamo, _, _ = fakes
    admin = mcp_users.UserAdmin("dev", mcp_users.Clients(UsersCfn(), UsersDynamo(), FakeCognito(), FakeSsm()),
                                out=lambda _l: None, token_factory=lambda: "T" * 43)
    link = admin.invite("a+b@example.com")
    query = link.split("?", 1)[1]
    event = {"rawPath": "/invitacion", "rawQueryString": query,
             "requestContext": {"http": {"method": "GET", "path": "/invitacion"}}}
    response = identity.handler(event, Context())
    assert response["statusCode"] == 200 and "a+b@example.com" in response["body"]


# --- mcp_users -------------------------------------------------------------------------

def test_relink_does_not_bypass_consent():
    dynamo = UsersDynamo()
    dynamo.items[EMAIL] = {"email": {"S": EMAIL}, "tenant_id": {"S": TENANT}, "status": {"S": STATUS_INVITED}}
    admin = mcp_users.UserAdmin("dev", mcp_users.Clients(UsersCfn(), dynamo, FakeCognito(), FakeSsm()),
                                out=lambda _l: None)
    try:
        admin.relink(EMAIL)
    except mcp_users.UsersError:
        pass
    assert dynamo.items[EMAIL]["status"]["S"] == STATUS_INVITED


# --- template ------------------------------------------------------------------------

def _resources(env="dev"):
    return build_multiuser_template(env)["Resources"]


def test_tenant_attribute_immutable_and_not_client_writable():
    resources = _resources()
    schema = resources["UserPool"]["Properties"]["Schema"]
    assert [item["Mutable"] for item in schema if item["Name"] == "tenant_id"] == [False]
    for name in ("ClaudeClient", "CodexClient"):
        assert "custom:tenant_id" not in resources[name]["Properties"]["WriteAttributes"]
    assert resources["UserPool"]["Properties"]["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True


def test_env_names_match_template_for_both_functions():
    resources = _resources()
    mcp_vars = set(resources["McpFunction"]["Properties"]["Environment"]["Variables"])
    assert mcp_vars | {"AWS_LAMBDA_FUNCTION_NAME", "AWS_REGION"} == set(entry.ENV_NAMES)
    identity_vars = set(resources["IdentityFunction"]["Properties"]["Environment"]["Variables"])
    assert identity_vars == {"MAPIT_MCP_ENV", "MULTIUSER_TABLE", "MAPIT_CONFIG_JSON", "MULTIUSER_RESOURCE_URL",
                             "MULTIUSER_PUBLIC_CONFIG_PARAMETER", "MULTIUSER_CODEX_CALLBACK_PORT",
                             "MULTIUSER_PRIVACY_CONTACT"}


def test_routes_match_lambda_adapter_paths():
    from mapit.lambda_adapter import _ALLOWED_PATHS
    routes = {r["Properties"]["RouteKey"]: r["Properties"] for r in _resources().values()
              if r["Type"] == "AWS::ApiGatewayV2::Route"}
    mcp_paths = {key.split(" ", 1)[1] for key, props in routes.items()
                 if props["Target"]["Fn::Join"][1][1]["Ref"] == "McpIntegration"}
    assert mcp_paths == set(_ALLOWED_PATHS)
    assert routes["POST /mcp"]["AuthorizationType"] == "JWT"


def test_pool_password_policy_is_permissive_for_migrated_passwords():
    policy = _resources()["UserPool"]["Properties"].get("Policies", {}).get("PasswordPolicy")
    assert policy is not None
    assert not any(policy.get(flag, True) for flag in
                   ("RequireUppercase", "RequireLowercase", "RequireNumbers", "RequireSymbols"))


def test_clients_cannot_change_email():
    for name in ("ClaudeClient", "CodexClient"):
        assert "email" not in _resources()[name]["Properties"]["WriteAttributes"]
