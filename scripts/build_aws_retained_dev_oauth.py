"""Offline, closed retained-dev OAuth draft against the existing identity pool.

This composes already-reviewed factories; it never creates a pool, domain,
identity, endpoint route, invocation permission or runtime environment.
Real bindings and a fresh, separately reviewed update/readback are required.
"""
from __future__ import annotations

import copy
from typing import Any

from scripts.build_aws_retained_dev import build_retained_dev_template, STACK_NAME
from scripts.build_aws_shared_identity_dev import build_shared_identity_oauth_setup_retained_template

CHILDREN = ("McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding")


def build_retained_dev_oauth_setup(
    api_id: str, user_pool_id: str, *, callback_url: str,
) -> dict[str, Any]:
    """Eight closed resources, with a dev-specific public PKCE client.

    Pool ownership, the observed API binding, the actual callback registration,
    and unchanged owner/MFA must be verified by the private operator. Syntax
    validation alone is not that evidence.
    """
    source = build_shared_identity_oauth_setup_retained_template(
        api_id, user_pool_id, callback_url=callback_url,
    )
    template = build_retained_dev_template()
    parameters = source["Parameters"]
    template["Parameters"] = {
        name: copy.deepcopy(parameters[name])
        for name in ("McpResourceUri", "OAuthCallbackURL")
    }
    for name in CHILDREN:
        template["Resources"][name] = copy.deepcopy(source["Resources"][name])
    template["Resources"]["McpResourceServer"]["Properties"]["Name"] = STACK_NAME
    template["Resources"]["McpUserPoolClient"]["Properties"]["ClientName"] = STACK_NAME + "-client"
    template["Outputs"].update({
        "UserPoolId": {"Condition": "SupportedDeployment", "Value": user_pool_id},
        "UserPoolClientId": {"Condition": "SupportedDeployment", "Value": {"Ref": "McpUserPoolClient"}},
    })
    template["Metadata"] = {
        "Readiness": "RETAINED_DEV_OAUTH_NOT_DEPLOY_READY",
        "NotDeployReady": True,
        "ExistingPoolAndDomainUnchanged": True,
        "NoNewUserOrMfaReset": True,
        "NoRoutesOrInvocationPermission": True,
        "NoRuntimeSecretsOrData": True,
        "SharedPoolChildrenRetained": True,
        "FreshPrivateBindingUpdateAndReadbackRequired": True,
    }
    template["Description"] = "Closed retained-dev OAuth draft; existing owner identity unchanged."
    return template
