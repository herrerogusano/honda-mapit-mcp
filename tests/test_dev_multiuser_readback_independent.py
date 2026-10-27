from __future__ import annotations

from copy import deepcopy

from tests.test_dev_multiuser_setup_readback import (
    ACCOUNT,
    API,
    CALLBACK,
    CLIENT,
    POOL,
    RUN_ID,
    STACK,
    _clients,
)
from scripts.dev_multiuser_readback import verify_closed_setup


def _verify(clients):
    return verify_closed_setup(
        clients,
        account=ACCOUNT,
        stack_arn=STACK,
        api_id=API,
        user_pool_id=POOL,
        client_id=CLIENT,
        callback_url=CALLBACK,
        original_creation_run_id=RUN_ID,
    )


def test_setup_readback_binds_all_resource_physical_ids():
    """A successful readback must not accept foreign stage/domain/server IDs."""
    for logical_id, foreign_id in (
        ("McpApiStage", "foreign-stage"),
        ("McpUserPoolDomain", "foreign-domain"),
        ("McpResourceServer", "https://foreign.invalid/resource"),
    ):
        clients = _clients()
        original = clients["cloudformation"].describe_stack_resources

        def mutated(*args, _original=original, **kwargs):
            response = deepcopy(_original(*args, **kwargs))
            next(row for row in response["StackResources"] if row["LogicalResourceId"] == logical_id)["PhysicalResourceId"] = foreign_id
            return response

        clients["cloudformation"].describe_stack_resources = mutated
        result = _verify(clients)
        assert result["success"] is False
        assert result["category"] in {"setup_resource_identity_mismatch", "setup_resources_mismatch"}
