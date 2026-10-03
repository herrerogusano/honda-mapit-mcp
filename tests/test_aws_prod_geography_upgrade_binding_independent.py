from __future__ import annotations

import contextlib

import pytest

from mapit.aws_prod_geography_upgrade import ProdGeographyUpgrade, ProdGeographyUpgradeError
from mapit.aws_prod_runtime import CognitoProdPolicy


class _Journal:
    def load(self):
        return None

    def save(self, value):
        raise AssertionError("constructor must not write the journal")

    @contextlib.contextmanager
    def locked(self):
        yield


def test_same_archive_digest_is_rejected_even_when_manifest_changes():
    account = "123456789012"
    api_id = "a1b2c3d4e5"
    policy = CognitoProdPolicy(
        user_pool_id="eu-west-1_A1b2C3d4E",
        api_id=api_id,
        client_id="SyntheticProdClient012345",
        owner_subject="18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
    )
    clients = {
        name: object()
        for name in ("sts", "cloudformation", "apigatewayv2", "lambda", "stepfunctions", "cloudwatch", "events")
    }

    with pytest.raises(ProdGeographyUpgradeError) as error:
        ProdGeographyUpgrade(
            clients,
            _Journal(),
            policy=policy,
            account_id=account,
            stack_arn=f"arn:aws:cloudformation:eu-west-1:{account}:stack/honda-mapit-mcp-prod/11111111-2222-4333-8444-555555555555",
            prod_run_id="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            api_id=api_id,
            function_name="honda-mapit-mcp-prod-handler",
            shutdown_state_machine_arn=f"arn:aws:states:eu-west-1:{account}:stateMachine:honda-mapit-mcp-prod-shutdown",
            bucket="honda-mapit-mcp-prod-artifacts",
            old_zip_sha256="1" * 64,
            old_manifest_sha256="2" * 64,
            new_zip_sha256="1" * 64,
            new_manifest_sha256="3" * 64,
            authorized_until_epoch=1_791_042_120,
        )
    assert error.value.category == "inputs_invalid"
