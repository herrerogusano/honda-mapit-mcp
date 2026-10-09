import copy
from pathlib import Path

import pytest

from scripts.dev_owner_enrolled_preparation import (
    assemble_delivery_metadata, _valid_namespace_key_separation,
)
from scripts.dev_owner_enrolled_delivery import _digest
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_template
from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS
from test_dev_owner_enrolled_inputs import _inputs
from tests import test_dev_mapit_bootstrap_coordinator as bootstrap_fixture
from scripts.dev_identity_binding_runtime_evidence import _resolve_context


def inputs(tmp_path, monkeypatch):
    # Match the accepted preparer: bootstrap exclusions are the storage pair;
    # hosted A/B provenance is separately carried by the prior app manifest.
    monkeypatch.setattr(bootstrap_fixture, "HISTORICAL", tuple(f"tenant-{x:064x}" for x in (101,102)))
    manifest_inputs = _inputs(tmp_path, monkeypatch)
    context = manifest_inputs["context"]
    old = tuple(f"tenant-{x:064x}" for x in (103,104))
    prior = build_retained_dev_multiuser_template(api_id=context.policy.api_id,
        bucket="honda-runtime-artifact-test-bucket", zip_sha256="1" * 64,
        source_sha256="2" * 40, jwks_sha256="3" * 64, manifest_sha256="4" * 64,
        account_id=context.account, execution_start_epoch=1900000000,
        execution_end_epoch=1900000300, callback_url="http://localhost:39031/callback",
        subjects=("00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"),
        tenant_keys=old)
    runtime = dict.fromkeys(_BINDING_FIELDS, None)
    runtime.update(account_id=context.account, operator_user_arn=context.operator,
        api_id=context.policy.api_id, template_sha256=_digest(prior),
        tenant_keys=list(manifest_inputs["bootstrap_authority"]._excluded_tenant_keys),
        app_run_id=33, user_pool_id="eu-west-1_Technical123", client_id="historicalclient123",
        ssm_key_arn=manifest_inputs["bootstrap_authority"].ssm_key_arn,
        accepted_runtime_journal_path="private/consumed-runtime",
        github_owner_id=context.github_owner_id, github_repository_id=context.github_repository_id,
        handler_role_arn=f"arn:aws:iam::{context.account}:role/honda-mapit-mcp-dev-retained-handler-role",
        code_sha256="1" * 64, app_stack_arn=f"arn:aws:cloudformation:eu-west-1:{context.account}:stack/honda-mapit-mcp-dev-retained/11111111-1111-4111-8111-111111111111")
    physical = {name: {"PhysicalResourceId": runtime[field]} for name, field in (
        ("McpApi", "api_id"), ("McpUserPool", "user_pool_id"), ("McpUserPoolClient", "client_id"))}
    role = prior["Resources"]["McpHandlerRole"]["Properties"]
    runtime.update(handler_trust_sha256=_digest(role["AssumeRolePolicyDocument"]),
        handler_policies_sha256=_digest({row["PolicyName"]:_resolve_context(row["PolicyDocument"],
            account=context.account,resource_rows=physical) for row in role["Policies"]}))
    return dict(manifest_inputs=manifest_inputs, prior_template=prior, runtime_binding=runtime,
        run_id="a" * 32, ci_run_id=108, start=1900000000, end=1900000600,
        execution_start=1900000200, execution_end=1900000500)


def test_offline_metadata_binds_validated_receipts_without_writes(tmp_path, monkeypatch):
    args = inputs(tmp_path, monkeypatch)
    before = copy.deepcopy({k: v for k, v in args.items() if k != "manifest_inputs"})
    monkeypatch.setattr(Path, "write_bytes", lambda *_a, **_kw: pytest.fail("file write"))
    monkeypatch.setattr(Path, "write_text", lambda *_a, **_kw: pytest.fail("file write"))
    result = assemble_delivery_metadata(**args)
    authority = result["authority"]
    assert authority["owner_oauth_receipt_sha256"] == args["manifest_inputs"]["context"].readback_digest
    assert authority["invitation_receipt_sha256"] == _digest(args["manifest_inputs"]["invitation"])
    assert authority["key_publication_receipt_sha256"] == _digest(args["manifest_inputs"]["publication"])
    assert set(authority["historical_tenant_keys"]).isdisjoint(args["runtime_binding"]["tenant_keys"])
    assert result["accepted"]["invitation"]["revision"] == 1
    bootstrap = args["manifest_inputs"]["bootstrap_authority"]
    assert tuple(bootstrap._excluded_tenant_keys) == tuple(args["runtime_binding"]["tenant_keys"])
    assert set(bootstrap._tenant_keys).isdisjoint(
        set(authority["historical_tenant_keys"]) | set(args["runtime_binding"]["tenant_keys"]))
    assert assemble_delivery_metadata(**args) == result
    assert before == {k: v for k, v in args.items() if k != "manifest_inputs"}


@pytest.mark.parametrize("collision", [101, 102, 103, 104])
def test_owner_key_must_be_fresh_from_both_hosted_and_storage_pairs(collision):
    owner = (f"tenant-{collision:064x}",)
    storage = ("tenant-" + "a" * 64, "tenant-" + "b" * 64)
    hosted = ("tenant-" + "c" * 64, "tenant-" + "d" * 64)
    excluded = storage
    if collision == 101:
        storage = (owner[0], storage[1])
        excluded = storage
    elif collision == 102:
        storage = (storage[0], owner[0])
        excluded = storage
    elif collision == 103:
        hosted = (owner[0], hosted[1])
    else:
        hosted = (hosted[0], owner[0])
    assert not _valid_namespace_key_separation(
        owner_keys=owner, storage_keys=storage, hosted_keys=hosted,
        excluded_keys=excluded)


@pytest.mark.parametrize("change", [
    lambda a: a["runtime_binding"].update(account_id="999999999999"),
    lambda a: a["runtime_binding"].update(template_sha256="0" * 64),
    lambda a: a["runtime_binding"].update(code_sha256="0" * 64),
    lambda a: a["runtime_binding"].update(api_id="wrongapi01"),
    lambda a: a["runtime_binding"].update(tenant_keys=list(a["prior_template"]["Metadata"]["ManifestContract"]["tenants"][i]["key"] for i in (0,1))),
    lambda a: a["runtime_binding"].update(app_run_id=True),
    lambda a: a["runtime_binding"].update(user_pool_id="invalid"),
    lambda a: a["runtime_binding"].update(client_id="invalid!"),
    lambda a: a["runtime_binding"].update(ssm_key_arn="wrong-key"),
    lambda a: a["runtime_binding"].update(handler_trust_sha256="0"*64),
    lambda a: a["runtime_binding"].update(handler_policies_sha256="0"*64),
    lambda a: a["runtime_binding"].update(github_owner_id=999),
    lambda a: a["runtime_binding"].update(app_stack_arn="invalid"),
    lambda a: a["runtime_binding"].update(extra="untrusted"),
    lambda a: a.update(run_id="invalid"),
    lambda a: a.update(ci_run_id=True),
    lambda a: a.update(execution_end=1900000601),
    lambda a: a["manifest_inputs"]["invitation"].update(readback_verified=False),
    lambda a: a["prior_template"]["Resources"]["McpApi"]["Properties"].update(DisableExecuteApiEndpoint=False),
])
def test_crossed_runtime_receipts_windows_or_unaccepted_state_fail(tmp_path, monkeypatch, change):
    args = inputs(tmp_path, monkeypatch)
    change(args)
    with pytest.raises(ValueError, match="^owner_delivery_metadata_unverified$"):
        assemble_delivery_metadata(**args)
