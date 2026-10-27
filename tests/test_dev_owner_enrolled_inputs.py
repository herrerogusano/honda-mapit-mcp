import copy
import json
from dataclasses import replace

import pytest

from scripts.dev_owner_enrolled_inputs import build_owner_manifest
from scripts.run_dev_mapit_binding_key_setup import _digest, build_plan
from scripts.run_dev_owner_invitation import KIND
from tests.test_dev_owner_login_context import receipt, parse
from tests import test_dev_mapit_bootstrap_coordinator as bootstrap_fixture
from tests.test_run_dev_mapit_binding_key_setup import _accepted_coordinator_state
from tests.test_run_dev_owner_invitation import _binding
from tests.test_dev_enrolled_manifest import _manifest


def _inputs(tmp_path, monkeypatch):
    context = parse(receipt())
    monkeypatch.setattr(bootstrap_fixture, "CALLER", context.operator)
    monkeypatch.setattr(bootstrap_fixture, "FRESH", bootstrap_fixture.FRESH[:1])
    coordinator, state = _accepted_coordinator_state()
    authority = coordinator.authority
    digest = _digest({"authority_sha256": authority._binding_sha256,
        "intent": state["intent"], "readback_receipt": state["readback_receipt"],
        "template_sha256": build_plan(authority).template_sha256})
    ia = _binding(tmp_path / "state")
    ia.update(owner_context_sha256=context.context_digest,
        github_owner_id=context.github_owner_id, github_repository_id=context.github_repository_id,
        owner_oauth_stack_id=context.stack_id, owner_oauth_client_id=context.policy.client_id,
        owner_tenant_key=authority._tenant_keys[0],
        mapit_bootstrap_authority_sha256=authority._binding_sha256,
        mapit_bootstrap_receipt_sha256=digest,
        runtime_evidence_sha256=authority.runtime_evidence_sha256)
    invitation = {"schema": 1, "kind": KIND, "phase": "invitation_accepted",
        "authority_sha256": _digest(ia), "owner_context_sha256": context.context_digest,
        "bootstrap_authority_sha256": authority._binding_sha256,
        "bootstrap_receipt_sha256": digest, "runtime_evidence_sha256": authority.runtime_evidence_sha256,
        "source_sha": ia["source_sha"], "run_id": ia["run_id"],
        "authorized_from_epoch": ia["authorized_from_epoch"],
        "authorized_until_epoch": ia["authorized_until_epoch"],
        "owner_key": authority._tenant_keys[0],
        "table_arn": f"arn:aws:dynamodb:eu-west-1:{context.account}:table/honda-mapit-mcp-dev-tenants",
        "write_dispatched": True, "readback_verified": True}
    manifest, jwks, mapit = _manifest()
    publication = {"schema": 1, "operation": "dev_mapit_binding_key_publication",
        "namespace": "mapit", "account": context.account, "source": "9" * 40,
        "run_id": authority.run_id + 1, "bootstrap_sha256": digest,
        "parameter_path": manifest["key_parameter_path"], "start": 1900000000,
        "end": 1900000600, "phase": "accepted"}
    return {"context": context, "bootstrap_authority": authority, "bootstrap_state": state,
        "publication": publication, "invitation_authority": ia, "invitation": invitation,
        "public_config": manifest["mapit_config"], "source_sha": "8" * 40,
        "invitation_jwks": jwks, "mapit_jwks": mapit}


def test_manifest_uses_only_bound_owner_key_identity_config_and_publication_window(tmp_path, monkeypatch):
    args = _inputs(tmp_path, monkeypatch)
    before = copy.deepcopy({k: v for k, v in args.items() if isinstance(v, dict)})
    value = json.loads(build_owner_manifest(**args))
    assert value["tenants"] == [{"key": args["bootstrap_authority"]._tenant_keys[0],
                                  "subject": args["context"].policy.owner_subject}]
    assert value["api_id"] == args["context"].policy.api_id
    assert value["user_pool_id"] == args["context"].policy.user_pool_id
    assert value["client_id"] == args["context"].policy.client_id
    assert value["key_publication_start_epoch"] == args["publication"]["start"]
    assert value["key_publication_end_epoch"] == args["publication"]["end"]
    assert value["mapit_config"] == args["public_config"]
    assert before == {k: v for k, v in args.items() if isinstance(v, dict)}


@pytest.mark.parametrize("change", [
    lambda a: a.update(context=replace(a["context"])),
    lambda a: a["bootstrap_state"].update(readback=False),
    lambda a: a["invitation"].update(phase="write_acknowledged"),
    lambda a: a["invitation"].update(run_id=True),
    lambda a: a["invitation"].update(owner_key="tenant-" + "a" * 64),
    lambda a: a["invitation_authority"].update(owner_oauth_client_id="anotherclient123"),
    lambda a: a["invitation"].update(extra="untrusted"),
    lambda a: a["publication"].update(phase="put_intent"),
    lambda a: a["publication"].update(schema=True),
    lambda a: a["publication"].update(bootstrap_sha256="0" * 64),
    lambda a: a["public_config"].update(password="never-copy-this"),
    lambda a: a["public_config"].update(discovery_enabled=1),
    lambda a: a.update(source_sha="0" * 40),
    lambda a: a.update(mapit_jwks=b"not-keys"),
])
def test_crossed_unaccepted_or_credential_bearing_inputs_fail_closed(tmp_path, monkeypatch, change):
    args = _inputs(tmp_path, monkeypatch)
    change(args)
    with pytest.raises(ValueError, match="^owner_manifest_inputs_unverified$"):
        build_owner_manifest(**args)
