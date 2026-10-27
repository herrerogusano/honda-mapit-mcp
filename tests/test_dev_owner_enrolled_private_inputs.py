from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from scripts import dev_owner_enrolled_private_inputs as loader
from scripts.run_aws_closed_rehearsal import FileJournal


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical(value))
    return path


def _private_inputs(tmp_path):
    from scripts.dev_owner_oauth_bootstrap import DevOwnerOAuthBootstrapCoordinator
    from scripts.build_aws_dev_owner_oauth import STACK_NAME as OWNER_STACK_NAME
    from scripts.run_dev_mapit_binding_key_setup import _digest
    from scripts.run_dev_mapit_bootstrap import KIND as MAPIT_KIND
    from scripts.run_dev_owner_assisted_login import load_trusted_owner_policy
    from tests.test_dev_owner_enrolled_runtime_readback import _build_owner_enrolled_current_state_fixture
    from tests.test_dev_owner_enrolled_runtime_readback import ACCOUNT
    from tests.test_dev_owner_login_context import receipt as owner_receipt
    from tests.test_run_dev_owner_invitation import _binding as invitation_binding

    fixture = _build_owner_enrolled_current_state_fixture(tmp_path / "runtime-fixture")
    current, delivery = fixture["current"], fixture["delivery"]
    caller = fixture["mapit_authority"].expected_caller_arn
    owner_auth, owner_binding, owner_state, trusted_policy = owner_receipt()
    owner_auth["expected_caller_arn"] = caller
    owner_binding["operator_user_arn"] = caller
    owner_binding["owner_pool_id"] = trusted_policy.user_pool_id
    owner_binding["api_id"] = delivery.auth["owner_resource_uri"].split("//", 1)[1].split(".", 1)[0]
    owner_binding["authorization_sha256"] = hashlib.sha256(_canonical(owner_auth)).hexdigest()
    owner_binding["state_directory"] = str((tmp_path / "owner" / "state").resolve())

    class NoIO:
        def __getattr__(self, _name):
            def fail(**_kwargs):
                raise AssertionError("historical parser unexpectedly dispatched SDK")
            return fail

    class MemoryJournal:
        def load(self):
            return owner_state
        def save(self, _value):
            raise AssertionError("parser attempted journal mutation")
        def locked(self):
            raise AssertionError("parser attempted journal lock")

    owner_coordinator = DevOwnerOAuthBootstrapCoordinator(
        {"cloudformation": NoIO(), "cognito": NoIO()}, MemoryJournal(),
        account_id=owner_auth["account"], operator_user_arn=caller,
        owner_pool_id=owner_binding["owner_pool_id"], api_id=owner_binding["api_id"],
        callback_url=owner_binding["callback_url"], source_sha=owner_auth["source_sha"],
        run_id=owner_binding["run_uuid"], authorized_from_epoch=owner_auth["start"],
        authorized_until_epoch=owner_auth["end"], expected_context_sha256=owner_binding["context_sha256"],
        context_reader=lambda *_: None, source_checker=lambda: False, readback_validator=lambda *_: None,
    )
    owner_state.update(
        authority_sha256=owner_coordinator.authority_sha256,
        template_sha256=owner_coordinator.template_sha256,
        last_observed_epoch=owner_auth["start"] + 10,
        intent={"token": owner_coordinator._request_token(), "stack_name": OWNER_STACK_NAME,
                "template_sha256": owner_coordinator.template_sha256},
        ack_stack_id=(f"arn:aws:cloudformation:eu-west-1:{owner_auth['account']}:stack/"
                      f"{OWNER_STACK_NAME}/123e4567-e89b-42d3-a456-426614174001"),
        phase="readback_verified",
        readback={"verified": True, "client_id": delivery.auth["owner_client_id"],
                  "readback_sha256": "c" * 64},
    )
    # Keep the independently trusted prod policy tied to the same owner pool.
    from mapit.aws_prod_runtime import CognitoProdPolicy
    trusted_policy = CognitoProdPolicy(trusted_policy.user_pool_id, trusted_policy.api_id,
        trusted_policy.client_id, trusted_policy.owner_subject)

    owner_root = tmp_path / "owner"
    owner_root.mkdir(exist_ok=True)
    owner_auth_path = _write(owner_root / "authorization.json", owner_auth)
    owner_binding_path = _write(owner_root / "owner-oauth-binding.json", owner_binding)
    owner_state_dir = owner_root / "state"
    owner_state_dir.mkdir(exist_ok=True)
    FileJournal(owner_state_dir).save(owner_state)

    # Original production release is metadata only; no secret fields are copied.
    owner_manifest = {"environment": "prod", "region": "eu-west-1", "account_id": ACCOUNT,
        **{name: getattr(trusted_policy, name) for name in (
            "user_pool_id", "api_id", "client_id", "owner_subject")}}
    owner_manifest_sha = hashlib.sha256(_canonical(owner_manifest)).hexdigest()
    release = {"schema": 1, "kind": "cd_delivery_preparation",
        "inventory": {"account": ACCOUNT, "manifest": owner_manifest,
                      "manifest_sha": owner_manifest_sha},
        "final_release_verified": {"exact_readback_verified": True,
                                   "manifest_sha256": owner_manifest_sha}}
    owner_release_path = _write(owner_root / "owner-release.json", release)

    # The accepted invitation is a separate exact flat journal on the existing
    # authorization table; it does not touch the MAPIT binding CAS document.
    invitation_root = tmp_path / "invitation"
    invitation_state_dir = invitation_root / "state"
    invitation_state_dir.mkdir(parents=True)
    invitation_authority = invitation_binding(invitation_state_dir)
    context_sha = owner_binding["context_sha256"]
    invitation_authority.update(
        operator_user_arn=caller,
        owner_context_sha256=context_sha,
        owner_oauth_stack_id=owner_state["ack_stack_id"],
        owner_oauth_client_id=delivery.auth["owner_client_id"],
        github_owner_id=owner_binding["github_owner_id"],
        github_repository_id=owner_binding["github_repository_id"],
        owner_tenant_key=fixture["mapit_authority"]._tenant_keys[0],
        mapit_bootstrap_authority_sha256=fixture["mapit_authority"]._binding_sha256,
        mapit_bootstrap_receipt_sha256=delivery.auth["mapit_bootstrap_receipt_sha256"],
        runtime_evidence_sha256=fixture["mapit_authority"].runtime_evidence_sha256,
        state_directory=str(invitation_state_dir.resolve()),
    )
    from scripts.run_dev_owner_invitation import KIND as INVITATION_KIND
    invitation = {"schema": 1, "kind": INVITATION_KIND, "phase": "invitation_accepted",
        "authority_sha256": hashlib.sha256(_canonical(invitation_authority)).hexdigest(),
        "owner_context_sha256": context_sha,
        "bootstrap_authority_sha256": fixture["mapit_authority"]._binding_sha256,
        "bootstrap_receipt_sha256": delivery.auth["mapit_bootstrap_receipt_sha256"],
        "runtime_evidence_sha256": fixture["mapit_authority"].runtime_evidence_sha256,
        "source_sha": invitation_authority["source_sha"], "run_id": invitation_authority["run_id"],
        "authorized_from_epoch": invitation_authority["authorized_from_epoch"],
        "authorized_until_epoch": invitation_authority["authorized_until_epoch"],
        "owner_key": fixture["mapit_authority"]._tenant_keys[0],
        "table_arn": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
        "write_dispatched": True, "readback_verified": True}
    invitation_authority_path = _write(invitation_root / "authorization.json", invitation_authority)
    FileJournal(invitation_state_dir).save(invitation)

    manifest_inputs = json.loads(delivery.args["manifest_raw"])
    public_config = manifest_inputs["mapit_config"]
    public_config_path = _write(tmp_path / "public-config.json", public_config)

    def jwks_fetcher(url):
        assert url in {
            f"https://cognito-idp.eu-west-1.amazonaws.com/{owner_binding['owner_pool_id']}/.well-known/jwks.json",
            f"https://cognito-idp.eu-west-1.amazonaws.com/{public_config['user_pool_id']}/.well-known/jwks.json",
        }
        if owner_binding["owner_pool_id"] in url:
            return delivery.args["invitation_jwks"]
        return delivery.args["mapit_jwks"]

    inputs = {
        "owner_release_receipt": owner_release_path,
        "owner_oauth_authorization_path": owner_auth_path,
        "owner_oauth_binding_path": owner_binding_path,
        "owner_oauth_state_dir": owner_state_dir,
        "mapit_bootstrap_authority_path": current.mapit_bootstrap_authority_path,
        "mapit_bootstrap_state_dir": current.mapit_bootstrap_state_dir,
        "mapit_publication_state_dir": current.mapit_publication_state_dir,
        "mapit_evidence_path": current.mapit_evidence_path,
        "synthetic_binding_path": current.synthetic_binding_path,
        "synthetic_authorization_path": current.synthetic_authorization_path,
        "synthetic_state_dir": current.synthetic_state_dir,
        "invitation_authorization_path": invitation_authority_path,
        "invitation_state_dir": invitation_state_dir,
        "public_config_path": public_config_path,
        "prior_template": delivery.prior,
        "source_sha": "f" * 40,
        "acl_checker": lambda _path: True,
        "jwks_fetcher": jwks_fetcher,
    }
    return inputs, fixture


def test_private_input_loader_reuses_owning_parsers_and_returns_registered_projection(tmp_path):
    inputs, fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    assert repr(loaded) == "OwnerEnrolledPrivateInputs(<redacted>)"
    assert loaded.assert_unchanged() is True
    assert loaded.manifest_inputs["context"].operator == fixture["mapit_authority"].expected_caller_arn
    assert loaded.manifest_inputs["bootstrap_authority"] is fixture["mapit_authority"] or (
        loaded.manifest_inputs["bootstrap_authority"]._binding_sha256
        == fixture["mapit_authority"]._binding_sha256)
    assert loaded.runtime_binding["template_sha256"] == fixture["runtime_binding"]["template_sha256"]
    assert "password" not in loaded.manifest_inputs["public_config"]
    assert loader._REGISTERED.get(loaded) is not None


def test_private_input_loader_detects_file_drift_after_load(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    config_path = inputs["public_config_path"]
    config = json.loads(config_path.read_bytes())
    config["discovery_enabled"] = not config["discovery_enabled"]
    config_path.write_bytes(_canonical(config))
    assert loaded.assert_unchanged() is False


def test_private_input_loader_detects_returned_projection_mutation(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    loaded.manifest_inputs["source_sha"] = "0" * 40
    assert loaded.assert_unchanged() is False


def test_directly_constructed_projection_is_not_registered(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    forged = loader.OwnerEnrolledPrivateInputs(
        manifest_inputs=loaded.manifest_inputs,
        prior_template=loaded.prior_template,
        runtime_binding=loaded.runtime_binding,
        bootstrap_template=loaded.bootstrap_template,
        fingerprints=(), max_sizes={}, acl_checker=None,
        object_digest="0" * 64,
    )
    assert forged.assert_unchanged() is False


@pytest.mark.parametrize("field", ["context", "bootstrap_authority"])
def test_registered_projection_rejects_equal_value_replacement_of_trusted_objects(tmp_path, field):
    inputs, _fixture = _private_inputs(tmp_path)
    loaded = loader.load_owner_enrolled_private_inputs(**inputs)
    original = loaded.manifest_inputs[field]
    loaded.manifest_inputs[field] = dataclasses.replace(original)
    assert loaded.assert_unchanged() is False


def test_owner_state_directory_must_match_accepted_binding(tmp_path):
    inputs, _fixture = _private_inputs(tmp_path)
    from scripts.run_aws_dev_owner_oauth_bootstrap import _load_binding
    binding = _load_binding(inputs["owner_oauth_binding_path"], acl_checker=lambda _path: True)
    binding["state_directory"] = str((tmp_path / "other-state").resolve())
    inputs["owner_oauth_binding_path"].write_bytes(_canonical(binding))
    with pytest.raises(loader.PrivateInputsError, match="^owner_enrolled_private_inputs_unverified$"):
        loader.load_owner_enrolled_private_inputs(**inputs)


@pytest.mark.parametrize("bad", [
    b'{"region":"eu-west-1","region":"eu-west-1"}',
    _canonical({"region": "eu-west-1", "unexpected": True}),
])
def test_public_config_duplicate_or_unexpected_fields_fail_before_jwks(tmp_path, bad):
    inputs, _fixture = _private_inputs(tmp_path)
    inputs["public_config_path"].write_bytes(bad)
    fetches = []
    inputs["jwks_fetcher"] = lambda url: fetches.append(url)
    with pytest.raises(loader.PrivateInputsError, match="^owner_enrolled_private_inputs_unverified$"):
        loader.load_owner_enrolled_private_inputs(**inputs)
    assert fetches == []
