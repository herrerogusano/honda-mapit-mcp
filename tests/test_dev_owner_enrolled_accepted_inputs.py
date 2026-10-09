from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from scripts import dev_owner_enrolled_accepted_inputs as loader
from scripts.dev_owner_enrolled_observation import make_capsule
from scripts.dev_owner_enrolled_private_inputs import load_owner_enrolled_private_inputs
from scripts.dev_owner_enrolled_preparation import assemble_delivery_metadata
from tests.test_dev_owner_enrolled_private_inputs import _private_inputs


def _write(root, relative, value):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else loader._canonical(value))


def _accepted(tmp_path):
    original_args, fixture = _private_inputs(tmp_path / "historical")
    # The shared private-loader fixture predates the runtime fixture's GitHub
    # identity binding. Rebind the synthetic metadata consistently before the
    # real parsers consume it; no verifier or owning parser is replaced.
    from scripts.run_aws_closed_rehearsal import FileJournal
    binding_path = original_args["owner_oauth_binding_path"]
    binding = json.loads(binding_path.read_bytes())
    binding["github_owner_id"], binding["github_repository_id"] = 12, 34
    binding_path.write_bytes(loader._canonical(binding))
    invitation_path = original_args["invitation_authorization_path"]
    invitation = json.loads(invitation_path.read_bytes())
    invitation["github_owner_id"], invitation["github_repository_id"] = 12, 34
    invitation_path.write_bytes(loader._canonical(invitation))
    journal = FileJournal(original_args["invitation_state_dir"])
    state = journal.load()
    state["authority_sha256"] = hashlib.sha256(loader._canonical(invitation)).hexdigest()
    journal.save(state)
    original = load_owner_enrolled_private_inputs(**original_args)
    old = fixture["delivery"]
    auth = old.auth
    assembled = assemble_delivery_metadata(manifest_inputs=original.manifest_inputs,
        prior_template=original.prior_template, runtime_binding=original.runtime_binding,
        run_id=auth["run_id"], ci_run_id=auth["ci_run_id"],
        start=auth["authorized_from_epoch"], end=auth["authorized_until_epoch"],
        execution_start=auth["execution_start_epoch"], execution_end=auth["execution_end_epoch"])
    manifest = assembled["manifest_raw"]
    invitation = original.manifest_inputs["invitation_jwks"]
    mapit = original.manifest_inputs["mapit_jwks"]
    archive_io = io.BytesIO()
    from mapit.dev_enrolled_manifest import MANIFEST_FILENAME, INVITATION_JWKS_FILENAME, MAPIT_JWKS_FILENAME
    with zipfile.ZipFile(archive_io, "w") as archive:
        for name, raw in ((MANIFEST_FILENAME, manifest), (INVITATION_JWKS_FILENAME, invitation),
                          (MAPIT_JWKS_FILENAME, mapit)):
            archive.writestr("mapit/" + name, raw)
    payload = archive_io.getvalue()
    summary = dict(old.summary, zip_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest())
    coordinator = loader.OwnerEnrolledClosedDelivery(authority=assembled["authority"],
        accepted=assembled["accepted"], prior_template=original.prior_template,
        mapit_bootstrap_template=original.bootstrap_template, manifest_raw=manifest,
        invitation_jwks=invitation, mapit_jwks=mapit, archive_bytes=payload,
        archive_summary=summary, artifact_journal=object(), update_journal=object(),
        source_check=loader._forbidden, protection_check=loader._forbidden,
        current_state=loader._forbidden, publish_once=loader._forbidden, update_once=loader._forbidden)
    capsule = make_capsule(delivery_binding=coordinator.binding,
        progress={"resource_ids": {"Resource" + str(i): "physical-" + str(i) for i in range(19)},
                  "historical_row_sha256": {"tenant_a": "a" * 64, "tenant_b": "b" * 64},
                  "authorization_table_id": "11111111-1111-4111-8111-111111111111",
                  "synthetic_policy_sha256": "c" * 64},
        target_template_sha256=coordinator.target_sha, artifact_sha256=coordinator.zip_sha,
        owner_context_sha256="d" * 64, accepted_read_call_count=150)
    root = tmp_path / "delivery"
    artifact = {"binding": coordinator.binding, "phase": "published",
                "receipt": coordinator._expected_artifact_receipt()}
    update = {"binding": coordinator.binding, "phase": "accepted", "receipt": {
        "target_template_sha256": coordinator.target_sha, "artifact_sha256": coordinator.zip_sha,
        "completion_event_token": coordinator.binding["client_request_token"],
        "owner_context_sha256": capsule["owner_context_sha256"],
        "runtime_evidence_sha256": capsule["runtime_evidence_sha256"]}}
    for name, value in {
        "authorization.json": assembled["authority"], "inputs/prior-template.json": original.prior_template,
        "inputs/archive-summary.json": summary, "inputs/manifest.json": manifest,
        "inputs/invitation-jwks.json": invitation, "inputs/mapit-jwks.json": mapit,
        "runtime.zip": payload, "artifact-intent/rehearsal-state.json": {"schema": 1, "delivery_state": artifact},
        "update-intent/rehearsal-state.json": {"schema": 1, "delivery_state": update},
        "observation-capsule.json": capsule,
    }.items():
        _write(root, name, value)
    private_paths = {k: v for k, v in original_args.items()
                     if k not in {"prior_template", "source_sha", "acl_checker", "jwks_fetcher"}}
    return root, private_paths, assembled, capsule


def test_loads_expired_original_delivery_without_io_or_authority_renewal(tmp_path, monkeypatch):
    root, paths, assembled, capsule = _accepted(tmp_path)
    from scripts.dev_owner_enrolled_delivery import OwnerEnrolledClosedDelivery
    for method in ("preflight", "publish", "update", "readback"):
        monkeypatch.setattr(OwnerEnrolledClosedDelivery, method, loader._forbidden)
    result = loader.load_accepted_owner_delivery(delivery_root=root, private_paths=paths,
                                                acl_checker=lambda _: True)
    assert result.authority == assembled["authority"]
    assert result.capsule == capsule
    assert result.assert_unchanged() is True
    assert repr(result) == "AcceptedDeliveryInputs(<redacted>)"
    result.capsule["progress"]["synthetic_policy_sha256"] = "f" * 64
    assert result.assert_unchanged() is False


@pytest.mark.parametrize("relative", ["inputs/prior-template.json", "inputs/archive-summary.json",
    "inputs/manifest.json", "runtime.zip", "artifact-intent/rehearsal-state.json",
    "update-intent/rehearsal-state.json", "observation-capsule.json"])
def test_rejects_missing_accepted_input(tmp_path, relative):
    root, paths, _, _ = _accepted(tmp_path)
    (root / relative).unlink()
    with pytest.raises(loader.AcceptedDeliveryInputsError, match="^accepted_delivery_inputs_unverified$"):
        loader.load_accepted_owner_delivery(delivery_root=root, private_paths=paths, acl_checker=lambda _: True)


@pytest.mark.parametrize("mutation", ["intent", "artifact_receipt", "binding", "capsule", "duplicate"])
def test_rejects_nonterminal_or_crossed_receipts_before_any_sdk(tmp_path, mutation):
    root, paths, _, _ = _accepted(tmp_path)
    relative = "update-intent/rehearsal-state.json"
    value = json.loads((root / relative).read_bytes())
    if mutation == "intent":
        value["delivery_state"]["phase"] = "intent"
    elif mutation == "binding":
        value["delivery_state"]["binding"]["authority"]["run_id"] = "f" * 32
    elif mutation == "artifact_receipt":
        relative = "artifact-intent/rehearsal-state.json"
        value = json.loads((root / relative).read_bytes())
        value["delivery_state"]["receipt"]["head_content_length"] += 1
    elif mutation == "capsule":
        relative = "observation-capsule.json"
        value = json.loads((root / relative).read_bytes())
        value["progress"]["authorization_table_id"] = "22222222-2222-4222-8222-222222222222"
    else:
        value = b'{"schema":1,"schema":1,"delivery_state":{}}'
    _write(root, relative, value)
    with pytest.raises(loader.AcceptedDeliveryInputsError):
        loader.load_accepted_owner_delivery(delivery_root=root, private_paths=paths, acl_checker=lambda _: True)


def test_rechecks_private_file_identity_after_load(tmp_path):
    root, paths, _, _ = _accepted(tmp_path)
    result = loader.load_accepted_owner_delivery(delivery_root=root, private_paths=paths,
                                                acl_checker=lambda _: True)
    path = root / "inputs/archive-summary.json"
    raw = path.read_bytes()
    path.unlink()
    path.write_bytes(raw)
    assert result.assert_unchanged() is False
