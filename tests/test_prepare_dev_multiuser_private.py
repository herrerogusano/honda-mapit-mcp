import json
from pathlib import Path

import pytest

from scripts.prepare_dev_multiuser_private import prepare


def fixture(tmp_path):
    account = "123456789012"
    directories = [tmp_path / name for name in ("app", "roles", "controls")]
    for path in directories:
        path.mkdir()
    auth = dict(account=account, expected_caller_arn=f"arn:aws:iam::{account}:user/operator",
                source_sha="a" * 40, ci_run_id=1, run_id=1, start=1, end=2)
    (directories[0] / "authorization.json").write_text(json.dumps(auth))
    app = dict(readback_verified=True, account_id=account, run_id=1, stack_id="app")
    roles = dict(readback=True, account=account, run_id=2, readback_receipt={"stack_id": "roles"})
    controls = dict(readback=True, account=account, run_id=3, readback_receipt={"stack_id": "controls"})
    for path, value in zip(directories, (app, roles, controls)):
        (path / "rehearsal-state.json").write_text(json.dumps(value))
    return dict(parent=tmp_path, app_directory=directories[0], roles_directory=directories[1],
                controls_directory=directories[2], source_sha="b" * 40, ci_run_id=7,
                acl_checker=lambda path: True, clock=lambda: 100)


def test_fresh_private_envelopes_do_not_replay_old_authority(tmp_path):
    args = fixture(tmp_path)
    old = (args["app_directory"] / "authorization.json").read_bytes()
    target = prepare(**args)
    value = json.loads((target / "authorization.json").read_text())
    assert value["start"] == 100 and value["end"] == 3700
    assert value["source_sha"] == "b" * 40 and value["ci_run_id"] == 7
    assert (args["app_directory"] / "authorization.json").read_bytes() == old
    assert len(list(target.iterdir())) == 7
    second = prepare(**args)
    assert second != target


@pytest.mark.parametrize("field,value", [("source_sha", "bad"), ("ci_run_id", 0)])
def test_invalid_fresh_bindings_create_nothing(tmp_path, field, value):
    args = fixture(tmp_path)
    before = set(tmp_path.iterdir())
    args[field] = value
    with pytest.raises(ValueError):
        prepare(**args)
    assert set(tmp_path.iterdir()) == before


def test_unaccepted_history_creates_nothing(tmp_path):
    args = fixture(tmp_path)
    path = args["roles_directory"] / "rehearsal-state.json"
    value = json.loads(path.read_text())
    value["readback"] = False
    path.write_text(json.dumps(value))
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError, match="historical_acceptance_required"):
        prepare(**args)
    assert set(tmp_path.iterdir()) == before


def test_optional_artifact_binding_preserves_original_accepted_metadata(tmp_path):
    args = fixture(tmp_path)
    directory = tmp_path / "artifacts"
    directory.mkdir()
    stack = ("arn:aws:cloudformation:eu-west-1:123456789012:stack/"
             "honda-mapit-mcp-dev-retained-runtime-artifacts/12345678-1234-1234-1234-123456789012")
    receipt = dict(readback=True, account="123456789012", run_id=4,
                   readback_receipt={"stack_id": stack})
    path = directory / "rehearsal-state.json"
    path.write_text(json.dumps(receipt))
    original = path.read_bytes()
    target = prepare(**args, artifact_directory=directory)
    assert json.loads((target / "artifact-binding.json").read_text()) == {
        "stack_arn": stack, "original_creation_run_id": 4}
    assert path.read_bytes() == original
    receipt["readback"] = False
    path.write_text(json.dumps(receipt))
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError, match="historical_acceptance_required"):
        prepare(**args, artifact_directory=directory)
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("receipt", [
    dict(readback=True, account="123456789012", run_id=4),
    dict(readback=True, account="123456789012", run_id=True, readback_receipt={"stack_id": "wrong"}),
])
def test_invalid_artifact_metadata_has_no_partial_outputs(tmp_path, receipt):
    args = fixture(tmp_path)
    directory = tmp_path / "artifacts"
    directory.mkdir()
    (directory / "rehearsal-state.json").write_text(json.dumps(receipt))
    before = set(tmp_path.iterdir())
    with pytest.raises(ValueError, match="metadata_invalid"):
        prepare(**args, artifact_directory=directory)
    assert set(tmp_path.iterdir()) == before
