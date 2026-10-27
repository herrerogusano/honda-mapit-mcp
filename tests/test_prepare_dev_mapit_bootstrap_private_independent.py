from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import prepare_dev_mapit_bootstrap_private as module
from scripts.dev_mapit_bootstrap_contract import build_plan
from scripts.run_dev_mapit_bootstrap import ci_evidence_digest, load_runner_authority
from tests.test_run_aws_dev_identity_binding_bootstrap import _auth, _binding


def _fixture(tmp_path: Path):
    parent = tmp_path / "private"
    parent.mkdir()
    history = parent / "historical"
    history.mkdir()
    binding = _binding()
    binding_path = history / "binding.json"
    auth_path = history / "authorization.json"
    state_dir = history / "state"
    state_dir.mkdir()
    binding_path.write_text(json.dumps(binding, sort_keys=True), encoding="utf-8")
    auth_path.write_text(json.dumps(_auth(), sort_keys=True), encoding="utf-8")
    state_path = state_dir / "rehearsal-state.json"
    state_path.write_text(json.dumps({"historical": "fixture", "phase": "accepted"},
                                     sort_keys=True), encoding="utf-8")
    source_calls = []
    protection_calls = []
    kwargs = dict(
        parent=parent,
        synthetic_binding_path=binding_path,
        synthetic_authorization_path=auth_path,
        synthetic_state_dir=state_dir,
        source_sha="f" * 40,
        ci_run_id=808,
        acl_checker=lambda _path: True,
        clock=lambda: 1_800_000_000.5,
        monotonic=lambda: 100.0,
        source_validator=lambda authorization: source_calls.append(dict(authorization)),
        protection_validator=lambda github: protection_calls.append(dict(github)),
    )
    return {
        "parent": parent, "history": history, "binding": binding,
        "binding_path": binding_path, "auth_path": auth_path,
        "state_path": state_path, "source_calls": source_calls,
        "protection_calls": protection_calls, "kwargs": kwargs,
    }


def test_preparer_binds_fresh_one_key_and_exact_historical_raw_bytes(tmp_path):
    fixture = _fixture(tmp_path)
    historical_before = {path: path.read_bytes() for path in fixture["history"].rglob("*") if path.is_file()}
    target = module.prepare(**fixture["kwargs"])
    assert target.parent == fixture["parent"]
    assert target.name.startswith("mb-")
    assert (target / "bootstrap").is_dir()
    assert set(path.name for path in target.iterdir()) == {
        "bootstrap", "runtime-evidence.json", "authority.json",
    }
    assert {path: path.read_bytes() for path in fixture["history"].rglob("*") if path.is_file()} == historical_before

    envelope = json.loads((target / "authority.json").read_bytes())
    evidence = json.loads((target / "runtime-evidence.json").read_bytes())
    authority, source, github = load_runner_authority(target / "authority.json", acl_checker=lambda _: True)
    assert source == envelope["source_authorization"]
    assert github == envelope["github"]
    assert len(authority._tenant_keys) == 1
    assert set(authority._tenant_keys).isdisjoint(fixture["binding"]["tenant_keys"])
    assert authority._excluded_tenant_keys == tuple(fixture["binding"]["tenant_keys"])
    assert evidence["runtime_binding"] == fixture["binding"]
    assert evidence["synthetic_binding_sha256"] == hashlib.sha256(historical_before[fixture["binding_path"]]).hexdigest()
    assert evidence["synthetic_authorization_sha256"] == hashlib.sha256(historical_before[fixture["auth_path"]]).hexdigest()
    assert evidence["synthetic_state_sha256"] == hashlib.sha256(historical_before[fixture["state_path"]]).hexdigest()
    assert evidence["mapit_plan_sha256"] == build_plan(authority).template_sha256
    assert authority.runtime_evidence_sha256 == module.runtime_evidence_digest(evidence)
    assert authority.ci_evidence_sha256 == ci_evidence_digest(source, github)
    assert source["start"] == 1_800_000_000 and source["end"] == 1_800_000_600
    assert fixture["source_calls"] == [source]
    assert fixture["protection_calls"] == [github]
    # Historical data is represented only by private-file hashes in the new
    # runtime bundle; no synthetic receipt is labeled current acceptance.
    assert set(evidence) == {
        "schema", "kind", "account_id", "caller_arn", "source_sha", "run_id",
        "authorized_from_epoch", "authorized_until_epoch", "mapit_plan_sha256",
        "runtime_binding", "synthetic_binding_sha256",
        "synthetic_authorization_sha256", "synthetic_state_sha256",
    }


@pytest.mark.parametrize("gate", ["source", "protection"])
def test_gate_failure_precedes_any_private_directory_creation(tmp_path, gate):
    fixture = _fixture(tmp_path)
    if gate == "source":
        def source(_authorization):
            assert list(fixture["parent"].iterdir()) == [fixture["history"]]
            raise RuntimeError("sensitive source output")
        fixture["kwargs"].update(source_validator=source,
                                 protection_validator=lambda _github: pytest.fail("protection called"))
    else:
        def protection(_github):
            assert list(fixture["parent"].iterdir()) == [fixture["history"]]
            raise RuntimeError("sensitive protection output")
        fixture["kwargs"].update(source_validator=lambda _authorization: None,
                                 protection_validator=protection)
    with pytest.raises(ValueError, match="mapit_private_preparation_unverified") as exc:
        module.prepare(**fixture["kwargs"])
    assert "sensitive" not in str(exc.value)
    assert list(fixture["parent"].iterdir()) == [fixture["history"]]


def test_expired_monotonic_budget_stops_before_creating_private_authority(tmp_path):
    fixture = _fixture(tmp_path)
    ticks = iter((5.0, 6.0, 126.0))
    fixture["kwargs"].update(monotonic=lambda: next(ticks))
    with pytest.raises(ValueError, match="mapit_private_preparation_unverified"):
        module.prepare(**fixture["kwargs"])
    assert list(fixture["parent"].iterdir()) == [fixture["history"]]


def test_failure_after_first_envelope_write_retains_private_partial_state(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    original = module._exclusive_json
    writes = []

    def fail_second(path, value, *, acl_checker):
        writes.append(Path(path).name)
        if len(writes) == 2:
            raise OSError("private failure details")
        return original(path, value, acl_checker=acl_checker)

    monkeypatch.setattr(module, "_exclusive_json", fail_second)
    with pytest.raises(ValueError, match="mapit_private_preparation_unverified") as exc:
        module.prepare(**fixture["kwargs"])
    assert "private failure" not in str(exc.value)
    assert writes == ["runtime-evidence.json", "authority.json"]
    created = [path for path in fixture["parent"].iterdir() if path != fixture["history"]]
    assert len(created) == 1 and created[0].is_dir()
    assert (created[0] / "runtime-evidence.json").is_file()
    assert not (created[0] / "authority.json").exists()


def test_collision_is_not_retried_or_overwritten(tmp_path, monkeypatch):
    fixture = _fixture(tmp_path)
    collision = fixture["parent"] / "mb-123456789abc"
    collision.mkdir()
    sentinel = collision / "sentinel"
    sentinel.write_text("keep", encoding="ascii")
    # The tenant key is generated first (32 bytes); keep it valid and distinct
    # so this test reaches the later, exclusive directory creation collision.
    monkeypatch.setattr(
        module.secrets, "token_hex",
        lambda count: "a" * 64 if count == 32 else "123456789abc",
    )
    attempted = []
    create_private_directory = module._create_private_directory

    def record_directory(path, acl_checker):
        attempted.append(Path(path))
        return create_private_directory(path, acl_checker)

    monkeypatch.setattr(module, "_create_private_directory", record_directory)
    with pytest.raises(ValueError, match="mapit_private_preparation_unverified"):
        module.prepare(**fixture["kwargs"])
    assert attempted == [collision]
    assert sentinel.read_text(encoding="ascii") == "keep"
    assert set(path.name for path in fixture["parent"].iterdir()) == {"historical", collision.name}
