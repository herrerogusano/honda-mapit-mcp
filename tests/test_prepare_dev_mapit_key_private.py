from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts import prepare_dev_mapit_key_private as module
from scripts.run_dev_mapit_binding_key_setup import _CONFIG_FIELDS
from tests.test_dev_mapit_binding_key_setup import CONFIG
from tests.test_run_dev_owner_assisted_login import owner_receipt


def _fixture(tmp_path, monkeypatch):
    parent = tmp_path / "private"
    parent.mkdir()
    historical = parent / "history"
    historical.mkdir()
    bootstrap_state = historical / "bootstrap"
    bootstrap_state.mkdir()
    synthetic_state = historical / "synthetic"
    synthetic_state.mkdir()
    authority_path = historical / "authority.json"
    authority_path.write_text('{"accepted":"historical"}')
    receipt_path = historical / "release.json"
    release = owner_receipt()
    manifest = release["inventory"]["manifest"]
    manifest["mapit_config"] = {key: getattr(CONFIG, key)
                                for key in _CONFIG_FIELDS - {"frontend_url"}}
    release["not_selected"] = "private-canary-not-a-real-session"

    def write_release():
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode()).hexdigest()
        release["inventory"]["manifest_sha"] = digest
        release["final_release_verified"]["manifest_sha256"] = digest
        receipt_path.write_text(json.dumps(release))

    write_release()
    authority = SimpleNamespace(account_id="123456789012",
        expected_caller_arn="arn:aws:iam::123456789012:user/operator", run_id=123)
    github = {"github_owner_id": 12, "github_repository_id": 34}
    monkeypatch.setattr(module, "_load_accepted_bootstrap",
        lambda *_args, **_kwargs: (authority, {}, github, {}, None, "a" * 64))
    gates = []
    kwargs = dict(parent=parent, bootstrap_authority_path=authority_path,
        bootstrap_state_dir=bootstrap_state, synthetic_state_dir=synthetic_state,
        owner_release_receipt=receipt_path, source_sha="f" * 40, ci_run_id=808,
        acl_checker=lambda _: True, clock=lambda: 1_800_000_000.5,
        monotonic=lambda: 100.0,
        source_validator=lambda source: gates.append(("source", source)),
        protection_validator=lambda ids: gates.append(("protection", ids)))
    return SimpleNamespace(parent=parent, historical=historical, release=release,
        manifest=manifest, write_release=write_release, kwargs=kwargs, gates=gates)


def test_preparation_only_copies_validated_public_config_and_new_authority(tmp_path, monkeypatch):
    f = _fixture(tmp_path, monkeypatch)
    old = {p: p.read_bytes() for p in f.historical.rglob("*") if p.is_file()}
    target = module.prepare(**f.kwargs)
    assert target.parent == f.parent and target.name.startswith("kp-")
    assert {p.name for p in target.iterdir()} == {"public-config.json", "authorization.json", "publication"}
    config = json.loads((target / "public-config.json").read_bytes())
    assert config == {key: getattr(CONFIG, key) for key in _CONFIG_FIELDS}
    auth = json.loads((target / "authorization.json").read_bytes())
    assert set(auth) == {"account", "expected_caller_arn", "source_sha", "ci_run_id", "run_id", "start", "end"}
    assert auth["run_id"] != 123 and auth["start"] == 1_800_000_000 and auth["end"] == 1_800_000_600
    assert f.gates == [("source", auth), ("protection", {"github_owner_id": 12, "github_repository_id": 34})]
    assert {p: p.read_bytes() for p in f.historical.rglob("*") if p.is_file()} == old
    assert all(b"private-canary" not in p.read_bytes() for p in target.iterdir() if p.is_file())


@pytest.mark.parametrize("gate", ["source_validator", "protection_validator"])
def test_failed_gate_precedes_any_new_directory(tmp_path, monkeypatch, gate):
    f = _fixture(tmp_path, monkeypatch)
    f.kwargs[gate] = lambda *_: (_ for _ in ()).throw(RuntimeError("private-canary"))
    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)
    assert list(f.parent.iterdir()) == [f.historical]


@pytest.mark.parametrize("change", ["not_accepted", "account", "digest", "credential_field", "discovery", "timeout_bool"])
def test_bad_release_or_config_is_rejected_before_gates_and_files(tmp_path, monkeypatch, change):
    f = _fixture(tmp_path, monkeypatch)
    if change == "not_accepted":
        f.release["final_release_verified"]["exact_readback_verified"] = False
    elif change == "account":
        f.release["inventory"]["account"] = "999999999999"
    elif change == "credential_field":
        f.manifest["mapit_config"]["refresh_token"] = "private-canary"
    elif change == "discovery":
        f.manifest["mapit_config"]["discovery_enabled"] = True
    elif change == "timeout_bool":
        f.manifest["mapit_config"]["http_timeout"] = True
    f.write_release()
    if change == "digest":
        f.release["final_release_verified"]["manifest_sha256"] = "0" * 64
        f.kwargs["owner_release_receipt"].write_text(json.dumps(f.release))
    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)
    assert f.gates == [] and list(f.parent.iterdir()) == [f.historical]


def test_parent_inside_historical_state_is_rejected(tmp_path, monkeypatch):
    f = _fixture(tmp_path, monkeypatch)
    nested = f.kwargs["synthetic_state_dir"] / "nested"
    nested.mkdir()
    f.kwargs["parent"] = nested
    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)
    assert not list(nested.iterdir()) and f.gates == []


def test_partial_new_metadata_is_retained_not_overwritten(tmp_path, monkeypatch):
    f = _fixture(tmp_path, monkeypatch)
    original = module._exclusive_json
    written = []
    def fail_second(path, value, **kwargs):
        written.append(path)
        if len(written) == 2:
            raise OSError("private-canary")
        return original(path, value, **kwargs)
    monkeypatch.setattr(module, "_exclusive_json", fail_second)
    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)
    assert written[0].is_file()
    assert written[0].parent.is_dir() and not written[1].exists()


@pytest.mark.parametrize("clock", [lambda: True, lambda: float("nan")])
def test_invalid_clock_stops_before_metadata(tmp_path, monkeypatch, clock):
    f = _fixture(tmp_path, monkeypatch)
    f.kwargs["clock"] = clock
    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)
    assert f.gates == []
