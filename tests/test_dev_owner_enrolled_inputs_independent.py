from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.dev_owner_enrolled_inputs import build_owner_manifest
from test_dev_owner_enrolled_inputs import _inputs


@pytest.mark.parametrize("mutation", [
    lambda args: args["invitation_authority"].update(
        mapit_bootstrap_receipt_sha256="0" * 64),
    lambda args: args["invitation"].update(
        bootstrap_receipt_sha256="0" * 64),
    lambda args: args["publication"].update(
        run_id=args["bootstrap_authority"].run_id),
    lambda args: args["publication"].update(
        end=args["publication"]["start"]),
])
def test_crossed_publication_and_invitation_lineage_is_rejected(tmp_path, monkeypatch, mutation):
    args = _inputs(tmp_path, monkeypatch)
    mutation(args)
    with pytest.raises(ValueError, match="^owner_manifest_inputs_unverified$"):
        build_owner_manifest(**args)


def test_pure_manifest_builder_does_not_resolve_or_read_paths(tmp_path, monkeypatch):
    args = _inputs(tmp_path, monkeypatch)

    def forbidden_resolve(*_args, **_kwargs):
        raise AssertionError("filesystem resolution is outside the pure manifest contract")

    monkeypatch.setattr(Path, "resolve", forbidden_resolve)
    result = build_owner_manifest(**args)
    assert result


def test_manifest_is_deterministic_and_does_not_mutate_receipt_inputs(tmp_path, monkeypatch):
    args = _inputs(tmp_path, monkeypatch)
    snapshot = {
        key: copy.deepcopy(value) for key, value in args.items()
        if type(value) is dict
    }
    first = build_owner_manifest(**args)
    second = build_owner_manifest(**args)
    assert first == second
    assert snapshot == {key: value for key, value in args.items() if type(value) is dict}


def test_unknown_or_credential_bearing_config_fields_never_enter_manifest(tmp_path, monkeypatch):
    for field, value in (("refresh_token", "synthetic-secret"), ("unexpected", "extra")):
        args = _inputs(tmp_path / field, monkeypatch)
        args["public_config"][field] = value
        with pytest.raises(ValueError, match="^owner_manifest_inputs_unverified$"):
            build_owner_manifest(**args)
