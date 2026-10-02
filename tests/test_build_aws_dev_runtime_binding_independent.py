from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import build_aws_dev_runtime as builder


def _valid_binding() -> dict[str, str]:
    return {
        "user_pool_id": "eu-west-1_abcdefghijk",
        "api_id": "a1b2c3d4e5",
        "client_id": "publicclient123",
        "owner_subject": "12345678-1234-4234-8234-123456789abc",
    }


def test_binding_accepts_exact_four_kibibyte_limit(tmp_path: Path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    path = private / "binding.json"
    payload = json.dumps(_valid_binding(), separators=(",", ":")).encode("utf-8")
    assert len(payload) < builder.MAX_BINDING_BYTES
    path.write_bytes(payload + b" " * (builder.MAX_BINDING_BYTES - len(payload)))

    policy = builder._read_binding_file(path, repo)

    assert policy.owner_subject == _valid_binding()["owner_subject"]
    assert path.stat().st_size == builder.MAX_BINDING_BYTES


@pytest.mark.parametrize("component", ["OneDrive", "ONEDRIVE - Shared Workspace"])
def test_binding_rejects_casefolded_onedrive_components(tmp_path: Path, component: str):
    repo = tmp_path / "checkout"
    repo.mkdir()
    synced = tmp_path / component
    synced.mkdir()
    path = synced / "binding.json"
    path.write_text(json.dumps(_valid_binding()), encoding="utf-8")

    with pytest.raises(builder.BuildError) as exc:
        builder._read_binding_file(path, repo)

    assert exc.value.args == ("runtime_binding_file_invalid",)
    assert all(value not in str(exc.value) for value in _valid_binding().values())
