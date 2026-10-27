from __future__ import annotations

import pytest

from scripts import prepare_dev_mapit_key_private as module
from tests.test_prepare_dev_mapit_key_private import _fixture


def test_authority_is_not_written_if_fresh_window_expires_after_public_config(tmp_path, monkeypatch):
    f = _fixture(tmp_path, monkeypatch)
    start = 1_800_000_000
    wall = iter((start + 0.5, start + 1, start + 600))
    mono = iter((100.0, 101.0, 102.0))
    f.kwargs["clock"] = lambda: next(wall)
    f.kwargs["monotonic"] = lambda: next(mono)

    with pytest.raises(ValueError, match="^mapit_key_private_preparation_unverified$"):
        module.prepare(**f.kwargs)

    targets = [path for path in f.parent.iterdir() if path.name.startswith("kp-")]
    assert len(targets) == 1
    target = targets[0]
    assert (target / "public-config.json").is_file()
    assert not (target / "authorization.json").exists()
    assert (target / "publication").is_dir()
