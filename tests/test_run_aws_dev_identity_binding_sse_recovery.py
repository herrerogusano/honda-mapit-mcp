"""Independent CLI composition and fixed-journal routing holdouts; no SDK calls."""
import json
import os
from pathlib import Path

import pytest

from scripts import run_aws_dev_identity_binding_sse_recovery as runner


@pytest.mark.parametrize("step", ["preflight", "update", "readback", "exercise", "verify"])
def test_main_maps_actual_parser_names_to_operator_contract(monkeypatch, capsys, tmp_path, step):
    expected = {
        "authorization_path": tmp_path / "authorization.json",
        "binding_path": tmp_path / "bindings.json",
        "historical_directory": tmp_path / "history",
        "recovery_binding_path": tmp_path / "recovery-binding.json",
        "state_dir": tmp_path / "update", "probe_state_dir": tmp_path / "probe", "step": step}
    calls = []
    def execute(**kwargs):
        calls.append(kwargs)
        return {"step": step, "ok": True, "category": "readback_verified", "calls": 0, "flags": {}}
    monkeypatch.setattr(runner, "run_authorized_step", execute)
    args = []
    for option, key in (("authorization", "authorization_path"), ("binding", "binding_path"),
                        ("historical-directory", "historical_directory"),
                        ("recovery-binding", "recovery_binding_path"), ("state-dir", "state_dir"),
                        ("probe-state-dir", "probe_state_dir"), ("step", "step")):
        args.extend(("--" + option, str(expected[key])))
    assert runner.main(args) == 0
    assert calls == [expected]
    assert json.loads(capsys.readouterr().out)["step"] == step


@pytest.mark.parametrize("fault", ["new_update_root", "new_probe_root", "relocated_binding", "relocated_metadata"])
def test_relocated_journal_or_binding_is_rejected_before_clients(monkeypatch, tmp_path, fault):
    for key in tuple(os.environ):
        if key.casefold() in runner._PROXY_KEYS:
            monkeypatch.delenv(key)
    root, history = tmp_path / "fresh", tmp_path / "history"
    args = dict(authorization_path=root / "authorization.json", binding_path=history / "bindings.json",
                historical_directory=history, recovery_binding_path=root / "recovery-binding.json",
                state_dir=root / "update", probe_state_dir=root / "probe", step="exercise")
    key = {"new_update_root": "state_dir", "new_probe_root": "probe_state_dir",
           "relocated_binding": "binding_path", "relocated_metadata": "recovery_binding_path"}[fault]
    args[key] = tmp_path / "unconsumed-alternative"
    monkeypatch.setattr(runner, "validate_private_location", lambda path: Path(path).resolve())
    result = runner.run_authorized_step(**args, client_factory=lambda: pytest.fail("SDK constructed"))
    assert result["ok"] is False and result["category"] == "journal_setup_failed"
    assert result["calls"] == 0
