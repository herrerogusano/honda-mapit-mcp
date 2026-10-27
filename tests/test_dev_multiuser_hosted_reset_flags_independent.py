"""Independent ordering and gate regressions for the optional reset path."""

from __future__ import annotations

from scripts.run_dev_multiuser_hosted_acceptance import run_hosted_acceptance
from test_run_dev_multiuser_hosted_acceptance import _private_inputs


def test_reset_flag_shape_is_checked_after_source_gate_and_before_clients(tmp_path):
    inputs = _private_inputs(tmp_path)
    inputs = inputs.__class__(
        **{**inputs.__dict__, "allow_single_a_password_reset": "yes"}
    )
    source_calls = []
    client_calls = []

    result = run_hosted_acceptance(
        inputs,
        source_verifier=lambda auth: source_calls.append(auth["source_sha"]),
        clients_factory=lambda: client_calls.append(True) or {},
        acl_checker=lambda _path: True,
    )

    assert result == {"success": False, "category": "bindings_invalid"}
    assert source_calls == ["a" * 40]
    assert client_calls == []


def test_confirmed_journal_without_explicit_reset_is_rejected_before_clients(tmp_path):
    inputs = _private_inputs(tmp_path)
    inputs = inputs.__class__(
        **{**inputs.__dict__, "confirmed_user_journal_path": tmp_path / "confirmed.json"}
    )
    client_calls = []

    result = run_hosted_acceptance(
        inputs,
        source_verifier=lambda _auth: None,
        clients_factory=lambda: client_calls.append(True) or {},
        acl_checker=lambda _path: True,
    )

    assert result == {"success": False, "category": "bindings_invalid"}
    assert client_calls == []


def test_unknown_source_exception_remains_safe_before_reset_or_clients(tmp_path):
    inputs = _private_inputs(tmp_path)
    client_calls = []

    def source_failure(_auth):
        raise RuntimeError("password=secret https://private/token")

    result = run_hosted_acceptance(
        inputs,
        source_verifier=source_failure,
        clients_factory=lambda: client_calls.append(True) or {},
        acl_checker=lambda _path: True,
    )

    assert result == {"success": False, "category": "runner_failed"}
    assert "secret" not in repr(result)
    assert client_calls == []
