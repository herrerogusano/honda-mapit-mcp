from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from scripts import probe_aws_retained_dev_runtime_arm as probe
from scripts import build_aws_retained_dev_archive as archive_builder
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest


def _candidate(tmp_path: Path):
    jwks, tokens = probe._fixture(probe.SYNTHETIC_EXECUTION_START + 60)
    jwks_sha = hashlib.sha256(jwks).hexdigest()
    manifest = build_retained_dev_manifest(probe.SOURCE_SHA, probe.API_ID, jwks_sha, probe.SYNTHETIC_EXECUTION_START, probe.SYNTHETIC_EXECUTION_END)
    policy = probe.cognito_dev_policy(
        user_pool_id=probe.SYNTHETIC_USER_POOL_ID,
        api_id=probe.API_ID,
        client_id=probe.SYNTHETIC_CLIENT_ID,
        owner_subject=probe.SYNTHETIC_OWNER_SUBJECT,
    )
    jwks_manifest = {"issuer": policy.issuer_url, "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json", "sha256": jwks_sha}
    entries = {
        "mapit/retained-dev.manifest.json": json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
        "mapit/cognito-public-jwks.json": jwks,
        "mapit/cognito-public-jwks.manifest.json": json.dumps(jwks_manifest, sort_keys=True, separators=(",", ":")).encode(),
    }
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    body = out.getvalue()
    path = tmp_path / "candidate.zip"
    path.write_bytes(body)
    receipt = archive_builder._make_receipt(
        source_sha=probe.SOURCE_SHA,
        api_id=probe.API_ID,
        jwks_sha256=jwks_sha,
        execution_start_epoch=probe.SYNTHETIC_EXECUTION_START,
        execution_end_epoch=probe.SYNTHETIC_EXECUTION_END,
        zip_sha256=hashlib.sha256(body).hexdigest(),
        manifest_sha256=hashlib.sha256(entries["mapit/retained-dev.manifest.json"]).hexdigest(),
        source_allowlist_sha256="b" * 64,
        source_proof_sha256="c" * 64,
        wheel_lock_sha256="d" * 64,
        wheel_proof_sha256="e" * 64,
        archive_entries=len(entries),
        wheel_count=0,
        source_modules=0,
        public_key_count=1,
    )
    return path, receipt, tokens, body


def test_retained_fixture_uses_synthetic_public_jwks_and_fixed_manifest_window():
    snapshot, tokens = probe._fixture(probe.SYNTHETIC_EXECUTION_START + 60)
    assert b'"d"' not in snapshot and b'"p"' not in snapshot
    assert set(tokens) == {"valid", "unknown_kid", "wrong_audience", "wrong_scope"}
    assert probe.SYNTHETIC_EXECUTION_START < probe.SYNTHETIC_EXECUTION_END
    assert probe.SYNTHETIC_EXECUTION_END - probe.SYNTHETIC_EXECUTION_START <= 300


def test_retained_fixture_accepts_operator_bound_api_and_window():
    snapshot, tokens = probe._fixture(api_id="z9y8x7w6v5", execution_start_epoch=1_900_000_000)
    assert snapshot and set(tokens) == {"valid", "unknown_kid", "wrong_audience", "wrong_scope"}


def test_output_parser_requires_the_exact_boolean_matrix():
    checks = {name: True for name in probe._CHECKS}
    assert probe._parse_checks(json.dumps({"checks": checks})) == checks
    with pytest.raises(ValueError, match="arm_probe_output_invalid"):
        probe._parse_checks(json.dumps({"checks": {**checks, "unexpected": False}}))
    with pytest.raises(ValueError, match="arm_probe_output_invalid"):
        probe._parse_checks(json.dumps({"checks": {**checks, "initialize": 1}}))
    with pytest.raises(ValueError, match="arm_probe_output_invalid"):
        probe._parse_checks(json.dumps({"checks": checks, "extra": "must-fail"}))
    with pytest.raises(ValueError, match="arm_probe_output_invalid"):
        probe._parse_checks('{"checks":' + json.dumps(checks) + ',"checks":' + json.dumps(checks) + '}')


def test_docker_command_is_pinned_arm_networkless_and_readonly(tmp_path: Path):
    archive = tmp_path / "runtime.zip"
    command = probe._command(archive, context="default", name="retained-dev-probe", run_id="a" * 32, cid_file=tmp_path / "cid")
    assert "--pull=never" in command
    assert command[command.index("--platform") + 1] == "linux/arm64"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--memory") + 1] == "256m"
    mount = command[command.index("--mount") + 1]
    assert str(archive.resolve()) in mount and mount.endswith(",readonly")
    assert "-e" not in command and "--env" not in command
    assert probe.IMAGE in command


def test_container_probe_contains_manifest_clock_source_and_negative_guards():
    for marker in (
        "retained-dev.manifest.json", "sys.path.insert(0,str(root))", "execution_start_epoch", "execution_end_epoch",
        "MAPIT_COGNITO_JWKS_SHA256", "jwks_mismatch_503", "window_expiry_503",
        "tools/call", "unknown_kid_401", "wrong_scope_403",
    ):
        assert marker in probe._CONTAINER_PROBE
    assert "--network" not in probe._CONTAINER_PROBE


def test_probe_source_is_not_production_builder_or_open_network():
    source = Path(probe.__file__).read_text(encoding="utf-8")
    assert "build_aws_retained_dev_archive" in source
    assert "build_aws_prod_runtime" not in source
    assert "probe_aws_prod_runtime_arm" not in source
    assert "network\":\"none\"" not in source  # command is represented as argv, not payload


def test_probe_does_not_import_production_probe_helpers_and_adds_archive_to_child_path():
    source = Path(probe.__file__).read_text(encoding="utf-8")
    # Importing the production probe also imports the production builder.  The
    # retained-dev probe must remain a dev-only dependency graph.
    assert "probe_aws_prod_runtime_arm" not in source
    # Extraction alone does not make the archive importable in the Lambda
    # image; the child must explicitly put its temporary root first.
    assert "sys.path.insert(0,str(root))" in probe._CONTAINER_PROBE


def test_candidate_validation_binds_real_archive_digest_manifest_jwks_and_tokens(tmp_path: Path):
    path, receipt, tokens, _ = _candidate(tmp_path)
    body, entries = probe._validate_candidate_archive(path, receipt, tokens)
    assert len(body) == path.stat().st_size
    assert entries == receipt.archive_entries == 3


def test_candidate_validation_rejects_forged_receipt_digest_token_and_wheel_shape(tmp_path: Path):
    path, receipt, tokens, body = _candidate(tmp_path)
    path.write_bytes(body[:-1] + bytes([body[-1] ^ 1]))
    with pytest.raises(ValueError, match="candidate_digest_mismatch"):
        probe._validate_candidate_archive(path, receipt, tokens)

    path, receipt, tokens, body = _candidate(tmp_path)
    forged = archive_builder._make_receipt(
        source_sha=receipt.source_sha, api_id=receipt.api_id, jwks_sha256=receipt.jwks_sha256,
        execution_start_epoch=receipt.execution_start_epoch, execution_end_epoch=receipt.execution_end_epoch,
        zip_sha256=receipt.zip_sha256, manifest_sha256="0" * 64,
        source_allowlist_sha256="b" * 64, source_proof_sha256="c" * 64,
        wheel_lock_sha256="d" * 64, wheel_proof_sha256="e" * 64,
        archive_entries=receipt.archive_entries, wheel_count=receipt.wheel_count,
        source_modules=receipt.source_modules, public_key_count=receipt.public_key_count,
    )
    with pytest.raises(ValueError, match="candidate_manifest_digest_mismatch"):
        probe._validate_candidate_archive(path, forged, tokens)

    path, receipt, tokens, _ = _candidate(tmp_path)
    with pytest.raises(ValueError, match="synthetic_tokens_invalid"):
        probe._validate_candidate_archive(path, receipt, {**tokens, "valid": "not-a-jwt"})

    path, receipt, tokens, _ = _candidate(tmp_path)
    malformed = archive_builder._make_receipt(
        source_sha=receipt.source_sha, api_id=receipt.api_id, jwks_sha256=receipt.jwks_sha256,
        execution_start_epoch=receipt.execution_start_epoch, execution_end_epoch=receipt.execution_end_epoch,
        zip_sha256=receipt.zip_sha256, manifest_sha256=receipt.manifest_sha256,
        source_allowlist_sha256="b" * 64, source_proof_sha256="c" * 64,
        wheel_lock_sha256="d" * 64, wheel_proof_sha256="e" * 64,
        archive_entries=receipt.archive_entries, wheel_count=-1,
        source_modules=receipt.source_modules, public_key_count=receipt.public_key_count,
    )
    with pytest.raises(ValueError, match="candidate_receipt_invalid"):
        probe._validate_candidate_archive(path, malformed, tokens)


def test_candidate_probe_rejects_nonlocal_context_override_before_container(monkeypatch, tmp_path: Path):
    path, receipt, tokens, _ = _candidate(tmp_path)
    monkeypatch.setattr(probe.docker_helpers, "_docker_context", lambda: "default")
    with pytest.raises(ValueError, match="local_docker_context_unavailable"):
        probe.probe_candidate_archive(path, receipt, tokens, docker_context="remote")


def test_candidate_probe_rejects_symlink_and_returns_only_opaque_summary(monkeypatch, tmp_path: Path):
    path, receipt, tokens, _ = _candidate(tmp_path)
    one_drive = tmp_path / "OneDrive - Synthetic" / "candidate.zip"
    one_drive.parent.mkdir()
    one_drive.write_bytes(path.read_bytes())
    with pytest.raises(ValueError, match="candidate_archive_invalid"):
        probe._validate_candidate_archive(one_drive, receipt, tokens)

    link = tmp_path / "candidate-link.zip"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ValueError, match="candidate_archive_invalid"):
        probe._validate_candidate_archive(link, receipt, tokens)

    checks = {name: True for name in probe._CHECKS}
    run_calls: list[list[str]] = []
    cleanup_calls: list[tuple[str, str, Path]] = []
    monkeypatch.setattr(probe.docker_helpers, "_docker_context", lambda: "default")
    monkeypatch.setattr(probe, "_run_bounded_process", lambda command, payload, timeout: (run_calls.append(command) or (0, json.dumps({"checks": checks}))))
    monkeypatch.setattr(probe.docker_helpers, "_cleanup_owned_container", lambda context, name, run_id, cid: (cleanup_calls.append((context, name, cid)) or True))
    result = probe.probe_candidate_archive(path, receipt, tokens, docker_context="default")
    assert result["success"] is True
    assert set(result) == {"success", "category", "archive_bytes", "archive_entries", "checks"}
    assert "zip_sha256" not in result and "manifest_sha256" not in result and "api_id" not in result and "valid" not in result
    assert len(run_calls) == len(cleanup_calls) == 1

    monkeypatch.setattr(probe.docker_helpers, "_cleanup_owned_container", lambda *args: (_ for _ in ()).throw(RuntimeError("cleanup failure")))
    with pytest.raises(ValueError, match="cleanup_unverified"):
        probe.probe_candidate_archive(path, receipt, tokens, docker_context="default")
