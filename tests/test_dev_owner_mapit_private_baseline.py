from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import time

import pytest

from scripts.dev_owner_enrolled_accepted_inputs import load_accepted_owner_delivery
from scripts import dev_owner_mapit_private_baseline as baseline
from tests.test_dev_owner_enrolled_accepted_inputs import _accepted


def setup(tmp_path, **kwargs):
    root, paths, _, _ = _accepted(tmp_path)
    accepted = load_accepted_owner_delivery(delivery_root=root, private_paths=paths, acl_checker=lambda _: True)
    return root, accepted, baseline.AcceptedPrivateBaseline(accepted, **kwargs)


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
def test_native_fast_provenance_checks_use_real_time_without_subprocess(tmp_path, monkeypatch):
    root, accepted, guard = setup(tmp_path)
    for index in range(2):
        archive = root / ("synthetic-public-archive-" + str(index))
        archive.write_bytes(b"x" * 9_317_568)
        _, _, fingerprint = baseline.private._snapshot(archive, maximum=10 * 1024 * 1024, acl_checker=lambda _: True)
        guard.add(archive, maximum=10 * 1024 * 1024, expected_fingerprint=fingerprint)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("subprocess in short cloud lease"))
    monkeypatch.setattr(accepted, "assert_unchanged", lambda: pytest.fail("slow owning ACL revalidation in short lease"))
    started = time.monotonic()
    for _ in range(64):
        assert guard.check() is True
    elapsed = time.monotonic() - started
    assert elapsed < 14, f"native provenance checks consumed {elapsed:.3f}s"
    print(f"native checks=64 bytes=18635136 files={len(guard.files)} descriptors={len(guard.descriptors)} seconds={elapsed:.3f}")


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
@pytest.mark.parametrize("change", ["content", "same_length", "replace", "parent_replace", "projection", "context", "registration"])
def test_native_baseline_rejects_private_file_and_registered_object_drift(tmp_path, change):
    root, accepted, guard = setup(tmp_path)
    path = root / "inputs" / "archive-summary.json"
    if change == "content":
        path.write_bytes(path.read_bytes() + b" ")
    elif change == "same_length":
        before = path.stat()
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b"true", b"null", 1))
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    elif change == "replace":
        raw = path.read_bytes()
        old = path.with_name("retained-original")
        path.rename(old)
        path.write_bytes(raw)
    elif change == "parent_replace":
        old_parent = path.parent.with_name("retained-inputs")
        path.parent.rename(old_parent)
        path.parent.mkdir()
        for original in old_parent.iterdir():
            if original.is_file():
                (path.parent / original.name).write_bytes(original.read_bytes())
    elif change == "projection":
        accepted.private_inputs.runtime_binding["app_run_id"] += 1
    elif change == "context":
        import dataclasses
        accepted.private_inputs.manifest_inputs["context"] = dataclasses.replace(
            accepted.private_inputs.manifest_inputs["context"])
    else:
        baseline.private._REGISTERED.pop(accepted.private_inputs)
    assert guard.check() is False


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
def test_native_descriptor_includes_dacl_protection_and_detects_change(tmp_path):
    root, _, guard = setup(tmp_path)
    path = root / "inputs" / "archive-summary.json"
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    get = advapi.GetNamedSecurityInfoW
    get.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    get.restype = wintypes.DWORD
    set_security = advapi.SetNamedSecurityInfoW
    set_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    set_security.restype = wintypes.DWORD
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    before = baseline.native_security_descriptor(path)
    control = int.from_bytes(before[2:4], "little")
    # Change only the synthetic temp file; restore its original protection flag.
    target_flag = 0x20000000 if control & 0x1000 else 0x80000000
    restore_flag = 0x80000000 if control & 0x1000 else 0x20000000
    assert get(str(path), 1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0
    try:
        assert set_security(str(path), 1, 4 | target_flag, None, None, dacl, None) == 0
        assert baseline.native_security_descriptor(path) != before
        assert guard.check() is False
    finally:
        assert set_security(str(path), 1, 4 | restore_flag, None, None, dacl, None) == 0
        kernel.LocalFree(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
def test_parent_acl_and_owner_bytes_are_not_ignored(tmp_path):
    changed = set()
    def reader(path):
        native = baseline.native_security_descriptor(path)
        return native if path not in changed else native + b"descriptor-change"
    root, _, guard = setup(tmp_path, descriptor_reader=reader)
    changed.add(root / "inputs")
    assert guard.check() is False


def test_unregistered_or_unvalidated_provenance_cannot_seed_native_baseline(tmp_path):
    from scripts.dev_owner_enrolled_accepted_inputs import AcceptedDeliveryInputs
    with pytest.raises(baseline.PrivateBaselineError):
        baseline.AcceptedPrivateBaseline(AcceptedDeliveryInputs())


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
@pytest.mark.parametrize("change", ["files_drop", "descriptors_drop", "identities_drop", "reader", "digest", "evidence"])
def test_public_baseline_mutation_cannot_change_registered_authority(tmp_path, change):
    _, accepted, guard = setup(tmp_path)
    if change == "files_drop": guard.files.clear()
    if change == "descriptors_drop": guard.descriptors.clear()
    if change == "identities_drop": guard.path_identities.clear()
    if change == "reader": guard.descriptor_reader = lambda _: b"fake"
    if change == "digest": guard._private_digest = "f" * 64
    if change == "evidence": guard.evidence = copy_evidence = object()
    assert guard.check() is False
    assert guard.is_registered_native() is False


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
def test_readding_modified_file_does_not_reset_baseline(tmp_path):
    root, _, guard = setup(tmp_path)
    path = root / "inputs" / "archive-summary.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(baseline.PrivateBaselineError):
        guard.add(path, maximum=8192, expected_fingerprint=(str(path), *guard.files[path][1]))
    assert guard.check() is False


def test_forged_object_cannot_claim_registered_native_status():
    forged = baseline.AcceptedPrivateBaseline.__new__(baseline.AcceptedPrivateBaseline)
    assert forged.check() is False
    assert forged.is_registered_native() is False


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptor")
@pytest.mark.parametrize("late", ["deadline", "authority", "wall_rollback", "mono_rollback", "freshness"])
def test_default_native_scan_must_resample_clocks_before_sdk_dispatch(tmp_path, monkeypatch, late):
    from scripts import run_dev_owner_mapit_enrollment as runner
    from tests.test_run_dev_owner_mapit_enrollment import authority, SOURCE, NOW
    from types import SimpleNamespace
    _, accepted, guard = setup(tmp_path / "history")
    root = tmp_path / "operation"
    root.mkdir()
    (root / "authorization.json").write_bytes(runner._canonical(authority(accepted, state_directory=str(root.resolve()))))
    wall, mono = [NOW], [100]
    operation = runner._Operation(root=root, evidence=accepted, source_sha=SOURCE, ci_run_id=999,
        acl_checker=lambda _: True, clock=lambda: wall[0], monotonic=lambda: mono[0], private_baseline=guard)
    operation.gates_verified()
    operation.intent()
    actual = baseline._file_fingerprint
    def delayed(*args, **kwargs):
        result = actual(*args, **kwargs)
        if late == "deadline": mono[0] = 114
        elif late == "authority": wall[0] = operation.authority["authorized_until_epoch"]
        elif late == "wall_rollback": wall[0] = NOW - 1
        elif late == "mono_rollback": mono[0] = 99
        else: wall[0], mono[0] = NOW + 30, 130
        return result
    monkeypatch.setattr(baseline, "_file_fingerprint", delayed)
    calls = []
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        operation.dispatch(SimpleNamespace(put_item=lambda **kw: calls.append(kw)), "put_item", {},
            deadline=140 if late == "freshness" else 114, write="ddb")
    assert calls == [] and operation.ddb_writes == 0 and operation.calls == 0
    assert (root / "intent.json").is_file()
