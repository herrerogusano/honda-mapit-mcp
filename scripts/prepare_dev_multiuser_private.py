"""Create fresh private DEV envelopes from accepted historical metadata only.

This is a local-file operation, not an AWS operator. Historical authorizations
and journals remain read-only; their expired windows and tokens are not copied.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization, validate_private_location, write_private_authorization,
)


def _read(path, acl_checker=None):
    path = validate_private_location(Path(path), acl_checker=acl_checker)
    if not 0 < path.stat().st_size <= 32768:
        raise ValueError("metadata_invalid")
    from scripts.run_aws_retained_dev_bootstrap import _reject_duplicates
    with path.open("rb") as stream:
        raw = stream.read(32769)
    if len(raw) > 32768:
        raise ValueError("metadata_invalid")
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates)


def _create_private_directory(path, acl_checker=None):
    path.mkdir(mode=0o700)
    if os.name == "nt" and acl_checker is None:
        # Tighten only this newly created empty directory. Directory readback
        # deliberately rejects inherited ACLs, even when the parent is private.
        import ntsecuritycon
        import win32api
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        try:
            owner = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        finally:
            token.Close()
        system = win32security.ConvertStringSidToSid("S-1-5-18")
        dacl = win32security.ACL()
        inheritance = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
        for principal in (owner, system):
            dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inheritance, ntsecuritycon.FILE_ALL_ACCESS, principal)
        win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
            win32security.PROTECTED_DACL_SECURITY_INFORMATION, owner, None, dacl, None)
    validate_private_location(path, acl_checker=acl_checker)


def prepare(parent, *, app_directory, roles_directory, controls_directory,
            source_sha, ci_run_id, artifact_directory=None, acl_checker=None, clock=time.time):
    parent = validate_private_location(Path(parent), acl_checker=acl_checker)
    old = load_authorization(validate_private_location(
        Path(app_directory) / "authorization.json", acl_checker=acl_checker))
    app = _read(Path(app_directory) / "rehearsal-state.json", acl_checker)
    roles = _read(Path(roles_directory) / "rehearsal-state.json", acl_checker)
    controls = _read(Path(controls_directory) / "rehearsal-state.json", acl_checker)
    artifact = (_read(Path(artifact_directory) / "rehearsal-state.json", acl_checker)
                if artifact_directory is not None else None)
    if artifact is not None and (artifact.get("readback") is not True
                                or artifact.get("account") != old["account"]):
        raise ValueError("historical_acceptance_required")
    if artifact is not None:
        artifact_receipt = artifact.get("readback_receipt")
        artifact_stack = artifact_receipt.get("stack_id") if type(artifact_receipt) is dict else None
        if (type(artifact.get("run_id")) is not int or artifact["run_id"] <= 0
            or type(artifact_stack) is not str
            or re.fullmatch(rf"arn:aws:cloudformation:eu-west-1:{old['account']}:stack/"
                            r"honda-mapit-mcp-dev-retained-runtime-artifacts/"
                            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", artifact_stack) is None):
            raise ValueError("metadata_invalid")
    if (app.get("readback_verified") is not True or roles.get("readback") is not True
        or controls.get("readback") is not True
        or app.get("account_id") != old["account"]
        or roles.get("account") != old["account"]
        or controls.get("account") != old["account"]):
        raise ValueError("historical_acceptance_required")
    start = int(clock())
    run_id = secrets.randbelow(10**15) + 1
    auth = dict(old, source_sha=source_sha, ci_run_id=ci_run_id,
                run_id=run_id, start=start, end=start + 3600)
    # Validate before any file/directory creation.
    from scripts.run_aws_retained_dev_bootstrap import validate_authorization
    validate_authorization(auth)
    metadata = {
        "app-binding.json": {"stack_arn": app["stack_id"], "original_creation_run_id": app["run_id"]},
        "roles-binding.json": {"stack_arn": roles["readback_receipt"]["stack_id"], "original_creation_run_id": roles["run_id"]},
        "controls-binding.json": {"stack_arn": controls["readback_receipt"]["stack_id"], "original_creation_run_id": controls["run_id"]},
    }
    if artifact is not None:
        metadata["artifact-binding.json"] = {
            "stack_arn": artifact_stack,
            "original_creation_run_id": artifact["run_id"],
        }
    target = parent / ("dev-multiuser-" + secrets.token_hex(16))
    _create_private_directory(target, acl_checker)
    write_private_authorization(target / "authorization.json", auth, acl_checker=acl_checker)
    for name, value in metadata.items():
        with (target / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    for operation in ("roles", "setup", "controls"):
        _create_private_directory(target / f"{operation}-{run_id}-{source_sha[:12]}", acl_checker)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("parent", "app-directory", "roles-directory", "controls-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--artifact-directory", type=Path)
    parser.add_argument("--ci-run-id", required=True, type=int)
    args = parser.parse_args()
    try:
        target = prepare(**vars(args))
        # Local path only; no account, credentials, tokens or cloud identifiers.
        print(json.dumps({"ok": True, "private_directory": str(target)}))
        return 0
    except Exception:
        print('{"ok":false,"category":"private_preparation_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
