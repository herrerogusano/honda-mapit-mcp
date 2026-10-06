"""Create fresh private DEV envelopes from accepted historical metadata only.

This is a local-file operation, not an AWS operator. Historical authorizations
and journals remain read-only; their expired windows and tokens are not copied.
"""
from __future__ import annotations

import argparse
import json
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
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


def prepare(parent, *, app_directory, roles_directory, controls_directory,
            source_sha, ci_run_id, acl_checker=None, clock=time.time):
    parent = validate_private_location(Path(parent), acl_checker=acl_checker)
    old = load_authorization(validate_private_location(
        Path(app_directory) / "authorization.json", acl_checker=acl_checker))
    app = _read(Path(app_directory) / "rehearsal-state.json", acl_checker)
    roles = _read(Path(roles_directory) / "rehearsal-state.json", acl_checker)
    controls = _read(Path(controls_directory) / "rehearsal-state.json", acl_checker)
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
    target = parent / ("dev-multiuser-" + secrets.token_hex(16))
    target.mkdir(mode=0o700)
    validate_private_location(target, acl_checker=acl_checker)
    write_private_authorization(target / "authorization.json", auth, acl_checker=acl_checker)
    metadata = {
        "app-binding.json": {"stack_arn": app["stack_id"], "original_creation_run_id": app["run_id"]},
        "roles-binding.json": {"stack_arn": roles["readback_receipt"]["stack_id"], "original_creation_run_id": roles["run_id"]},
        "controls-binding.json": {"stack_arn": controls["readback_receipt"]["stack_id"], "original_creation_run_id": controls["run_id"]},
    }
    for name, value in metadata.items():
        with (target / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
    for operation in ("roles", "setup", "controls"):
        (target / f"{operation}-{run_id}-{source_sha[:12]}").mkdir(mode=0o700)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("parent", "app-directory", "roles-directory", "controls-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
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
