"""Prepare fresh private real-MAPIT DEV metadata, never dispatch AWS writes.

Historical receipts are hashed/read only. Fresh tenant paths are opaque
identifiers, not MAPIT credentials or the binding MAC/proof keys. The separate
runner must still verify current AWS state before any one-shot creation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import sys
import time

_ROOT = Path(__file__).resolve().parents[1]
for _item in (str(_ROOT), str(_ROOT / "src")):
    if _item not in sys.path:
        sys.path.insert(0, _item)

from scripts.dev_mapit_bootstrap_contract import build_plan, make_authority
from scripts.dev_mapit_runtime_evidence import _read_private, runtime_evidence_digest
from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.run_aws_dev_identity_binding_bootstrap import load_binding, validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import (
    validate_private_location, validate_authorization, validate_source_and_ci,
)
from scripts.run_dev_mapit_bootstrap import KIND, ci_evidence_digest, load_runner_authority


def _exclusive_json(path, value, *, acl_checker):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if not 0 < len(payload) <= 64 * 1024:
        raise ValueError
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    validate_private_location(path, acl_checker=acl_checker)


def prepare(*, parent, synthetic_binding_path, synthetic_authorization_path,
            synthetic_state_dir, source_sha, ci_run_id, acl_checker=None,
            clock=time.time, monotonic=time.monotonic,
            source_validator=validate_source_and_ci,
            protection_validator=validate_github_protections):
    """Create a new ACL-private envelope with a 600-second exclusive cutoff.

    This only binds proposed metadata to immutable historical bytes. It does
    not accept those receipts as current cloud evidence or authorize a retry.
    Failed/partial new files are retained, never silently deleted or replaced.
    """
    try:
        begun = monotonic()
        wall = clock()
        if (type(begun) not in (int, float) or not math.isfinite(begun)
                or type(wall) not in (int, float) or not math.isfinite(wall) or wall <= 0):
            raise ValueError
        start = int(wall)
        last_mono, last_wall = float(begun), float(wall)
        def fresh():
            nonlocal last_mono, last_wall
            current_mono, current_wall = monotonic(), clock()
            if (type(current_mono) not in (int, float) or not math.isfinite(current_mono)
                    or type(current_wall) not in (int, float) or not math.isfinite(current_wall)
                    or current_mono < last_mono or current_wall < last_wall
                    or current_mono - begun >= 120 or not start <= current_wall < start + 600):
                raise ValueError
            last_mono, last_wall = float(current_mono), float(current_wall)

        parent = validate_private_location(Path(parent), acl_checker=acl_checker)
        binding = load_binding(Path(synthetic_binding_path), acl_checker=acl_checker)
        paths = (Path(synthetic_binding_path), Path(synthetic_authorization_path),
                 Path(synthetic_state_dir) / "rehearsal-state.json")
        historical = [_read_private(p, acl_checker=acl_checker, maximum=128 * 1024)[1]
                      for p in paths]
        github = {k: binding[k] for k in ("github_owner_id", "github_repository_id")}
        source = validate_authorization({
            "account": binding["account_id"], "expected_caller_arn": binding["operator_user_arn"],
            "source_sha": source_sha, "ci_run_id": ci_run_id,
            "run_id": int.from_bytes(secrets.token_bytes(6), "big") or 1,
            "start": start, "end": start + 600,
        })
        source_validator(source)
        protection_validator(github)
        fresh()
        old_keys = tuple(binding["tenant_keys"])
        fresh_key = "tenant-" + secrets.token_hex(32)
        if fresh_key in old_keys:
            raise ValueError
        kwargs = {
            "account_id": binding["account_id"], "operator_user_arn": binding["operator_user_arn"],
            "source_sha": source_sha, "run_id": source["run_id"],
            "expected_caller_arn": binding["operator_user_arn"],
            "authorized_from_epoch": start, "authorized_until_epoch": start + 600,
            "ci_evidence_sha256": ci_evidence_digest(source, github),
            "runtime_evidence_sha256": "0" * 64, "ssm_key_arn": binding["ssm_key_arn"],
            "tenant_keys": (fresh_key,), "excluded_tenant_keys": old_keys,
        }
        template_hash = build_plan(make_authority(**kwargs)).template_sha256
        runtime_binding = dict(binding)
        runtime_binding["tenant_keys"] = list(old_keys)
        bundle = {
            "schema": 1, "kind": "dev-mapit-runtime-evidence",
            "account_id": binding["account_id"], "caller_arn": binding["operator_user_arn"],
            "source_sha": source_sha, "run_id": source["run_id"],
            "authorized_from_epoch": start, "authorized_until_epoch": start + 600,
            "mapit_plan_sha256": template_hash, "runtime_binding": runtime_binding,
            **dict(zip(("synthetic_binding_sha256", "synthetic_authorization_sha256",
                        "synthetic_state_sha256"),
                       (hashlib.sha256(raw).hexdigest() for raw in historical))),
        }
        kwargs["runtime_evidence_sha256"] = runtime_evidence_digest(bundle)
        authority = make_authority(**kwargs)
        if build_plan(authority).template_sha256 != template_hash:
            raise ValueError
        wire = dict(kwargs)
        for name in ("tenant_keys", "excluded_tenant_keys"):
            wire[name] = list(wire[name])
        envelope = {"schema": 1, "kind": KIND, "authority": wire,
                    "source_authorization": source, "github": github}
        target = parent / ("mb-" + secrets.token_hex(6))
        fresh()
        _create_private_directory(target, acl_checker)
        _create_private_directory(target / "bootstrap", acl_checker)
        _exclusive_json(target / "runtime-evidence.json", bundle, acl_checker=acl_checker)
        fresh()
        _exclusive_json(target / "authority.json", envelope, acl_checker=acl_checker)
        load_runner_authority(target / "authority.json", acl_checker=acl_checker)
        fresh()
        return target
    except Exception:
        raise ValueError("mapit_private_preparation_unverified") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare fresh private real-MAPIT bootstrap metadata only.")
    for name in ("parent", "synthetic-binding", "synthetic-authorization", "synthetic-state-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        target = prepare(parent=args.parent, synthetic_binding_path=args.synthetic_binding,
                         synthetic_authorization_path=args.synthetic_authorization,
                         synthetic_state_dir=args.synthetic_state_dir,
                         source_sha=args.source_sha, ci_run_id=args.ci_run_id)
    except Exception:
        sys.stdout.write('{"prepared":false,"category":"mapit_private_preparation_unverified"}\n')
        return 1
    # Private local path only; no authority bytes, subjects, hashes or keys.
    sys.stdout.write(json.dumps({"prepared": True, "directory": str(target)}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
