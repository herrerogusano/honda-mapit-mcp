"""Prepare new private key-publication metadata; no SDK or secret generation.

Only the public MAPIT configuration from the retained original release receipt
is selected. Historical bootstrap state is parsed, never executed. The separate
publisher must independently recheck current AWS state and consume its own intent.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import secrets
import sys
import time

_ROOT = Path(__file__).resolve().parents[1]
for _item in (str(_ROOT), str(_ROOT / "src")):
    if _item not in sys.path:
        sys.path.insert(0, _item)

from mapit.cloud_transport import validate_cloud_config
from mapit.config import MapitConfig
from scripts.dev_mapit_runtime_evidence import _read_private
from scripts.prepare_dev_mapit_bootstrap_private import _exclusive_json
from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _reject_constant, _reject_duplicates, validate_github_protections,
)
from scripts.run_aws_retained_dev_bootstrap import (
    validate_authorization, validate_private_location, validate_source_and_ci,
)
from scripts.run_dev_mapit_binding_key_setup import _CONFIG_FIELDS, _load_accepted_bootstrap, _load_config
from scripts.run_dev_owner_assisted_login import parse_trusted_owner_policy
from scripts.run_dev_owner_invitation import _parser_only_clients


def prepare(*, parent: Path, bootstrap_authority_path: Path,
            bootstrap_state_dir: Path, synthetic_state_dir: Path,
            owner_release_receipt: Path, source_sha: str, ci_run_id: int,
            acl_checker=None, clock=time.time, monotonic=time.monotonic,
            source_validator=validate_source_and_ci,
            protection_validator=validate_github_protections):
    """Create-only public config and fresh seven-field publication authority.

    Partial files are retained. No MAC/proof keys or session/token bytes are
    generated/read, and an accepted old authority is not renewed or replayed.
    """
    try:
        begun, wall = monotonic(), clock()
        if any(type(v) not in (int, float) or isinstance(v, bool) or not math.isfinite(v)
               for v in (begun, wall)) or wall <= 0:
            raise ValueError
        start = int(wall)
        last_mono, last_wall = float(begun), float(wall)

        def fresh():
            nonlocal last_mono, last_wall
            current_mono, current_wall = monotonic(), clock()
            if (any(type(v) not in (int, float) or isinstance(v, bool) or not math.isfinite(v)
                    for v in (current_mono, current_wall))
                    or current_mono < last_mono or current_wall < last_wall
                    or current_mono - begun >= 120
                    or not start <= current_wall < start + 600):
                raise ValueError
            last_mono, last_wall = float(current_mono), float(current_wall)

        parent = validate_private_location(Path(parent), acl_checker=acl_checker)
        if not parent.is_dir():
            raise ValueError
        protected = tuple(validate_private_location(Path(p), acl_checker=acl_checker)
            for p in (bootstrap_authority_path, bootstrap_state_dir,
                      synthetic_state_dir, owner_release_receipt))
        if any(parent == p or p in parent.parents for p in protected):
            raise ValueError
        authority, _old_source, github, _state, _plan, _receipt = _load_accepted_bootstrap(
            Path(bootstrap_authority_path), Path(bootstrap_state_dir), _parser_only_clients(),
            acl_checker=acl_checker)
        _, raw = _read_private(Path(owner_release_receipt), acl_checker=acl_checker,
                               maximum=256 * 1024)
        release = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                             parse_constant=_reject_constant)
        parse_trusted_owner_policy(release, expected_account=authority.account_id)
        original = release["inventory"]["manifest"]["mapit_config"]
        if type(original) is not dict or set(original) != _CONFIG_FIELDS - {"frontend_url"}:
            raise ValueError
        config = {**original, "frontend_url": MapitConfig().frontend_url}
        if (any(type(config[k]) is not str for k in _CONFIG_FIELDS - {"discovery_enabled", "http_timeout"})
                or type(config["discovery_enabled"]) is not bool
                or type(config["http_timeout"]) not in (int, float)
                or isinstance(config["http_timeout"], bool)):
            raise ValueError
        parsed = MapitConfig(**config)
        validate_cloud_config(parsed)
        if parsed.frontend_url != "https://app.mapit.me/":
            raise ValueError
        run_id = int.from_bytes(secrets.token_bytes(6), "big") or 1
        if run_id == authority.run_id:
            raise ValueError
        source = validate_authorization({
            "account": authority.account_id, "expected_caller_arn": authority.expected_caller_arn,
            "source_sha": source_sha, "ci_run_id": ci_run_id, "run_id": run_id,
            "start": start, "end": start + 600,
        })
        source_validator(source)
        protection_validator(github)
        fresh()
        target = parent / ("kp-" + secrets.token_hex(6))
        _create_private_directory(target, acl_checker)
        _create_private_directory(target / "publication", acl_checker)
        _exclusive_json(target / "public-config.json", config, acl_checker=acl_checker)
        _load_config(target / "public-config.json", acl_checker=acl_checker)
        fresh()
        _exclusive_json(target / "authorization.json", source, acl_checker=acl_checker)
        fresh()
        return target
    except Exception:
        raise ValueError("mapit_key_private_preparation_unverified") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prepare private MAPIT key-publication metadata only.")
    for name in ("parent", "bootstrap-authority", "bootstrap-state-dir", "synthetic-state-dir", "owner-release-receipt"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        target = prepare(parent=args.parent, bootstrap_authority_path=args.bootstrap_authority,
            bootstrap_state_dir=args.bootstrap_state_dir, synthetic_state_dir=args.synthetic_state_dir,
            owner_release_receipt=args.owner_release_receipt, source_sha=args.source_sha,
            ci_run_id=args.ci_run_id)
    except Exception:
        sys.stdout.write('{"prepared":false,"category":"mapit_key_private_preparation_unverified"}\n')
        return 1
    sys.stdout.write(json.dumps({"prepared": True, "directory": str(target)}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
