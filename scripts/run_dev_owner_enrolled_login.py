"""One human DEV login after an accepted closed owner runtime delivery.

This is not MAPIT enrollment or endpoint opening. Password and MFA entry stay
on Cognito; a verified token is discarded in memory, never printed or saved.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
import time

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from mapit.aws_dev_runtime import parse_cognito_jwks
from scripts.dev_owner_assisted_login import DevOwnerAssistedLogin
from scripts.dev_owner_enrolled_accepted_inputs import load_accepted_owner_delivery
from scripts.dev_owner_enrolled_delivery_sdk import build_explicit_delivery_clients
from scripts.dev_owner_enrolled_login_lineage import validate_owner_enrolled_login_lineage
from scripts.dev_owner_enrolled_runtime_readback import make_owner_enrolled_accepted_observer
from scripts.dev_owner_enrolled_observation import validate_observation_window
from scripts.run_dev_owner_assisted_login import fetch_owner_public_jwks
from scripts.run_dev_owner_enrolled_delivery import (
    _PRIVATE_INPUT_FIELDS, _source_and_protection_checks, _source_check_result,
    _protection_check_result,
)
from scripts.run_aws_dev_owner_oauth_bootstrap import validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import validate_source_and_ci


def run_post_delivery_login(*, delivery_root, private_paths, source_sha, ci_run_id,
        acl_checker=None, source_validator=validate_source_and_ci,
        protection_reader=validate_github_protections,
        bundle_factory=build_explicit_delivery_clients,
        accepted_loader=load_accepted_owner_delivery,
        observer_factory=make_owner_enrolled_accepted_observer,
        jwks_fetcher=fetch_owner_public_jwks, channel_factory=DevOwnerAssistedLogin,
        ready_callback=None, clock=time.time, monotonic=time.monotonic):
    """Reconstruct terminal evidence, freshly observe AWS, then serve once.

    The old delivery authority is never executed or renewed. Only a separate
    read-only window names the current operator commit and its integrated CI.
    No historical pre-update verifier is used after the runtime update.
    """
    calls = 0
    observer = None
    try:
        _source_and_protection_checks(source_sha, ci_run_id,
            source_validator=source_validator, protection_reader=protection_reader)
        evidence = accepted_loader(delivery_root=delivery_root, private_paths=private_paths,
                                    acl_checker=acl_checker)
        if evidence.assert_unchanged() is not True:
            raise ValueError
        authority = evidence.authority
        owner_id, repository_id = authority["github_owner_id"], authority["github_repository_id"]
        def gates():
            if evidence.assert_unchanged() is not True:
                raise ValueError
            _source_and_protection_checks(source_sha, ci_run_id,
                source_validator=source_validator, protection_reader=protection_reader,
                owner_id=owner_id, repository_id=repository_id)
        gates()
        now = clock()
        if type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now) or now <= 0:
            raise ValueError
        # Start strictly before the current sample, retaining the exclusive
        # cutoff and a total window of at most 600 seconds.
        window = {"schema": 1, "kind": "owner-enrolled-readonly-observation",
            "account_id": authority["account_id"], "operator_arn": authority["operator_arn"],
            "source_sha": source_sha, "ci_run_id": ci_run_id,
            "authorized_from_epoch": now - 1, "authorized_until_epoch": now + 599,
            "github_owner_id": owner_id, "github_repository_id": repository_id}
        def check_deadline():
            validate_observation_window(window, account_id=authority["account_id"],
                operator_arn=authority["operator_arn"], github_owner_id=owner_id,
                github_repository_id=repository_id, now=clock())
        context = evidence.private_inputs.manifest_inputs["context"]
        bundle = bundle_factory()
        observer = observer_factory(client_bundle=bundle, authority=authority,
            accepted=evidence.accepted, prior_template=evidence.private_inputs.prior_template,
            manifest_raw=evidence.manifest_raw, invitation_jwks=evidence.invitation_jwks,
            mapit_jwks=evidence.mapit_jwks, archive_bytes=evidence.archive_bytes,
            archive_size=len(evidence.archive_bytes), owner_oauth_context=context,
            **{name: Path(private_paths[name]) for name in (
                "mapit_bootstrap_authority_path", "mapit_bootstrap_state_dir",
                "mapit_publication_state_dir", "mapit_evidence_path", "synthetic_binding_path",
                "synthetic_authorization_path", "synthetic_state_dir")},
            accepted_observation_capsule=evidence.capsule, observation_window=window,
            accepted_update_state=evidence.update_state,
            accepted_runtime_evidence_sha256=evidence.update_state["receipt"]["runtime_evidence_sha256"],
            observation_source_check=lambda value: _source_check_result(value, source_validator),
            observation_protection_check=lambda value: _protection_check_result(
                value, protection_reader, owner_id, repository_id),
            acl_checker=acl_checker, clock=clock, monotonic=monotonic)
        readback = observer("accepted", evidence.binding)
        calls = observer.last_read_call_count
        runtime, identity = observer.owner_login_projections(readback)
        lineage = validate_owner_enrolled_login_lineage(original_context=context,
            delivery_authority=authority, accepted_receipts=evidence.accepted,
            accepted_update_state=evidence.update_state,
            current_runtime_readback=runtime, owner_identity_readback=identity)
        gates()
        keys = parse_cognito_jwks(jwks_fetcher(lineage.policy))
        check_deadline()
        gates()
        check_deadline()
        seen = []
        def consume(_verified_token):
            if seen:
                raise ValueError
            gates()
            seen.append(True)
            # Deliberately no persistence or downstream token consumer.
        channel = channel_factory(lineage.policy, keys, consume)
        check_deadline()
        outcome = channel.serve(ready_callback=ready_callback)
        ok = outcome == "verified" and seen == [True]
        return {"ok": ok, "category": "owner_enrolled_login_verified" if ok
                else "owner_enrolled_login_unverified", "calls": calls}
    except Exception:
        try:
            attempted = observer.last_read_call_count
            if type(attempted) is int and 0 <= attempted <= 256:
                calls = attempted
        except Exception:
            pass
        return {"ok": False, "category": "owner_enrolled_login_unverified", "calls": calls}


def main(argv=None):
    parser = argparse.ArgumentParser(description="One post-delivery DEV owner login; no MAPIT enrollment.")
    parser.add_argument("--delivery-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", type=int, required=True)
    for name in sorted(_PRIVATE_INPUT_FIELDS):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args(argv)
    def ready(_url):
        print('{"category":"owner_login_ready","url":"http://127.0.0.1:8787/"}', flush=True)
    result = run_post_delivery_login(delivery_root=args.delivery_root,
        private_paths={name: getattr(args, name) for name in _PRIVATE_INPUT_FIELDS},
        source_sha=args.source_sha, ci_run_id=args.ci_run_id, ready_callback=ready)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
