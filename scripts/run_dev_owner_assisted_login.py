"""Explicit human DEV login smoke; never bootstraps, invites or enrolls MAPIT.

Only fixed-category results are printed. The browser opens a query-free local
URL; Cognito handles the password and MFA. Tokens stay in this process only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.request

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.http_transport import open_direct, read_bounded
from scripts.dev_owner_login_context import parse_accepted_owner_login_context, prepare_assisted_owner_login
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_identity_binding_bootstrap import _build_clients
from scripts.run_aws_dev_owner_oauth_bootstrap import _load_binding, _reject_duplicates, validate_github_protections
from scripts.run_aws_retained_dev_bootstrap import load_authorization, validate_private_location, validate_source_and_ci


def parse_trusted_owner_policy(value, *, expected_account: str):
    """Pure validation of an operator-owned accepted release metadata snapshot.

    This does not establish file provenance; callers must first read a bounded,
    ACL-verified private receipt. It selects no MAPIT credential/session fields.
    """
    try:
        manifest = value["inventory"]["manifest"]
        digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        final = value["final_release_verified"]
        if (type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("kind") != "cd_delivery_preparation"
                or manifest.get("environment") != "prod" or manifest.get("region") != "eu-west-1"
                or manifest.get("account_id") != expected_account
                or value["inventory"].get("account") != expected_account
                or value["inventory"].get("manifest_sha") != digest
                or final.get("exact_readback_verified") is not True
                or final.get("manifest_sha256") != digest):
            raise ValueError
        return CognitoProdPolicy(**{key: manifest[key] for key in
            ("user_pool_id", "api_id", "client_id", "owner_subject")})
    except Exception:
        raise ValueError("owner_login_context_unverified") from None


def load_trusted_owner_policy(path: Path, *, expected_account: str, acl_checker=None):
    """Read the accepted original release receipt, not a callback-derived user.

    Hashes establish receipt consistency, not a signature. Trust comes from the
    independently retained operator-owned private journal and its verified ACL.
    No private MAPIT keys/session/token fields are selected or returned.
    """
    try:
        path = validate_private_location(path, acl_checker=acl_checker)
        if not 0 < path.stat().st_size <= 256 * 1024:
            raise ValueError
        raw = path.read_bytes()
        if len(raw) > 256 * 1024:
            raise ValueError
        value = json.loads(raw, object_pairs_hook=_reject_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        return parse_trusted_owner_policy(value, expected_account=expected_account)
    except Exception:
        raise ValueError("owner_login_context_unverified") from None


def fetch_owner_public_jwks(policy, *, opener=None):
    """One bounded direct TLS GET of the exact verified issuer's public keys."""
    request = urllib.request.Request(policy.issuer_url + "/.well-known/jwks.json",
        headers={"Accept": "application/json"}, method="GET")
    started = time.monotonic()
    def budget(_size):
        if time.monotonic() - started >= 10:
            raise ValueError
    try:
        response = open_direct(request, timeout=3, opener=opener)
        try:
            if response.status != 200:
                raise ValueError
            raw = read_bounded(response, 32 * 1024, on_chunk=budget)
            budget(0)
            return raw
        finally:
            response.close()
    except Exception:
        raise ValueError("owner_login_context_unverified") from None


def run_login(accepted_authorization: Path, owner_release_receipt: Path, *, source_sha: str,
              ci_run_id: int, acl_checker=None, client_factory=_build_clients,
              source_validator=validate_source_and_ci, protection_reader=validate_github_protections,
              jwks_fetcher=fetch_owner_public_jwks, channel_preparer=prepare_assisted_owner_login,
              token_consumer=None, ready_callback=None):
    """Explicit one-attempt smoke, with an optional memory-only next-stage handoff.

    ``ready_callback`` may open only the query-free local URL after binding; the
    default caller instead opens it manually. No SDK lease runs while waiting
    for the human. Consumers must independently authorize any future invitation
    or session publication; a successful login confers no such capability.
    """
    sdk = None
    try:
        auth_path = validate_private_location(accepted_authorization, acl_checker=acl_checker)
        auth = load_authorization(auth_path)
        binding = _load_binding(auth_path.parent / "owner-oauth-binding.json", acl_checker=acl_checker)
        state_path = validate_private_location(Path(binding["state_directory"]), acl_checker=acl_checker)
        state = FileJournal(state_path).load()
        owner = load_trusted_owner_policy(owner_release_receipt, expected_account=auth["account"], acl_checker=acl_checker)
        context = parse_accepted_owner_login_context(auth, binding, state, trusted_owner_policy=owner)
        # The old creation envelope is never extended or executed. This fresh
        # source descriptor is solely a read-only source/CI validation input.
        now = int(time.time())
        source = dict(auth, source_sha=source_sha, ci_run_id=ci_run_id, start=now, end=now + 600)
        def check_source():
            source_validator(source)
            return True
        check_source()
        protection_reader(expected_owner_id=context.github_owner_id,
            expected_repository_id=context.github_repository_id)
        sdk = OwnerOAuthSdkBindings(client_factory(), account_id=context.account,
            operator_user_arn=context.operator, until_epoch=now + 180)
        seen = []
        def consume(token):
            if seen:
                raise ValueError
            seen.append(True)
            if token_consumer is not None:
                token_consumer(token)
        channel = channel_preparer(context, sdk, public_jwks=jwks_fetcher(context.policy),
            source_checker=check_source, protection_checker=protection_reader, token_consumer=consume)
        # No authorize query/code/token ever goes to stdout or a browser-opening
        # API. The fixed local start page owns the subsequent Cognito redirect.
        outcome = channel.serve(ready_callback=ready_callback)
        return {"ok": outcome == "verified" and seen == [True],
            "category": "owner_login_verified" if outcome == "verified" and seen == [True] else "owner_login_unverified",
            "calls": sdk.calls}
    except Exception:
        return {"ok": False, "category": "owner_login_unverified", "calls": getattr(sdk, "calls", 0)}


def main(argv=None):
    parser = argparse.ArgumentParser(description="One human owner login to the isolated DEV client; no MAPIT enrollment.")
    parser.add_argument("--accepted-authorization", required=True, type=Path)
    parser.add_argument("--owner-release-receipt", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", required=True, type=int)
    args = parser.parse_args(argv)
    def ready(_url):
        print('{"category":"owner_login_ready","url":"http://127.0.0.1:8787/"}', flush=True)
    result = run_login(args.accepted_authorization, args.owner_release_receipt,
        source_sha=args.source_sha, ci_run_id=args.ci_run_id, ready_callback=ready)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
