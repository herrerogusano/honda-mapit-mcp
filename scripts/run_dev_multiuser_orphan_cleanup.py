"""Source-gated private CLI for one exact retained DEV authorizer deletion."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.dev_multiuser_journal import PlainFileJournal
from scripts.dev_multiuser_orphan_cleanup import cleanup_orphan_authorizer, _binding, _digest
from scripts.run_aws_retained_dev_bootstrap import (
    load_authorization, validate_private_location, validate_source_and_ci, _build_clients,
)
from scripts.run_dev_multiuser_closed_update import _load_app_binding, _discover_setup_ids
from scripts.run_dev_multiuser_hosted_acceptance import _read_private_json, _validate_full_role_bindings

CALLBACK = "http://localhost:39031/callback"


def run(authorization_path, app_binding_path, role_bindings_path,
        lineage_runtime_path, state_dir, *, source_verifier=validate_source_and_ci,
        acl_checker=None, clients_factory=_build_clients):
    """No SDK construction until all private/source inputs have passed."""
    calls = 0
    try:
        paths = [validate_private_location(Path(p), acl_checker=acl_checker) for p in (
            authorization_path, app_binding_path, role_bindings_path,
            lineage_runtime_path, state_dir)]
        authorization, app_path, roles_path, old_path, new_path = paths
        auth = load_authorization(authorization)
        source_verifier(auth)
        app = _load_app_binding(app_path, acl_checker=acl_checker)
        roles = _validate_full_role_bindings(_read_private_json(roles_path, acl_checker=acl_checker), account=auth["account"])
        if app["stack_arn"] != roles["stack_arn"]:
            raise ValueError
        if (old_path.name != "runtime" or new_path == old_path
            or new_path.name != f"orphan-{auth['run_id']}-{auth['source_sha'][:12]}"):
            raise ValueError
        old = PlainFileJournal(old_path).load()
        fields = {"schema", "operation", "account", "caller", "stack", "role",
                  "source", "start", "end", "token", "prior", "target"}
        if type(old) is not dict or set(old) != {"binding", "phase"} or old["phase"] != "acknowledged":
            raise ValueError
        b = old["binding"]
        if (type(b) is not dict or set(b) != fields or type(b["schema"]) is not int or b["schema"] != 1
            or b["operation"] != "dev_multiuser_closed_update" or b["account"] != auth["account"]
            or b["caller"] != auth["expected_caller_arn"] or b["stack"] != app["stack_arn"]
            or b["role"] != f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update"
            or type(b["source"]) is not str or re.fullmatch(r"[0-9a-f]{40}", b["source"]) is None
            or b["source"] == auth["source_sha"] or type(b["token"]) is not str
            or re.fullmatch(r"dev-multiuser-[0-9a-f]{32}", b["token"]) is None
            or any(type(b[k]) is not int for k in ("start", "end"))
            or not 0 < b["end"] - b["start"] <= 3600 or b["start"] >= auth["start"]):
            raise ValueError
        api_id = roles["api_arn"].rsplit("/", 1)[-1]
        expected = build_retained_dev_multiuser_setup(api_id=api_id, callback_url=CALLBACK)
        if b["prior"] != _digest(expected) or not re.fullmatch(r"[0-9a-f]{64}", b["target"]) or b["target"] == b["prior"]:
            raise ValueError
        journal = PlainFileJournal(new_path)
        if journal.load() is not None:
            return {"success": False, "category": "cleanup_journal_not_fresh", "calls": 0}
        clients = clients_factory()
        calls += 1
        identity = clients["sts"].get_caller_identity()
        if (identity.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
            or identity.get("Account") != auth["account"] or identity.get("Arn") != auth["expected_caller_arn"]):
            raise ValueError
        calls += 1
        pool, _ = _discover_setup_ids(clients["cloudformation"], app["stack_arn"], auth["account"])
        issuer = f"https://cognito-idp.eu-west-1.amazonaws.com/{pool}"
        audience = f"https://{api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
        name = "honda-mapit-mcp-dev-multiuser-jwt"
        token = "dev-multiuser-" + hashlib.sha256(f"orphan-cleanup:{auth['run_id']}:{auth['source_sha']}".encode()).hexdigest()[:32]
        binding = _binding(account=auth["account"], caller=auth["expected_caller_arn"],
            stack=app["stack_arn"], api_id=api_id, region="eu-west-1", source=auth["source_sha"],
            token=token, lineage_token=b["token"], start=auth["start"], end=auth["end"],
            authorizer_name=name, issuer=issuer, audience=audience)
        cleanup_auth = {key: auth[key] for key in ("account", "expected_caller_arn", "source_sha", "start", "end")}
        cleanup_auth.update(region="eu-west-1", token=token, binding_sha256=_digest(binding))
        result = cleanup_orphan_authorizer(
            {key: clients[key] for key in ("sts", "cloudformation", "apigatewayv2", "lambda")},
            journal, auth=cleanup_auth, app_stack=app["stack_arn"], api_id=api_id,
            expected_template=expected, authorizer_name=name, issuer=issuer,
            audience=audience, lineage_token=b["token"],
        )
        return dict(result, calls=calls + result["calls"])
    except Exception:
        return {"success": False, "category": "cleanup_preparation_failed", "calls": calls}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("authorization", "app-binding", "role-bindings", "lineage-runtime", "state-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    result = run(args.authorization, args.app_binding, args.role_bindings,
                 args.lineage_runtime, args.state_dir)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
