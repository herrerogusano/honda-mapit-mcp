"""Private one-step runner for the separately authorized real-MAPIT DEV stack.

Import is inert. Historical synthetic receipts are read-only inputs, never
authorization to run their old operations. This runner does not prepare its
own authority, publish keys, authenticate MAPIT or open the API.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from collections.abc import Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _item in (str(_ROOT), str(_ROOT / "src")):
    if _item not in sys.path:
        sys.path.insert(0, _item)

from scripts.dev_mapit_bootstrap_contract import make_authority
from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinator
from scripts.dev_mapit_runtime_evidence import make_mapit_runtime_evidence_verifier
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _build_clients, _reject_duplicates, _reject_constant, validate_github_protections,
)
from scripts.run_aws_retained_dev_bootstrap import (
    validate_authorization, validate_private_location, validate_source_and_ci,
)

KIND = "dev-mapit-bootstrap-runner"
MAX_AUTHORITY_BYTES = 32 * 1024
_AUTHORITY_FIELDS = {
    "account_id", "operator_user_arn", "source_sha", "run_id",
    "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch",
    "ci_evidence_sha256", "runtime_evidence_sha256", "ssm_key_arn",
    "tenant_keys", "excluded_tenant_keys",
}


class MapitBootstrapRunnerError(ValueError):
    def __init__(self):
        super().__init__("mapit_bootstrap_runner_unverified")


def ci_evidence_digest(source_authorization, github):
    payload = {"source_authorization": source_authorization, "github": github}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def load_runner_authority(path, *, acl_checker=None):
    """Load exact fresh private inputs; hashes alone grant no cloud authority."""
    try:
        location = validate_private_location(Path(path), acl_checker=acl_checker)
        if not 0 < location.stat().st_size <= MAX_AUTHORITY_BYTES:
            raise ValueError
        payload = location.read_bytes()
        if len(payload) > MAX_AUTHORITY_BYTES:
            raise ValueError
        value = json.loads(payload.decode("utf-8", "strict"),
                           object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
        if (type(value) is not dict
                or set(value) != {"schema", "kind", "authority", "source_authorization", "github"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or value["kind"] != KIND):
            raise ValueError
        raw, github = value["authority"], value["github"]
        if type(raw) is not dict or set(raw) != _AUTHORITY_FIELDS:
            raise ValueError
        if (type(github) is not dict
                or set(github) != {"github_owner_id", "github_repository_id"}
                or any(type(v) is not int or v <= 0 for v in github.values())
                or any(type(raw[k]) is not list for k in ("tenant_keys", "excluded_tenant_keys"))):
            raise ValueError
        kwargs = dict(raw)
        for key in ("tenant_keys", "excluded_tenant_keys"):
            kwargs[key] = tuple(kwargs[key])
        authority = make_authority(**kwargs)
        source = validate_authorization(value["source_authorization"])
        expected = {
            "account": authority.account_id, "expected_caller_arn": authority.expected_caller_arn,
            "source_sha": authority.source_sha, "run_id": authority.run_id,
            "start": authority.authorized_from_epoch, "end": authority.authorized_until_epoch,
        }
        if (any(source[k] != v or type(source[k]) is not type(v) for k, v in expected.items())
                or authority.ci_evidence_sha256 != ci_evidence_digest(source, github)):
            raise ValueError
        return authority, source, github
    except Exception:
        raise MapitBootstrapRunnerError() from None


def run_authorized_step(
    authority_path, evidence_path, synthetic_binding_path, synthetic_authorization_path,
    synthetic_state_dir, state_dir, step, *, acl_checker=None,
    command_runner=subprocess.run, client_factory=_build_clients,
    journal_factory=FileJournal, runtime_verifier_factory=make_mapit_runtime_evidence_verifier,
):
    """Run one explicit step; every successful evidence callback is fresh.

    ``calls`` counts actual SDK dispatches, including failures; ``command_calls``
    counts actual local/GitHub command attempts. ``budget_calls`` preserves the
    coordinator's separate combined per-step evidence budget when available.
    """
    safe_step = step if type(step) is str and step in MapitBootstrapCoordinator.STEPS else "unknown"
    if safe_step == "unknown":
        return {"step": safe_step, "ok": False, "category": "step_invalid", "calls": 0, "command_calls": 0}
    sdk_calls = command_calls = 0
    try:
        authority, source, github = load_runner_authority(authority_path, acl_checker=acl_checker)
        private_state = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        historical_state = validate_private_location(Path(synthetic_state_dir), acl_checker=acl_checker)
        historical_files = [validate_private_location(Path(path), acl_checker=acl_checker)
                            for path in (synthetic_binding_path, synthetic_authorization_path)]
        protected_paths = historical_files + [historical_state, Path(authority_path).resolve(),
                                             Path(evidence_path).resolve()]
        # Reject historical journals before constructing any journal/lock.
        if (private_state == historical_state or historical_state in private_state.parents
                or any(private_state == p or private_state in p.parents for p in protected_paths)):
            raise ValueError
        verifier = runtime_verifier_factory(
            evidence_path=Path(evidence_path), synthetic_binding_path=Path(synthetic_binding_path),
            synthetic_authorization_path=Path(synthetic_authorization_path),
            synthetic_state_dir=historical_state, acl_checker=acl_checker,
        )

        def evidence_fields(candidate, calls):
            if candidate is not authority:
                raise ValueError
            return {"verified": True, "calls": calls, "account_id": authority.account_id,
                    "source_sha": authority.source_sha, "run_id": authority.run_id,
                    "caller_arn": authority.expected_caller_arn,
                    "evidence_sha256": authority.ci_evidence_sha256}

        def fresh_source(candidate):
            calls = 0
            def counted(*args, **kwargs):
                nonlocal calls, command_calls
                calls += 1
                if calls > 8:
                    raise ValueError
                command_calls += 1
                return command_runner(*args, **kwargs)
            validate_source_and_ci(source, command_runner=counted)
            return {**evidence_fields(candidate, calls), "branch": "develop"}

        def fresh_protections(candidate):
            calls = 0
            def counted(*args, **kwargs):
                nonlocal calls, command_calls
                calls += 1
                if calls > 8:
                    raise ValueError
                command_calls += 1
                return command_runner(*args, **kwargs)
            validate_github_protections(github, command_runner=counted)
            return {**evidence_fields(candidate, calls), "environment": "dev", "protections_verified": True}

        # Initial gates precede SDK construction. Coordinator repeats them
        # inside the exclusive window and again immediately before creation.
        fresh_source(authority)
        fresh_protections(authority)
        class CountedClient:
            def __init__(self, client):
                self.client = client

            def __getattr__(self, name):
                value = getattr(self.client, name)
                if not callable(value) or not name.startswith(("get_", "describe_", "list_", "create_")):
                    return value
                def dispatch(*args, **kwargs):
                    nonlocal sdk_calls
                    sdk_calls += 1
                    return value(*args, **kwargs)
                return dispatch

        clients = {name: CountedClient(client) for name, client in client_factory().items()}
        coordinator = MapitBootstrapCoordinator(
            clients, journal_factory(private_state), authority=authority,
            fresh_source=fresh_source, fresh_protections=fresh_protections,
            closed_runtime_verifier=verifier,
        )
        result = coordinator.run_step(safe_step)
        return {**result, "budget_calls": result["calls"],
                "calls": sdk_calls, "command_calls": command_calls}
    except Exception:
        return {"step": safe_step, "ok": False,
                "category": "mapit_bootstrap_runner_unverified",
                "calls": sdk_calls, "command_calls": command_calls}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run one separate authorized real-MAPIT DEV bootstrap step.")
    for name in ("authority", "evidence", "synthetic-binding", "synthetic-authorization",
                 "synthetic-state-dir", "state-dir"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--step", required=True, choices=MapitBootstrapCoordinator.STEPS)
    args = parser.parse_args(argv)
    result = run_authorized_step(
        args.authority, args.evidence, args.synthetic_binding, args.synthetic_authorization,
        args.synthetic_state_dir, args.state_dir, args.step,
    )
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result["ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
