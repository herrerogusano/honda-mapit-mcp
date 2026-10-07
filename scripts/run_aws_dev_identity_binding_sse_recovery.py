"""One-step private operator for the approved DEV table-encryption recovery."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import math
import time
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from scripts.aws_dev_identity_binding_sse_recovery import (
    DevIdentityBindingSseRecoveryCoordinator, SseRecoveryError,
)
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _build_clients, load_binding, validate_github_protections,
)
from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError, load_authorization, validate_private_location,
    validate_source_and_ci,
)
from scripts.run_dev_identity_binding_storage_probe import _build_assumed_clients

_MAX_JSON_BYTES = 4096
_PROXY_KEYS = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle",
    "aws_endpoint_url", "aws_endpoint_url_cloudformation", "aws_endpoint_url_dynamodb",
    "aws_endpoint_url_iam", "aws_endpoint_url_ssm", "aws_endpoint_url_sts",
    "aws_endpoint_url_cognito", "aws_endpoint_url_apigatewayv2", "aws_endpoint_url_lambda",
    "aws_endpoint_url_kms",
})
_SAFE_CATEGORIES = frozenset({
    "step_invalid", "authorization_invalid", "binding_invalid", "authorization_binding_mismatch",
    "lineage_invalid", "source_ci_failed", "protection_failed", "private_location_invalid",
    "private_acl_invalid", "private_acl_unverified", "client_setup_failed", "journal_setup_failed",
    "binding_invalid", "journal_invalid", "window_invalid", "window_expired", "preflight_conflict",
    "preflight_verified", "preflight_required", "probe_consumed", "update_intent_saved",
    "update_outcome_unknown", "update_acknowledged", "update_in_progress", "update_readback_unverified",
    "sse_recovery_accepted", "probe_intent_saved", "storage_exercise_unverified",
    "storage_exercise_verified", "readback_unverified", "readback_verified", "aws_call_failed",
    "aws_response_invalid", "journal_failed", "operator_internal_error",
})
_SAFE_FLAGS = frozenset({
    "preflight", "update_acknowledged", "sse_recovery_accepted", "tenant_a_enrolled",
    "tenant_b_enrolled", "tenant_results_isolated", "tenant_a_revoked", "tenant_b_remained_active",
    "tenant_b_active", "tenant_parameter_versions_verified",
})


class SseRecoveryRunnerError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in _SAFE_CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _strict_private_json(path: Path, *, expected_fields: frozenset[str]) -> dict[str, Any]:
    try:
        path = validate_private_location(path)
        if path.stat().st_size <= 0 or path.stat().st_size > _MAX_JSON_BYTES:
            raise ValueError
        raw = path.read_bytes()
        if not 0 < len(raw) <= _MAX_JSON_BYTES:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(value) is not dict or set(value) != expected_fields:
            raise ValueError
        return value
    except Exception:
        raise SseRecoveryRunnerError("binding_invalid") from None


def _safe_result(step: str, ok: bool, category: str, calls: int = 0,
                 flags: Mapping[str, Any] | None = None) -> dict[str, Any]:
    safe_flags = {}
    if isinstance(flags, Mapping):
        safe_flags = {key: value for key, value in flags.items()
                      if type(key) is str and key in _SAFE_FLAGS and type(value) is bool}
    return {
        "step": step if type(step) is str and step in DevIdentityBindingSseRecoveryCoordinator.STEPS else "unknown",
        "ok": ok is True,
        "category": category if type(category) is str and category in _SAFE_CATEGORIES else "operator_internal_error",
        "calls": calls if type(calls) is int and not isinstance(calls, bool) and calls >= 0 else 0,
        "flags": safe_flags,
    }


def run_authorized_step(
    authorization_path: Path,
    binding_path: Path,
    historical_directory: Path,
    recovery_binding_path: Path,
    state_dir: Path,
    probe_state_dir: Path,
    step: str,
    *,
    client_factory: Callable[[], Mapping[str, Any]] = _build_clients,
    source_ci_validator=validate_source_and_ci,
    protection_validator=validate_github_protections,
    runtime_verifier=None,
    journal_factory=FileJournal,
    assumed_client_factory=_build_assumed_clients,
    wall_clock=None,
    monotonic=None,
) -> dict[str, Any]:
    safe_step = step if type(step) is str and step in DevIdentityBindingSseRecoveryCoordinator.STEPS else "unknown"
    if safe_step == "unknown":
        return _safe_result("unknown", False, "step_invalid")
    try:
        import os
        if any(name.casefold() in _PROXY_KEYS for name in os.environ):
            raise SseRecoveryRunnerError("client_setup_failed")
        from scripts.run_aws_retained_dev_bootstrap import validate_authorization
        auth_path = validate_private_location(Path(authorization_path))
        history = validate_private_location(Path(historical_directory))
        binding_file = validate_private_location(Path(binding_path))
        recovery_file = validate_private_location(Path(recovery_binding_path))
        update_dir = validate_private_location(Path(state_dir))
        proof_dir = validate_private_location(Path(probe_state_dir))
        auth_dir = validate_private_location(auth_path.parent)
        if (auth_path.name != "authorization.json"
            or binding_file != history / "bindings.json"
            or recovery_file != auth_dir / "recovery-binding.json"
            or update_dir != auth_dir / "update"
            or proof_dir != auth_dir / "probe"
            or update_dir == proof_dir
            or auth_dir == history or auth_dir in history.parents or history in auth_dir.parents):
            raise SseRecoveryRunnerError("journal_setup_failed")
        auth = load_authorization(auth_path)
        binding = load_binding(binding_file)
        recovery = _strict_private_json(recovery_file, expected_fields=frozenset({
            "table_id", "table_creation_time", "bootstrap_state_sha256",
            "probe_state_sha256", "key_state_sha256", "sse_key_arn", "runtime_policy_physical_id",
        }))
        validate_authorization(auth)
        if auth["account"] != binding["account_id"] or auth["expected_caller_arn"] != binding["operator_user_arn"]:
            raise SseRecoveryRunnerError("authorization_binding_mismatch")
        historical = {}
        for name in ("bootstrap", "probe", "keys"):
            directory = validate_private_location(history / name)
            historical_journal = journal_factory(directory)
            validate_private_location(Path(historical_journal.path))
            historical[name] = historical_journal.load()
            if type(historical[name]) is not dict:
                raise SseRecoveryRunnerError("lineage_invalid")
        from scripts.aws_dev_identity_binding_sse_recovery import validate_recovery_lineage
        validate_recovery_lineage(binding, historical["bootstrap"], historical["probe"],
                                   historical["keys"], recovery)
        try:
            if source_ci_validator(auth) is False:
                raise ValueError
        except Exception:
            raise SseRecoveryRunnerError("source_ci_failed") from None
        try:
            if protection_validator(binding) is False:
                raise ValueError
        except Exception:
            raise SseRecoveryRunnerError("protection_failed") from None
        now = time.time() if wall_clock is None else wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or not auth["start"] <= now < auth["end"]):
            raise SseRecoveryRunnerError("window_expired")
        if runtime_verifier is None:
            from scripts.dev_identity_binding_runtime_evidence import verify_accepted_runtime
            runtime_verifier = verify_accepted_runtime
        clients = client_factory()
        coordinator = DevIdentityBindingSseRecoveryCoordinator(
            clients,
            journal_factory(update_dir),
            probe_journal=journal_factory(proof_dir),
            authorization=auth,
            binding=binding,
            recovery_binding=recovery,
            accepted_bootstrap_state=historical["bootstrap"],
            accepted_probe_state=historical["probe"],
            accepted_key_state=historical["keys"],
            accepted_runtime_verifier=runtime_verifier,
            explicit_client_factory=assumed_client_factory,
            source_ci_validator=source_ci_validator,
            protection_validator=protection_validator,
            **({} if wall_clock is None else {"wall_clock": wall_clock}),
            **({} if monotonic is None else {"monotonic": monotonic}),
        )
        result = coordinator.run_step(safe_step)
        return _safe_result(safe_step, result.get("ok") is True, result.get("category"),
                            result.get("calls", 0), result.get("flags"))
    except SseRecoveryRunnerError as exc:
        return _safe_result(safe_step, False, exc.category)
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", None)
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "authorization_invalid"
        return _safe_result(safe_step, False, category)
    except RehearsalError:
        return _safe_result(safe_step, False, "journal_setup_failed")
    except Exception:
        return _safe_result(safe_step, False, "operator_internal_error")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--historical-directory", required=True, type=Path)
    parser.add_argument("--recovery-binding", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--probe-state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=DevIdentityBindingSseRecoveryCoordinator.STEPS)
    args = parser.parse_args(argv)
    result = run_authorized_step(
        authorization_path=args.authorization,
        binding_path=args.binding,
        historical_directory=args.historical_directory,
        recovery_binding_path=args.recovery_binding,
        state_dir=args.state_dir,
        probe_state_dir=args.probe_state_dir,
        step=args.step,
    )
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
