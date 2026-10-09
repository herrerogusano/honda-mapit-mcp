"""Secret-free receipt-bound capsule for restarting accepted DEV readbacks.

The capsule preserves only hashes and stable resource identifiers needed to
compare a later read-only observation with the original pre-update baseline.
It is not an authority, does not verify AWS by itself, and cannot authorize a
write. Callers must obtain it from an ACL-checked private file and pair it with
fresh source/protection checks and SDK readbacks.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HISTORY_SLOTS = ("tenant_a", "tenant_b")
_CAPSULE_FIELDS = frozenset({
    "schema", "kind", "delivery_binding_sha256", "progress", "progress_sha256",
    "target_template_sha256", "artifact_sha256", "owner_context_sha256",
    "accepted_read_call_count", "runtime_evidence_sha256",
})
_PROGRESS_FIELDS = frozenset({
    "resource_ids", "historical_row_sha256", "authorization_table_id",
    "synthetic_policy_sha256",
})
_WINDOW_FIELDS = frozenset({
    "schema", "kind", "account_id", "operator_arn", "source_sha", "ci_run_id",
    "authorized_from_epoch", "authorized_until_epoch", "github_owner_id",
    "github_repository_id",
})


class ObservationEvidenceError(ValueError):
    """Fixed-category evidence error; contains no provider or identity data."""

    def __init__(self, category: str = "observation_capsule_invalid"):
        allowed = {"observation_capsule_invalid", "observation_window_invalid"}
        self.category = category if category in allowed else "observation_capsule_invalid"
        super().__init__(self.category)


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise ObservationEvidenceError() from None


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _valid_sha(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def make_progress_projection(*, resource_ids: Any, historical_rows: Any,
                              historical_tenant_keys: Any,
                              authorization_table_id: Any, synthetic_policy: Any) -> dict[str, Any]:
    """Build a non-sensitive projection in authority order, omitting raw keys."""
    try:
        if (type(resource_ids) is not dict or len(resource_ids) != 19
                or any(type(k) is not str or not k or type(v) is not str or not v
                       for k, v in resource_ids.items())
                or type(historical_rows) is not dict or len(historical_rows) != 2
                or type(historical_tenant_keys) is not list or len(historical_tenant_keys) != 2
                or any(type(k) is not str or not k for k in historical_tenant_keys)
                or len(set(historical_tenant_keys)) != 2
                or set(historical_rows) != set(historical_tenant_keys)
                or type(authorization_table_id) is not str or not authorization_table_id
                or type(synthetic_policy) is not dict):
            raise ValueError
        # Never serialize the opaque tenant selectors. Their order is bound by
        # the authority which validates this projection; only fixed slots leave
        # memory.
        row_hashes = {
            slot: sha256_json(historical_rows[key])
            for slot, key in zip(_HISTORY_SLOTS, historical_tenant_keys)
        }
        projection = {
            "resource_ids": dict(sorted(resource_ids.items())),
            "historical_row_sha256": row_hashes,
            "authorization_table_id": authorization_table_id,
            "synthetic_policy_sha256": sha256_json(synthetic_policy),
        }
        _validate_progress(projection)
        return projection
    except ObservationEvidenceError:
        raise
    except Exception:
        raise ObservationEvidenceError() from None


def progress_digest(progress: Any) -> str:
    _validate_progress(progress)
    return sha256_json(progress)


def runtime_evidence_digest(*, target_template_sha256: str, artifact_sha256: str,
                            owner_context_sha256: str, progress_sha256: str,
                            accepted_read_call_count: int) -> str:
    """Domain-separated v2 digest binding the restart baseline to acceptance."""
    if (not all(_valid_sha(x) for x in (target_template_sha256, artifact_sha256,
                                        owner_context_sha256, progress_sha256))
            or type(accepted_read_call_count) is not int
            or not 1 <= accepted_read_call_count <= 256):
        raise ObservationEvidenceError()
    return sha256_json({
        "schema": 2,
        "kind": "owner-enrolled-runtime-evidence-v2",
        "target_template_sha256": target_template_sha256,
        "artifact_sha256": artifact_sha256,
        "owner_context_sha256": owner_context_sha256,
        "progress_sha256": progress_sha256,
        "accepted_read_call_count": accepted_read_call_count,
    })


def make_capsule(*, delivery_binding: Mapping[str, Any], progress: Any,
                 target_template_sha256: str, artifact_sha256: str,
                 owner_context_sha256: str, accepted_read_call_count: int) -> dict[str, Any]:
    try:
        p_digest = progress_digest(progress)
        evidence = runtime_evidence_digest(
            target_template_sha256=target_template_sha256,
            artifact_sha256=artifact_sha256,
            owner_context_sha256=owner_context_sha256,
            progress_sha256=p_digest,
            accepted_read_call_count=accepted_read_call_count,
        )
        if type(delivery_binding) is not dict:
            raise ValueError
        return {
            "schema": 1,
            "kind": "owner-enrolled-observation-capsule",
            "delivery_binding_sha256": sha256_json(delivery_binding),
            "progress": progress,
            "progress_sha256": p_digest,
            "target_template_sha256": target_template_sha256,
            "artifact_sha256": artifact_sha256,
            "owner_context_sha256": owner_context_sha256,
            "accepted_read_call_count": accepted_read_call_count,
            "runtime_evidence_sha256": evidence,
        }
    except ObservationEvidenceError:
        raise
    except Exception:
        raise ObservationEvidenceError() from None


def validate_capsule(capsule: Any, *, delivery_binding: Mapping[str, Any],
                     expected_runtime_evidence_sha256: str | None = None) -> dict[str, Any]:
    try:
        if (type(capsule) is not dict or set(capsule) != _CAPSULE_FIELDS
                or type(capsule.get("schema")) is not int or capsule["schema"] != 1
                or capsule.get("kind") != "owner-enrolled-observation-capsule"
                or type(delivery_binding) is not dict
                or capsule.get("delivery_binding_sha256") != sha256_json(delivery_binding)
                or not all(_valid_sha(capsule.get(name)) for name in (
                    "delivery_binding_sha256", "progress_sha256", "target_template_sha256",
                    "artifact_sha256", "owner_context_sha256", "runtime_evidence_sha256"))
                or type(capsule.get("accepted_read_call_count")) is not int
                or not 1 <= capsule["accepted_read_call_count"] <= 256
                or not _valid_sha(capsule.get("progress_sha256"))
                or capsule["progress_sha256"] != progress_digest(capsule.get("progress"))):
            raise ValueError
        if (capsule["target_template_sha256"] != delivery_binding.get("target_template_sha256")
                or capsule["artifact_sha256"] != delivery_binding.get("artifact_sha256")):
            raise ValueError
        calculated = runtime_evidence_digest(
            target_template_sha256=capsule["target_template_sha256"],
            artifact_sha256=capsule["artifact_sha256"],
            owner_context_sha256=capsule["owner_context_sha256"],
            progress_sha256=capsule["progress_sha256"],
            accepted_read_call_count=capsule["accepted_read_call_count"],
        )
        if (capsule["runtime_evidence_sha256"] != calculated
                or (expected_runtime_evidence_sha256 is not None
                    and capsule["runtime_evidence_sha256"] != expected_runtime_evidence_sha256)):
            raise ValueError
        return capsule
    except ObservationEvidenceError:
        raise
    except Exception:
        raise ObservationEvidenceError() from None


def validate_capsule_for_accepted_update(capsule: Any, *, delivery_binding: Any,
                                         accepted_update_state: Any) -> dict[str, Any]:
    """Bind a sidecar capsule to the exact terminal update journal receipt."""
    try:
        if (type(delivery_binding) is not dict
                or type(accepted_update_state) is not dict
                or set(accepted_update_state) != {"binding", "phase", "receipt"}
                or accepted_update_state.get("phase") != "accepted"
                or accepted_update_state.get("binding") != delivery_binding
                or type(accepted_update_state.get("receipt")) is not dict):
            raise ValueError
        receipt = accepted_update_state["receipt"]
        required = {"target_template_sha256", "artifact_sha256", "completion_event_token",
                    "owner_context_sha256", "runtime_evidence_sha256"}
        if (set(receipt) != required
                or receipt.get("target_template_sha256") != delivery_binding.get("target_template_sha256")
                or receipt.get("artifact_sha256") != delivery_binding.get("artifact_sha256")
                or receipt.get("completion_event_token") != delivery_binding.get("client_request_token")
                or not _valid_sha(receipt.get("owner_context_sha256"))
                or not _valid_sha(receipt.get("runtime_evidence_sha256"))):
            raise ValueError
        result = validate_capsule(capsule, delivery_binding=delivery_binding,
                                  expected_runtime_evidence_sha256=receipt["runtime_evidence_sha256"])
        if result.get("owner_context_sha256") != receipt["owner_context_sha256"]:
            raise ValueError
        return result
    except ObservationEvidenceError:
        raise
    except Exception:
        raise ObservationEvidenceError() from None


def validate_observation_window(window: Any, *, account_id: str, operator_arn: str,
                                github_owner_id: int, github_repository_id: int,
                                now: float) -> dict[str, Any]:
    """Validate a fresh read-only time/source descriptor; it grants no writes."""
    try:
        if (type(window) is not dict or set(window) != _WINDOW_FIELDS
                or type(window.get("schema")) is not int or window["schema"] != 1
                or window.get("kind") != "owner-enrolled-readonly-observation"
                or window.get("account_id") != account_id or window.get("operator_arn") != operator_arn
                or type(window.get("source_sha")) is not str
                or _GIT_SHA.fullmatch(window["source_sha"]) is None
                or type(window.get("ci_run_id")) is not int or window["ci_run_id"] <= 0
                or type(window.get("github_owner_id")) is not int
                or window["github_owner_id"] != github_owner_id
                or type(window.get("github_repository_id")) is not int
                or window["github_repository_id"] != github_repository_id
                or type(window.get("authorized_from_epoch")) not in (int, float)
                or isinstance(window.get("authorized_from_epoch"), bool)
                or type(window.get("authorized_until_epoch")) not in (int, float)
                or isinstance(window.get("authorized_until_epoch"), bool)):
            raise ValueError
        start, end = float(window["authorized_from_epoch"]), float(window["authorized_until_epoch"])
        if (not math.isfinite(start) or not math.isfinite(end) or not start < now < end
                or not 0 < end - start <= 600):
            raise ValueError
        return window
    except Exception:
        raise ObservationEvidenceError("observation_window_invalid") from None


def _validate_progress(progress: Any) -> None:
    if type(progress) is not dict or set(progress) != _PROGRESS_FIELDS:
        raise ObservationEvidenceError()
    resources = progress.get("resource_ids")
    history = progress.get("historical_row_sha256")
    if (type(resources) is not dict or len(resources) != 19
            or any(type(k) is not str or not k or type(v) is not str or not v
                   for k, v in resources.items())
            or type(history) is not dict or set(history) != set(_HISTORY_SLOTS)
            or any(not _valid_sha(v) for v in history.values())
            or type(progress.get("authorization_table_id")) is not str
            or not progress["authorization_table_id"]
            or not _valid_sha(progress.get("synthetic_policy_sha256"))):
        raise ObservationEvidenceError()


__all__ = [
    "ObservationEvidenceError", "canonical_bytes", "make_capsule", "make_progress_projection",
    "progress_digest", "runtime_evidence_digest", "sha256_json", "validate_capsule",
    "validate_capsule_for_accepted_update", "validate_observation_window",
]
