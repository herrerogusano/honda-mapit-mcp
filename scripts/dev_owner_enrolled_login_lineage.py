"""Offline contract for post-delivery owner login lineage.

The historical owner-login verifier deliberately pins the pre-update handler
code and revision. It must not be weakened or reused after an owner-enrolled
delivery. This module validates the accepted delivery journal plus an exact
current-readback projection supplied by a separately reviewed adapter.

This is a pure injected validator, not an AWS adapter and not live-login
readiness. The readback mappings and credential snapshot are trusted adapter
outputs. In particular, ``CredentialSnapshot`` proves only that two trusted
adapters carried the same in-memory capability object; it does not prove that
an AWS SDK used those credentials. A production adapter must bind that object
to the credentials actually used by its clients and perform fresh provider
readbacks before calling this validator.
"""
from __future__ import annotations

import hashlib
import re
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts import dev_owner_login_context as _owner_context
from scripts.dev_owner_enrolled_delivery import (
    _canonical,
    _strict_state,
    _validate_accepted,
    _validate_authority,
)

_LINEAGES: weakref.WeakValueDictionary[int, "OwnerEnrolledLoginLineage"] = weakref.WeakValueDictionary()
_SNAPSHOTS: weakref.WeakSet["CredentialSnapshot"] = weakref.WeakSet()
_SNAPSHOT_MINT = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_POOL_ID = re.compile(r"eu-west-1_[A-Za-z0-9]{9,45}\Z")
_CLIENT_ID = re.compile(r"[A-Za-z0-9]{8,128}\Z")
_API_ID = re.compile(r"[a-z0-9]{10}\Z")
_OWNER_IDENTITY_FIELDS = frozenset({
    "account_id", "owner_pool_id", "client_id", "owner_subject", "api_id",
    "issuer", "resource_uri", "audience", "scope",
})
_CURRENT_FIELDS = frozenset({"state", "owner_identity", "current_context_sha256", "credential_snapshot"})
_OAUTH_FIELDS = frozenset({"owner_identity", "current_context_sha256", "credential_snapshot"})


class OwnerEnrolledLoginLineageError(ValueError):
    """Closed-category failure that never includes identities or provider data."""

    _CATEGORIES = frozenset({
        "owner_context_invalid", "delivery_receipt_invalid", "current_readback_invalid",
        "credential_binding_invalid", "lineage_invalid",
    })

    def __init__(self, category: str = "lineage_invalid") -> None:
        safe = category if type(category) is str and category in self._CATEGORIES else "lineage_invalid"
        self.category = safe
        super().__init__(safe)


class CredentialSnapshot:
    """Opaque, redacted snapshot minted from an explicit frozen credential set.

    The snapshot is process-local and is never serialized. It retains the
    credential tuple only in memory so the trusted paired adapter can compare
    credentials without printing or persisting them.
    """

    __slots__ = ("_access_key", "_secret_key", "_session_token", "__weakref__")

    def __init__(self, access_key: str, secret_key: str, session_token: str | None, *, _mint=None):
        if _mint is not _SNAPSHOT_MINT:
            raise TypeError("snapshot must come from the trusted adapter helper")
        object.__setattr__(self, "_access_key", access_key)
        object.__setattr__(self, "_secret_key", secret_key)
        object.__setattr__(self, "_session_token", session_token)
        _SNAPSHOTS.add(self)

    def __setattr__(self, _name, _value):
        raise AttributeError("credential snapshot is immutable")

    def __repr__(self) -> str:
        return "CredentialSnapshot(<redacted>)"


def credential_snapshot_from_explicit_credentials(credentials: Any) -> CredentialSnapshot:
    """Create a redacted capability from a frozen SDK credential object.

    The trusted client factory should call this once, then attach the *same
    object* to its current-runtime and owner-identity readback projections.
    This helper does not construct clients or prove that the factory used the
    supplied credentials.
    """
    try:
        access = credentials.access_key
        secret = credentials.secret_key
        token = credentials.token
        if (type(access) is not str or not 16 <= len(access) <= 128
                or type(secret) is not str or not 16 <= len(secret) <= 4096
                or (token is not None and (type(token) is not str or not 16 <= len(token) <= 8192))):
            raise ValueError
        return CredentialSnapshot(access, secret, token, _mint=_SNAPSHOT_MINT)
    except Exception:
        raise OwnerEnrolledLoginLineageError("credential_binding_invalid") from None


@dataclass(frozen=True, repr=False)
class OwnerEnrolledLoginLineage:
    """Registered, ephemeral result usable only by the post-delivery path."""

    policy: CognitoDevPolicy = field(repr=False)
    account_id: str
    operator_arn: str
    stack_id: str
    source_sha: str
    target_template_sha256: str
    artifact_sha256: str
    runtime_evidence_sha256: str
    owner_context_sha256: str
    delivery_receipt_sha256: str
    _credential_snapshot: CredentialSnapshot = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "OwnerEnrolledLoginLineage(<redacted>)"


def _owner_identity(value: Any, *, context: Any, authority: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _OWNER_IDENTITY_FIELDS:
        raise OwnerEnrolledLoginLineageError("current_readback_invalid")
    policy = context.policy
    expected = {
        "account_id": authority["account_id"],
        "owner_pool_id": policy.user_pool_id,
        "client_id": policy.client_id,
        "owner_subject": policy.owner_subject,
        "api_id": policy.api_id,
        "issuer": policy.issuer_url,
        "resource_uri": policy.resource_url,
        "audience": policy.audience,
        "scope": policy.required_scope,
    }
    if value != expected:
        raise OwnerEnrolledLoginLineageError("current_readback_invalid")
    if (_POOL_ID.fullmatch(value["owner_pool_id"]) is None
            or _CLIENT_ID.fullmatch(value["client_id"]) is None
            or _API_ID.fullmatch(value["api_id"]) is None):
        raise OwnerEnrolledLoginLineageError("current_readback_invalid")
    return dict(value)


def validate_owner_enrolled_login_lineage(
    *,
    original_context: Any,
    delivery_authority: Any,
    accepted_receipts: Any,
    accepted_update_state: Any,
    current_runtime_readback: Any,
    owner_identity_readback: Any,
) -> OwnerEnrolledLoginLineage:
    """Validate identity continuity across an accepted owner-enrolled update.

    ``accepted_update_state`` is the exact loaded update-journal value from the
    frozen delivery coordinator. ``current_runtime_readback`` and
    ``owner_identity_readback`` are exact projections from one separately
    reviewed adapter; both must carry the same registered credential snapshot.
    This function performs no I/O and cannot establish that those projections
    came from AWS. It therefore does not itself authorize a live login.
    """
    try:
        if (type(original_context) is not _owner_context.AcceptedOwnerLoginContext
                or _owner_context._ACCEPTED.get(id(original_context)) is not original_context
                or type(original_context.policy) is not CognitoDevPolicy):
            raise OwnerEnrolledLoginLineageError("owner_context_invalid")

        authority = _validate_authority(delivery_authority)
        receipts = _validate_accepted(accepted_receipts, authority)
        if (type(receipts["invitation"].get("revision")) is not int
                or receipts["invitation"]["revision"] != 1
                or type(receipts["key_publication"].get("version")) is not int
                or receipts["key_publication"]["version"] != 1):
            raise OwnerEnrolledLoginLineageError("delivery_receipt_invalid")
        if (authority["account_id"] != original_context.account
                or authority["operator_arn"] != original_context.operator
                or authority["owner_context_sha256"] != original_context.context_digest
                or authority["owner_pool_id"] != original_context.policy.user_pool_id
                or authority["owner_client_id"] != original_context.policy.client_id
                or authority["owner_resource_uri"] != original_context.policy.resource_url
                or receipts["owner_oauth"]["scope"] != original_context.policy.required_scope):
            raise OwnerEnrolledLoginLineageError("delivery_receipt_invalid")

        state = accepted_update_state
        if (type(state) is not dict or set(state) != {"binding", "phase", "receipt"}
                or state.get("phase") != "accepted" or type(state.get("binding")) is not dict
                or type(state.get("receipt")) is not dict):
            raise OwnerEnrolledLoginLineageError("delivery_receipt_invalid")
        receipt = state["receipt"]
        if set(receipt) != {"target_template_sha256", "artifact_sha256", "completion_event_token",
                            "runtime_evidence_sha256", "owner_context_sha256"}:
            raise OwnerEnrolledLoginLineageError("delivery_receipt_invalid")
        delivery_binding = state["binding"]
        expected_delivery_binding_fields = {
            "schema", "kind", "authority", "accepted", "prior_template_sha256",
            "target_template_sha256", "artifact_sha256", "artifact_size", "client_request_token",
        }
        if (set(delivery_binding) != expected_delivery_binding_fields
                or type(delivery_binding.get("schema")) is not int or delivery_binding["schema"] != 1
                or delivery_binding.get("kind") != "dev-owner-enrolled-delivery"
                or delivery_binding.get("authority") != authority
                or _canonical(delivery_binding.get("accepted")) != _canonical(receipts)
                or delivery_binding.get("prior_template_sha256") != authority["prior_template_sha256"]
                or delivery_binding.get("target_template_sha256") != receipt["target_template_sha256"]
                or delivery_binding.get("artifact_sha256") != receipt["artifact_sha256"]
                or type(delivery_binding.get("artifact_size")) is not int
                or isinstance(delivery_binding.get("artifact_size"), bool)
                or delivery_binding["artifact_size"] <= 0
                or delivery_binding.get("client_request_token") != f"owner-enrolled-{authority['run_id']}"
                or receipt.get("completion_event_token") != delivery_binding.get("client_request_token")
                or any(type(receipt.get(k)) is not str or _SHA256.fullmatch(receipt[k]) is None
                       for k in ("target_template_sha256", "artifact_sha256", "runtime_evidence_sha256",
                                 "owner_context_sha256"))
                or receipt["owner_context_sha256"] == original_context.context_digest):
            raise OwnerEnrolledLoginLineageError("delivery_receipt_invalid")

        current = current_runtime_readback
        if type(current) is not dict or set(current) != _CURRENT_FIELDS:
            raise OwnerEnrolledLoginLineageError("current_readback_invalid")
        current_context_sha = current["current_context_sha256"]
        if (type(current_context_sha) is not str or _SHA256.fullmatch(current_context_sha) is None
                or current_context_sha != receipt["owner_context_sha256"]):
            raise OwnerEnrolledLoginLineageError("current_readback_invalid")
        current_state = current["state"]
        if (type(current_state) is not dict
                or current_state.get("runtime_evidence_sha256") != receipt["runtime_evidence_sha256"]
                or current_state.get("owner_context_sha256") != receipt["owner_context_sha256"]):
            raise OwnerEnrolledLoginLineageError("current_readback_invalid")
        try:
            _strict_state(current_state, phase="accepted", binding=authority,
                prior_sha=authority["prior_template_sha256"],
                target_sha=receipt["target_template_sha256"], zip_sha=receipt["artifact_sha256"],
                leading_keys=[*authority["historical_tenant_keys"], authority["owner_tenant_key"]],
                issuer=original_context.policy.issuer_url)
        except Exception:
            raise OwnerEnrolledLoginLineageError("current_readback_invalid") from None
        _owner_identity(current["owner_identity"], context=original_context, authority=authority)
        _owner_identity(owner_identity_readback.get("owner_identity") if type(owner_identity_readback) is dict else None,
                        context=original_context, authority=authority)
        if (type(owner_identity_readback) is not dict
                or set(owner_identity_readback) != _OAUTH_FIELDS
                or owner_identity_readback.get("current_context_sha256") != current_context_sha):
            raise OwnerEnrolledLoginLineageError("current_readback_invalid")
        runtime_snapshot = current["credential_snapshot"]
        oauth_snapshot = owner_identity_readback["credential_snapshot"]
        if (type(runtime_snapshot) is not CredentialSnapshot or runtime_snapshot not in _SNAPSHOTS
                or oauth_snapshot is not runtime_snapshot):
            raise OwnerEnrolledLoginLineageError("credential_binding_invalid")

        lineage = OwnerEnrolledLoginLineage(
            original_context.policy, authority["account_id"], authority["operator_arn"],
            authority["stack_id"], authority["source_sha"], receipt["target_template_sha256"],
            receipt["artifact_sha256"], receipt["runtime_evidence_sha256"],
            current_context_sha,
            hashlib.sha256(_canonical({"accepted_receipts": receipts, "update_receipt": receipt})).hexdigest(),
            runtime_snapshot,
        )
        _LINEAGES[id(lineage)] = lineage
        return lineage
    except OwnerEnrolledLoginLineageError:
        raise
    except Exception:
        raise OwnerEnrolledLoginLineageError("lineage_invalid") from None


def is_registered_owner_enrolled_lineage(value: Any) -> bool:
    """Identity check for an ephemeral lineage object; no equality authority."""
    return (type(value) is OwnerEnrolledLoginLineage
            and _LINEAGES.get(id(value)) is value
            and type(value.policy) is CognitoDevPolicy)


__all__ = [
    "CredentialSnapshot", "OwnerEnrolledLoginLineage", "OwnerEnrolledLoginLineageError",
    "credential_snapshot_from_explicit_credentials", "is_registered_owner_enrolled_lineage",
    "validate_owner_enrolled_login_lineage",
]
