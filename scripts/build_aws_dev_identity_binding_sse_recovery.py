"""Pure fixed-template builder for the DEV table SSE recovery candidate."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap


def templates(binding: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes, str, str]:
    """Return original and exact AWS-owned-encryption target templates.

    The only resource-property difference is the existing table's
    ``SSESpecification.SSEEnabled`` value. This module intentionally has no
    runtime/provider imports so it is safe for the pinned static schema checker.
    """
    original = build_dev_identity_binding_bootstrap(
        account_id=binding["account_id"], operator_user_arn=binding["operator_user_arn"],
        tenant_keys=binding["tenant_keys"], ssm_key_arn=binding["ssm_key_arn"],
    )
    target = json.loads(json.dumps(original))
    old_sse = target["Resources"]["MapitIdentityBindings"]["Properties"]["SSESpecification"]
    if old_sse != {"SSEEnabled": True}:
        raise ValueError("template_invalid")
    target["Resources"]["MapitIdentityBindings"]["Properties"]["SSESpecification"] = {"SSEEnabled": False}
    old_bytes = json.dumps(original, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False).encode("ascii")
    new_bytes = json.dumps(target, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                           allow_nan=False).encode("ascii")
    old_sha, new_sha = hashlib.sha256(old_bytes).hexdigest(), hashlib.sha256(new_bytes).hexdigest()
    if old_bytes == new_bytes:
        raise ValueError("template_invalid")
    return original, target, old_bytes, new_bytes, old_sha, new_sha


def target_template(binding: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    _, target, _, _, _, digest = templates(binding)
    return target, digest


__all__ = ["templates", "target_template"]
