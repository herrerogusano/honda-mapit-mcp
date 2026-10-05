"""Value-free recursive schemas for authorized MAPIT response inspection."""

from __future__ import annotations

import re
from typing import Any


_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_JWT = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_IDENTIFIER_PREFIX = re.compile(r"^(?:id|account|vehicle|device|subscription|user|vin|imei)(?:[-_:0-9]|$)", re.I)
_MIXED_TYPES = frozenset({"object", "array", "string", "number", "boolean", "null", "unknown"})


def safe_field_name(name: Any) -> str:
    """Keep ordinary field names while replacing dynamic sensitive key names."""
    text = str(name)
    lowered = text.lower()
    if _EMAIL.fullmatch(text):
        return "<email>"
    if _UUID.fullmatch(text):
        return "<uuid>"
    if _JWT.fullmatch(text) or lowered in {"token", "id_token", "access_token", "refresh_token", "session_token"} or ("token" in lowered and len(text) >= 16):
        return "<token>"
    # Require at least one digit so long ordinary field names are retained.
    if _OPAQUE_ID.fullmatch(text) and any(char.isdigit() for char in text):
        return "<id>"
    # Dynamic keys can be shorter than opaque tokens or contain a tenant-style
    # separator.  Keep ordinary schema names, but neutralize identifier-like
    # prefixes and compact mixed keys before they reach persisted schemas/UI.
    digit_count = sum(char.isdigit() for char in text)
    if (
        (_IDENTIFIER_PREFIX.match(text) and digit_count)
        or (":" in text and len(text) >= 6)
        or (digit_count >= 2 and len(text) >= 6)
        or (text[:1].isdigit() and len(text) >= 6)
    ):
        return "<id>"
    return text


def _primitive_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if isinstance(value, str):
        return "string"
    return "unknown"


def _allowed_types(node: dict[str, Any]) -> set[str]:
    node_type = node.get("type")
    if node_type != "mixed":
        return {node_type} if node_type in _MIXED_TYPES else {"unknown"}
    types = node.get("types")
    if not isinstance(types, list):
        return {"unknown"}
    allowed = {item for item in types if isinstance(item, str) and item in _MIXED_TYPES}
    return allowed or {"unknown"}


def _merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Merge schemas without retaining values, counts, lengths, or examples."""
    left_type = left["type"]
    right_type = right["type"]
    nullable = bool(left.get("nullable")) or bool(right.get("nullable"))
    if left_type == "null":
        result = dict(right)
        result["nullable"] = True
        return result
    if right_type == "null":
        result = dict(left)
        result["nullable"] = True
        return result
    if left_type == "mixed" or right_type == "mixed":
        return {"type": "mixed", "types": sorted(_allowed_types(left) | _allowed_types(right)), "nullable": nullable}
    if left_type != right_type:
        types = _allowed_types(left) | _allowed_types(right)
        return {"type": "mixed", "types": sorted(types), "nullable": nullable}
    if left_type == "object":
        fields: dict[str, dict[str, Any]] = {}
        for key in sorted(set(left.get("fields", {})) | set(right.get("fields", {}))):
            if key in left.get("fields", {}) and key in right.get("fields", {}):
                fields[key] = _merge(left["fields"][key], right["fields"][key])
            elif key in left.get("fields", {}):
                fields[key] = dict(left["fields"][key])
            else:
                fields[key] = dict(right["fields"][key])
        return {"type": "object", "nullable": nullable, "fields": fields}
    if left_type == "array":
        left_items = left.get("items", {"type": "unknown", "nullable": False})
        right_items = right.get("items", {"type": "unknown", "nullable": False})
        return {"type": "array", "nullable": nullable, "items": _merge(left_items, right_items)}
    return {"type": left_type, "nullable": nullable}


def schema_only(value: Any) -> dict[str, Any]:
    """Convert arbitrary decoded JSON to a recursive value-free schema."""
    if value is None:
        return {"type": "null", "nullable": True}
    if isinstance(value, dict):
        fields: dict[str, dict[str, Any]] = {}
        for raw_key, raw_value in value.items():
            key = safe_field_name(raw_key)
            child = schema_only(raw_value)
            fields[key] = _merge(fields[key], child) if key in fields else child
        return {"type": "object", "nullable": False, "fields": dict(sorted(fields.items()))}
    if isinstance(value, list):
        items: dict[str, Any] | None = None
        for item in value:
            child = schema_only(item)
            items = child if items is None else _merge(items, child)
        return {
            "type": "array",
            "nullable": False,
            "items": items or {"type": "unknown", "nullable": False},
        }
    return {"type": _primitive_type(value), "nullable": False}
