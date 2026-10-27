"""Bounded read-only proof that the retained DEV API has no children.

This helper deliberately accepts an injected API Gateway v2 client.  It does
not construct a client, discover an API, follow pagination, or expose service
errors.  A successful result means only that the three bounded child lists
were observed empty at the time of the reads.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


_API_ID = re.compile(r"[a-z0-9]{10}\Z")
_READS = ("get_authorizers", "get_routes", "get_integrations")


def _result(success: bool, category: str, calls: int) -> dict[str, Any]:
    return {"success": success, "category": category, "calls": calls}


def verify_empty_api_children(apigatewayv2: Any, *, api_id: str) -> dict[str, Any]:
    """Read exactly three single-page API Gateway child collections.

    The function is fail-closed and returns stable categories only.  It never
    returns response bodies, IDs, URLs, or exception text.
    """
    if type(api_id) is not str or _API_ID.fullmatch(api_id) is None:
        return _result(False, "api_children_binding_invalid", 0)
    if apigatewayv2 is None or any(not callable(getattr(apigatewayv2, name, None)) for name in _READS):
        return _result(False, "api_children_client_invalid", 0)

    calls = 0
    try:
        for method in _READS:
            calls += 1
            response = getattr(apigatewayv2, method)(ApiId=api_id, MaxResults="100")
            if not isinstance(response, Mapping):
                return _result(False, "api_children_response_invalid", calls)
            metadata = response.get("ResponseMetadata")
            if (not isinstance(metadata, Mapping)
                or type(metadata.get("HTTPStatusCode")) is not int
                or metadata["HTTPStatusCode"] != 200
                or response.get("NextToken") not in (None, "")
                or type(response.get("Items")) is not list
                or response["Items"] != []):
                return _result(False, "api_children_not_empty", calls)
    except Exception:
        return _result(False, "api_children_read_failed", calls)
    return _result(True, "api_children_empty", calls)


__all__ = ["verify_empty_api_children"]
