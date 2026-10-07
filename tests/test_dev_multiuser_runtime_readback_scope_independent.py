"""Independent holdouts for API Gateway's empty-scope readback shapes."""
from __future__ import annotations

import copy

import pytest

from scripts.run_dev_multiuser_accepted_continuation import _verify_multiuser_runtime_children
from tests.test_dev_multiuser_accepted_runtime_readback import (
    ACCOUNT, API, _Api, _Lambda, _fixture,
)

_METADATA_ROUTES = (
    "GET /.well-known/oauth-protected-resource/mcp",
    "GET /.well-known/oauth-authorization-server",
)
_POST_ROUTE = "POST /mcp"


def _verify(api: _Api) -> None:
    template, rows = _fixture()
    _verify_multiuser_runtime_children(
        {"apigatewayv2": api, "lambda": _Lambda()}, template, rows,
        account=ACCOUNT, api_id=API,
    )


def _route(api: _Api, key: str) -> dict:
    return next(row for row in api.routes if row["RouteKey"] == key)


@pytest.mark.parametrize("empty_shape", [None, []])
def test_metadata_routes_accept_only_sdk_empty_scope_shapes(empty_shape):
    api = _Api()
    for key in _METADATA_ROUTES:
        _route(api, key)["AuthorizationScopes"] = copy.deepcopy(empty_shape)
    _verify(api)


@pytest.mark.parametrize("bad_shape", [
    "", "openid", {"scope": "openid"}, ["openid"], [None], [1], True,
])
def test_metadata_routes_reject_malformed_or_nonempty_scopes(bad_shape):
    api = _Api()
    _route(api, _METADATA_ROUTES[0])["AuthorizationScopes"] = copy.deepcopy(bad_shape)
    with pytest.raises(Exception) as exc:
        _verify(api)
    assert getattr(exc.value, "category", None) == "accepted_runtime_invalid"


@pytest.mark.parametrize("bad_shape", [None, [], [API], [f"{API}/use", f"{API}/other"], "openid"])
def test_post_route_rejects_empty_or_nonexact_scope_shapes(bad_shape):
    api = _Api()
    _route(api, _POST_ROUTE)["AuthorizationScopes"] = copy.deepcopy(bad_shape)
    with pytest.raises(Exception) as exc:
        _verify(api)
    assert getattr(exc.value, "category", None) == "accepted_runtime_invalid"
