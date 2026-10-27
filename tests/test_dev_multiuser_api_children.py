from __future__ import annotations

from copy import deepcopy

import pytest

from scripts.dev_multiuser_api_children import verify_empty_api_children


API = "abcdefghij"


def _ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Api:
    def __init__(self, *, mutation=None):
        self.calls = []
        self.replies = {
            "get_authorizers": _ok(Items=[]),
            "get_routes": _ok(Items=[]),
            "get_integrations": _ok(Items=[]),
        }
        if mutation:
            mutation(self.replies)

    def __getattr__(self, name):
        def read(**kwargs):
            self.calls.append((name, kwargs))
            return deepcopy(self.replies[name])
        return read


def test_empty_children_are_three_bounded_single_page_reads():
    api = Api()
    assert verify_empty_api_children(api, api_id=API) == {
        "success": True, "category": "api_children_empty", "calls": 3,
    }
    assert [name for name, _ in api.calls] == [
        "get_authorizers", "get_routes", "get_integrations",
    ]
    assert all(kwargs == {"ApiId": API, "MaxResults": "100"} for _, kwargs in api.calls)


@pytest.mark.parametrize("mutation", [
    lambda replies: replies["get_authorizers"].update(Items=[{"AuthorizerId": "auth"}]),
    lambda replies: replies["get_routes"].update(Items=[{"RouteId": "route"}]),
    lambda replies: replies["get_integrations"].update(Items=[{"IntegrationId": "integration"}]),
    lambda replies: replies["get_routes"].pop("Items"),
    lambda replies: replies["get_routes"].update(Items=None),
    lambda replies: replies["get_routes"].update(Items=()),
    lambda replies: replies["get_routes"].update(NextToken="more"),
    lambda replies: replies["get_routes"].update(ResponseMetadata={"HTTPStatusCode": 500}),
])
def test_nonempty_or_malformed_child_read_fails_closed(mutation):
    api = Api()
    mutation(api.replies)
    result = verify_empty_api_children(api, api_id=API)
    assert result["success"] is False
    assert result["category"] in {"api_children_not_empty", "api_children_read_failed"}


@pytest.mark.parametrize("api_id", ["", "ABCDEFGHIJ", "abc", "abcdefghijk", None, 1234567890])
def test_invalid_api_id_fails_before_any_client_call(api_id):
    api = Api()
    assert verify_empty_api_children(api, api_id=api_id)["success"] is False
    assert api.calls == []


def test_missing_client_method_fails_before_any_read():
    class Partial:
        def get_authorizers(self, **kwargs):
            raise AssertionError("must not call partial client")

    result = verify_empty_api_children(Partial(), api_id=API)
    assert result == {"success": False, "category": "api_children_client_invalid", "calls": 0}
