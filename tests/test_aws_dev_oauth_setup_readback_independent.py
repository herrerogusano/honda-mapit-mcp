from __future__ import annotations

import json

from test_aws_dev_oauth_setup_readback import _check, _clients


def test_nonempty_route_page_token_is_not_treated_as_empty_routes():
    clients = _clients()
    clients[1].responses[1][1]["NextToken"] = "private-page-token-canary"

    result = _check(clients)

    assert result.category == "routes_unexpected"
    assert result.calls == 4
    assert len(clients[1].calls) == 2
    assert result.client_id is None
    assert "private-page-token-canary" not in json.dumps(result.safe_projection())


def test_client_pagination_stops_before_exposing_client_id():
    clients = _clients()
    clients[3].responses[1][1]["NextToken"] = "second-client-page"

    result = _check(clients)

    assert result.category == "clients_readback_invalid"
    assert result.calls == 7
    assert [method for method, _ in clients[3].calls] == [
        "list_users", "list_user_pool_clients",
    ]
    assert result.client_id is None
    assert "second-client-page" not in repr(result)


def test_boolean_http_status_is_not_accepted_as_integer_200():
    clients = _clients()
    clients[0].responses[0][1]["ResponseMetadata"] = {"HTTPStatusCode": True}

    result = _check(clients)

    assert result.category == "stack_readback_invalid"
    assert result.calls == 1
    assert result.client_id is None
