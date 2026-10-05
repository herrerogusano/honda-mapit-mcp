"""Independent negative probes for the synthetic local HTTP boundary."""

import asyncio

import pytest

from mapit.remote_http import _BoundedHTTPMiddleware, dev_http_config


def _scope(headers):
    return {"type": "http", "method": "POST", "path": "/mcp", "headers": headers}


@pytest.mark.parametrize(
    "headers",
    [
        [(b"host", b"mapit.dev.example.invalid"), (b"host", b"mapit.dev.example.invalid")],
        [
            (b"host", b"mapit.dev.example.invalid"),
            (b"origin", b"https://mapit.dev.example.invalid"),
            (b"origin", b"https://mapit.dev.example.invalid"),
        ],
        [
            (b"host", b"mapit.dev.example.invalid"),
            (b"content-length", b"0"),
            (b"content-length", b"0"),
        ],
    ],
)
def test_duplicate_host_origin_and_content_length_are_rejected_before_dispatch(headers):
    dispatched = False

    async def app(scope, receive, send):
        nonlocal dispatched
        dispatched = True

    middleware = _BoundedHTTPMiddleware(app, dev_http_config())

    async def scenario():
        outgoing = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            outgoing.append(message)

        await middleware(_scope(headers), receive, send)
        assert outgoing[0]["status"] == 400
        assert dispatched is False

    asyncio.run(scenario())


def test_downstream_exception_group_is_replaced_with_static_sanitized_error():
    async def app(scope, receive, send):
        raise ExceptionGroup("synthetic failure", [ValueError("do-not-return-this-detail")])

    middleware = _BoundedHTTPMiddleware(app, dev_http_config())

    async def scenario():
        outgoing = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            outgoing.append(message)

        await middleware(_scope([(b"host", b"mapit.dev.example.invalid")]), receive, send)
        assert outgoing[0]["status"] == 500
        response_body = b"".join(message.get("body", b"") for message in outgoing)
        assert response_body == b'{"error":"internal_error"}'
        assert b"do-not-return-this-detail" not in response_body

    asyncio.run(scenario())


@pytest.mark.parametrize("grouped", [False, True])
def test_body_receive_exception_is_sanitized_without_leaking_details(grouped):
    async def app(scope, receive, send):
        raise AssertionError("body receive failure should prevent dispatch")

    middleware = _BoundedHTTPMiddleware(app, dev_http_config())

    async def scenario():
        outgoing = []

        async def receive():
            if grouped:
                raise ExceptionGroup("synthetic receive failure", [ValueError("receive-secret")])
            raise OSError("receive-secret")

        async def send(message):
            outgoing.append(message)

        await middleware(_scope([(b"host", b"mapit.dev.example.invalid")]), receive, send)
        assert outgoing[0]["status"] == 400
        response_body = b"".join(message.get("body", b"") for message in outgoing)
        assert response_body == b'{"error":"invalid_request"}'
        assert b"receive-secret" not in response_body

    asyncio.run(scenario())
