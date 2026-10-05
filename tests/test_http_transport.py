import urllib.error
import urllib.request

import pytest

from mapit import http_transport


def test_direct_opener_disables_proxies_and_rejects_redirects(monkeypatch):
    captured = []
    opened = []

    class Opener:
        def open(self, request, timeout):
            opened.append((request, timeout))
            return type("Response", (), {"status": 302, "closed": False, "close": lambda self: setattr(self, "closed", True)})()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: captured.append(handlers) or Opener())
    opener = http_transport.direct_opener()
    assert any(isinstance(item, urllib.request.ProxyHandler) and item.proxies == {} for item in captured[0])
    redirect_handler = next(item for item in captured[0] if isinstance(item, http_transport.NoRedirectHandler))
    assert redirect_handler.redirect_request(None, None, 301, "moved", {}, "https://other.invalid") is None
    req = urllib.request.Request("https://example.invalid/a")
    with pytest.raises(urllib.error.HTTPError) as caught:
        http_transport.open_direct(req, timeout=2, opener=opener)
    assert caught.value.code == 302
    assert len(opened) == 1


def test_bounded_reader_uses_small_chunks_and_rejects_overflow():
    sizes = []

    class Response:
        def __init__(self, content):
            self.content = content

        def read1(self, size):
            sizes.append(size)
            chunk, self.content = self.content[:size], self.content[size:]
            return chunk

    assert http_transport.read_bounded(Response(b"12345"), 5) == b"12345"
    assert max(sizes) <= http_transport.READ_CHUNK_BYTES
    with pytest.raises(http_transport.ResponseTooLargeError):
        http_transport.read_bounded(Response(b"123456"), 5)
