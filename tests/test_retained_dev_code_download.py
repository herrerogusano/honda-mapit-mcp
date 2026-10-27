from email.message import Message
import ssl

import pytest

from scripts.retained_dev_code_download import CodeDownloadError, HOST, download_initial_code


URL = "https://" + HOST + "/private.zip?signature=synthetic"


class Response:
    status = 200

    def __init__(self, body=b"zip"):
        self.body = body
        self.headers = Message()
        self.headers["Content-Length"] = str(len(body))
        self.closed = False

    def read(self, size):
        part, self.body = self.body[:size], self.body[size:]
        return part

    def close(self):
        self.closed = True


class Connection:
    sock = None

    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def invoke(response, **kwargs):
    connection = Connection(response)

    def factory(host, *, port, timeout, context):
        assert host == HOST and port == 443 and 0 < timeout <= 3
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        return connection

    return download_initial_code(URL, 100, 10, connection_factory=factory, **kwargs), connection


def test_direct_verified_tls_one_request_and_cleanup():
    response = Response()
    value, connection = invoke(response)
    assert value == b"zip" and len(connection.requests) == 1
    assert response.closed and connection.closed


@pytest.mark.parametrize("status", [301, 302, 307, 403, 500, True])
def test_no_redirect_or_error_payload(status):
    response = Response()
    response.status = status
    with pytest.raises(CodeDownloadError, match="^code_download_failed$"):
        invoke(response)
    assert response.closed


@pytest.mark.parametrize("url", [URL.replace("https", "http"), URL.replace(HOST, "other.invalid"),
                                    URL + "#fragment", URL.replace("https://", "https://user@"),
                                    URL + "\r\nsecret"])
def test_bad_url_before_connection(url):
    with pytest.raises(CodeDownloadError):
        download_initial_code(url, 100, 10, connection_factory=lambda *a, **k: pytest.fail("network"))


@pytest.mark.parametrize("change", ["duplicate", "oversize", "chunked", "compressed", "truncated"])
def test_bad_headers_and_body(change):
    response = Response()
    if change == "duplicate":
        response.headers["Content-Length"] = "3"
    elif change == "oversize":
        response.headers.replace_header("Content-Length", "101")
    elif change == "chunked":
        response.headers["Transfer-Encoding"] = "chunked"
    elif change == "compressed":
        response.headers["Content-Encoding"] = "gzip"
    else:
        response.body = b""
    with pytest.raises(CodeDownloadError):
        invoke(response)


@pytest.mark.parametrize("ticks", [[1, 0], [1, 11], [1, float("nan")]])
def test_clock_failure_prevents_request(ticks):
    clock = iter(ticks)
    with pytest.raises(CodeDownloadError):
        invoke(Response(), monotonic=lambda: next(clock))
