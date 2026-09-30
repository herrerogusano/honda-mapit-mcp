"""Fail before any socket call if conftest's external-network guard is absent."""

import socket
import urllib.request

import pytest


def test_external_network_guard_is_loaded_and_rejects_before_connect():
    assert socket.create_connection.__name__ == "guarded_create_connection"
    assert socket.socket.connect.__name__ == "guarded_connect"
    assert urllib.request.urlopen.__name__ == "blocked"
    with pytest.raises(AssertionError, match="real network access is forbidden"):
        socket.create_connection(("203.0.113.1", 443), timeout=0.01)
    with pytest.raises(AssertionError, match="real network access is forbidden"):
        urllib.request.urlopen("https://synthetic.invalid")
