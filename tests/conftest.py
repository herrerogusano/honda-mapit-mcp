"""Keep the offline test suite from making real network requests."""

import ipaddress
import socket
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("real network access is forbidden in offline tests")

    def _is_loopback_address(address):
        if not isinstance(address, tuple) or not address:
            return False
        host = address[0]
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_create_connection = socket.create_connection

    def guarded_connect(self, address):
        if _is_loopback_address(address):
            return original_connect(self, address)
        raise AssertionError("real network access is forbidden in offline tests")

    def guarded_connect_ex(self, address):
        if _is_loopback_address(address):
            return original_connect_ex(self, address)
        raise AssertionError("real network access is forbidden in offline tests")

    def guarded_create_connection(address, *args, **kwargs):
        if _is_loopback_address(address):
            return original_create_connection(address, *args, **kwargs)
        raise AssertionError("real network access is forbidden in offline tests")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
