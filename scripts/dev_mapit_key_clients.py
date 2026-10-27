"""Explicit same-credential STS/SSM composition for the MAPIT key publisher.

No default credential discovery, files, environment mutation or network calls.
The reviewed caller obtains short-lived credentials for the exact new enroller
role; the publisher separately verifies that role with fresh STS before use.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import math
import time


def create_mapit_key_clients(credentials: Mapping, *, wall_clock=time.time):
    """Build both clients from one explicit in-memory temporary credential triple.

    This establishes construction parity, not a successful role/account check.
    The returned clients and their credentials must never be logged or saved.
    """
    try:
        fields = {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}
        if not isinstance(credentials, Mapping) or set(credentials) != fields or not callable(wall_clock):
            raise ValueError
        triple = {name: credentials[name] for name in fields - {"Expiration"}}
        if any(type(value) is not str or not 1 <= len(value) <= 16384
                or any(ord(char) < 33 or ord(char) > 126 for char in value) for value in triple.values()):
            raise ValueError
        expiration, now = credentials["Expiration"], wall_clock()
        if (not isinstance(expiration, datetime) or expiration.tzinfo is None
                or expiration.utcoffset() is None or type(now) not in (int, float)
                or not math.isfinite(now) or not 20 <= expiration.timestamp() - now <= 3600):
            raise ValueError
        import boto3
        from botocore.config import Config
        config = Config(region_name="eu-west-1", signature_version="v4", connect_timeout=2,
            read_timeout=2, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={})
        values = dict(aws_access_key_id=triple["AccessKeyId"], aws_secret_access_key=triple["SecretAccessKey"],
            aws_session_token=triple["SessionToken"], region_name="eu-west-1")
        session = boto3.session.Session(**values)
        return {service: session.client(service, **values, config=config, verify=True,
            endpoint_url=f"https://{service}.eu-west-1.amazonaws.com") for service in ("sts", "ssm")}
    except Exception:
        raise ValueError("mapit_key_clients_unverified") from None


__all__ = ["create_mapit_key_clients"]
