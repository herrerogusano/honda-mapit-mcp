"""Explicit, same-credential SSM/STS pair for private enrollment.

Construction does not discover credentials or contact AWS. Verification is a
fresh, single STS call on the exact pair; neither receipts nor account strings
substitute for it. The caller supplies short-lived credentials in memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import re
import threading
import time
from typing import Any, Callable, Mapping


class EnrollmentClientError(ValueError):
    def __init__(self):
        super().__init__("enrollment_client_invalid")


@dataclass(frozen=True, repr=False)
class EnrollmentAwsClients:
    ssm: Any = field(repr=False)
    account_verifier: Callable[[Any, str], bool] = field(repr=False)
    dynamodb: Any = field(default=None, repr=False)
    dynamodb_account_verifier: Callable[[Any, str], bool] | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "EnrollmentAwsClients(<redacted>)"


def create_enrollment_clients(*, access_key: str, secret_key: str,
                              session_token: str, deadline: float,
                              include_dynamodb: bool = False,
                              monotonic: Callable[[], float] = time.monotonic) -> EnrollmentAwsClients:
    """Build an explicitly credentialed eu-west-1 pair, without any I/O.

    Temporary credentials only. No default boto3 session or environment lookup
    is used. The returned verifier is single-use, even on an ambiguous STS call.
    """
    try:
        if (any(type(value) is not str or not value or len(value) > 16384
                or any(ord(char) < 33 or ord(char) == 127 for char in value)
                for value in (access_key, secret_key, session_token))
            or type(include_dynamodb) is not bool
            or not callable(monotonic) or type(deadline) not in (int, float)
            or not math.isfinite(deadline)):
            raise ValueError
        now = monotonic()
        if type(now) not in (int, float) or not math.isfinite(now) or not 0 <= now < deadline <= now + 14:
            raise ValueError
        import boto3
        from botocore.config import Config
        config = Config(region_name="eu-west-1", connect_timeout=2, read_timeout=2,
                        retries={"total_max_attempts": 1, "mode": "standard"})
        # Explicit arguments prevent botocore's credential provider chain.
        kwargs = dict(aws_access_key_id=access_key, aws_secret_access_key=secret_key,
                      aws_session_token=session_token, config=config,
                      region_name="eu-west-1")
        session = boto3.session.Session(aws_access_key_id=access_key,
                                       aws_secret_access_key=secret_key,
                                       aws_session_token=session_token,
                                       region_name="eu-west-1")
        ssm = session.client("ssm", endpoint_url="https://ssm.eu-west-1.amazonaws.com", **kwargs)
        sts = session.client("sts", endpoint_url="https://sts.eu-west-1.amazonaws.com", **kwargs)
        dynamodb = session.client("dynamodb", endpoint_url="https://dynamodb.eu-west-1.amazonaws.com", **kwargs) if include_dynamodb else None
    except Exception:
        raise EnrollmentClientError() from None
    pair = _bind_pair(ssm, sts, deadline=deadline, monotonic=monotonic, initial_clock=float(now))
    if dynamodb is None:
        return pair
    ddb_pair = _bind_pair(dynamodb, sts, deadline=deadline, monotonic=monotonic, initial_clock=float(now))
    return EnrollmentAwsClients(pair.ssm, pair.account_verifier, dynamodb, ddb_pair.account_verifier)


def _bind_pair(ssm: Any, sts: Any, *, deadline: float,
               monotonic: Callable[[], float], initial_clock: float) -> EnrollmentAwsClients:
    """Internal seam; only the explicit factory creates a trusted pair."""
    lock = threading.Lock()
    used = False
    last_clock = initial_clock

    def check_time() -> bool:
        nonlocal last_clock
        try:
            now = monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or not last_clock <= now < deadline:
                return False
            last_clock = float(now)
            return True
        except Exception:
            return False

    def verify(client: Any, account: str) -> bool:
        nonlocal used
        with lock:
            if used or client is not ssm or type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None:
                return False
            used = True
            if not check_time():
                return False
            try:
                response = sts.get_caller_identity()
            except Exception:
                return False
            if not check_time() or not isinstance(response, Mapping):
                return False
            metadata = response.get("ResponseMetadata")
            arn = response.get("Arn")
            return (isinstance(metadata, Mapping)
                    and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200
                    and response.get("Account") == account
                    and type(response.get("UserId")) is str and bool(response["UserId"])
                    and type(arn) is str
                    and re.fullmatch(r"arn:aws:(?:iam|sts)::" + re.escape(account) + r":[A-Za-z0-9_+=,.@:/-]+", arn) is not None
                    and not arn.endswith(":root"))

    return EnrollmentAwsClients(ssm=ssm, account_verifier=verify)


__all__ = ["EnrollmentAwsClients", "EnrollmentClientError", "create_enrollment_clients"]
