"""Injected, read-only Parameter Store reader for one pinned prod token version.

This module constructs no AWS client/session and reads no environment,
credential store, cache, or filesystem state. Callers remain responsible for
single-attempt SDK configuration and wire-level connect/read timeouts.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable

_REGION = "eu-west-1"
_PATH = "/honda-mapit-mcp/prod/mapit-refresh-token"
_DEADLINE_CAP_SECONDS = 5.0
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_TIERS = {"Standard": 4096, "Advanced": 8192}
_ERRORS = frozenset({
    "invalid_configuration",
    "deadline_invalid",
    "deadline_expired",
    "clock_invalid",
    "clock_rollback",
    "parameter_read_failed",
    "response_invalid",
    "parameter_invalid",
    "value_invalid",
    "value_too_large",
})


class AwsSessionReaderError(RuntimeError):
    """Closed-category error; never includes the provider exception or value."""

    def __init__(self, category: str):
        self.category = category if category in _ERRORS else "parameter_read_failed"
        super().__init__(self.category)


@dataclass(frozen=True)
class AwsSessionReadResult:
    """Successful value is available to the trusted caller, never in repr."""

    success: bool
    category: str
    parameter_version: int
    tier_policy: str
    refresh_token: str = field(repr=False, compare=False)

    def safe_projection(self) -> dict[str, Any]:
        return {
            "success": self.success is True,
            "category": "session_read_verified" if self.success is True else "parameter_read_failed",
            "parameter_version": self.parameter_version if type(self.parameter_version) is int else 0,
            "tier_policy": self.tier_policy if self.tier_policy in _TIERS else "unknown",
        }


class AwsSessionReader:
    """Read one explicitly selected SecureString version through an injected client."""

    def __init__(
        self,
        client: Any,
        *,
        account_id: str,
        version: int,
        tier: str,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        # Validate all operator-selected identity/budget policy before touching
        # the client or its methods.
        if (
            type(account_id) is not str
            or not _ACCOUNT_RE.fullmatch(account_id)
            or account_id == "000000000000"
            or type(version) is not int
            or version <= 0
            or type(tier) is not str
            or tier not in _TIERS
            or not callable(monotonic)
        ):
            raise AwsSessionReaderError("invalid_configuration")
        self._client = client
        self._account_id = account_id
        self._version = version
        self._tier = tier
        self._monotonic = monotonic

    def read_refresh_token(self, *, deadline: float) -> AwsSessionReadResult:
        """Read one version, bounded by caller deadline and a local 5s ceiling.

        This is a cooperative deadline: the injected SDK client's wire timeout
        must separately bound an in-flight request.
        """
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or (isinstance(deadline, float) and not math.isfinite(deadline))
            or deadline <= 0
        ):
            raise AwsSessionReaderError("deadline_invalid")

        try:
            start = self._clock_value()
        except AwsSessionReaderError:
            raise
        effective_deadline = min(deadline, start + _DEADLINE_CAP_SECONDS)
        last_clock = start

        def check_deadline() -> None:
            nonlocal last_clock
            current = self._clock_value()
            if current < last_clock:
                raise AwsSessionReaderError("clock_rollback")
            last_clock = current
            if current >= effective_deadline:
                raise AwsSessionReaderError("deadline_expired")

        # Check expiration before resolving/calling the SDK method so an
        # expired window consumes no external attempt.
        check_deadline()
        try:
            getter = getattr(self._client, "get_parameter")
        except Exception:
            raise AwsSessionReaderError("invalid_configuration") from None
        if not callable(getter):
            raise AwsSessionReaderError("invalid_configuration")
        check_deadline()
        try:
            response = getter(
                Name=f"{_PATH}:{self._version}",
                WithDecryption=True,
            )
        except Exception:
            try:
                check_deadline()
            except AwsSessionReaderError as deadline_error:
                raise deadline_error from None
            raise AwsSessionReaderError("parameter_read_failed") from None
        check_deadline()

        if not isinstance(response, Mapping):
            raise AwsSessionReaderError("response_invalid")
        metadata = response.get("ResponseMetadata")
        status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
        if type(status) is not int or status != 200:
            raise AwsSessionReaderError("response_invalid")
        parameter = response.get("Parameter")
        if not isinstance(parameter, Mapping):
            raise AwsSessionReaderError("parameter_invalid")

        expected_arn = f"arn:aws:ssm:{_REGION}:{self._account_id}:parameter{_PATH}"
        selector = parameter.get("Selector")
        if (
            parameter.get("Name") != _PATH
            or parameter.get("ARN") != expected_arn
            or parameter.get("Type") != "SecureString"
            or type(parameter.get("Version")) is not int
            or parameter.get("Version") != self._version
            or parameter.get("DataType") != "text"
            or ("Selector" in parameter and selector != f":{self._version}")
            or "SourceResult" in parameter
        ):
            raise AwsSessionReaderError("parameter_invalid")

        value = parameter.get("Value")
        byte_limit = _TIERS[self._tier]
        if type(value) is not str or not value or len(value) > byte_limit:
            raise AwsSessionReaderError("value_invalid" if type(value) is not str or not value else "value_too_large")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise AwsSessionReaderError("value_invalid") from None
        if len(encoded) > byte_limit:
            raise AwsSessionReaderError("value_too_large")

        # Do not return a successful secret after validation work crosses the
        # deadline; the last clock sample also detects rollback.
        check_deadline()
        return AwsSessionReadResult(
            success=True,
            category="session_read_verified",
            parameter_version=self._version,
            tier_policy=self._tier,
            refresh_token=value,
        )

    def _clock_value(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise AwsSessionReaderError("clock_invalid") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise AwsSessionReaderError("clock_invalid")
        try:
            if not math.isfinite(value):
                raise AwsSessionReaderError("clock_invalid")
            return float(value)
        except OverflowError:
            raise AwsSessionReaderError("clock_invalid") from None


__all__ = ["AwsSessionReadResult", "AwsSessionReader", "AwsSessionReaderError"]
