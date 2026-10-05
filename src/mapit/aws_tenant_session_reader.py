"""Read one invited tenant's pinned SecureString version through an injected client.

No SDK/session, environment, credential store, fallback path, or persistence is
constructed here. A fresh reader should be used for each authorized invocation.
The injected client must be configured for one attempt with bounded wire
timeouts by its caller.
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable

from .aws_session_reader import AwsSessionReadResult, AwsSessionReader, AwsSessionReaderError
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority, TenantIsolationError

_REGION = "eu-west-1"
_BASE_PATH = "/honda-mapit-mcp/prod/mapit-refresh-token"
_TENANT_KEY = re.compile(r"^tenant-[0-9a-f]{64}$")


class AwsTenantSessionReaderError(RuntimeError):
    """Closed safe category; never includes grant, path, value, or SDK text."""

    def __init__(self, category: str):
        allowed = {
            "tenant_reader_configuration_invalid",
            "tenant_reader_already_used",
            "tenant_reader_grant_invalid",
            "tenant_reader_parameter_read_failed",
            "tenant_reader_parameter_invalid",
            "tenant_reader_deadline_invalid",
            "tenant_reader_deadline_expired",
            "tenant_reader_clock_invalid",
            "tenant_reader_clock_rollback",
            "tenant_reader_value_invalid",
            "tenant_reader_value_too_large",
        }
        self.category = category if category in allowed else "tenant_reader_parameter_read_failed"
        super().__init__(self.category)


class _TenantPathClient:
    """Narrow request/response namespace bridge into the established reader."""

    def __init__(self, client: Any, authority: InvitedTenantAuthority, grant: AuthenticatedTenant, account_id: str, tenant_path: str, version: int):
        self._client = client
        self._authority = authority
        self._grant = grant
        self._account_id = account_id
        self._tenant_path = tenant_path
        self._version = version
        self._tenant_arn = f"arn:aws:ssm:{_REGION}:{account_id}:parameter{tenant_path}"
        self._base_arn = f"arn:aws:ssm:{_REGION}:{account_id}:parameter{_BASE_PATH}"

    def __repr__(self) -> str:
        return "_TenantPathClient(<redacted>)"

    def get_parameter(self, *, Name: str, WithDecryption: bool) -> Mapping[str, Any]:
        if Name != f"{_BASE_PATH}:{self._version}" or WithDecryption is not True:
            raise AwsSessionReaderError("parameter_invalid")
        getter = getattr(self._client, "get_parameter", None)
        if not callable(getter):
            raise AwsSessionReaderError("invalid_configuration")
        try:
            self._authority.validate(self._grant)
        except TenantIsolationError:
            raise AwsSessionReaderError("invalid_configuration") from None
        response = getter(Name=f"{self._tenant_path}:{self._version}", WithDecryption=True)
        if not isinstance(response, Mapping):
            raise AwsSessionReaderError("parameter_invalid")
        metadata = response.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata.get("HTTPStatusCode") != 200:
            raise AwsSessionReaderError("parameter_invalid")
        parameter = response.get("Parameter")
        if not isinstance(parameter, Mapping):
            raise AwsSessionReaderError("parameter_invalid")
        if parameter.get("Name") != self._tenant_path or parameter.get("ARN") != self._tenant_arn:
            raise AwsSessionReaderError("parameter_invalid")
        copied = dict(parameter)
        copied["Name"] = _BASE_PATH
        copied["ARN"] = self._base_arn
        normalized = dict(response)
        normalized["Parameter"] = copied
        return normalized


class AwsTenantSessionReader:
    """Delegating tenant-scoped reader with fresh grant checks around one read."""

    def __init__(
        self,
        authority: InvitedTenantAuthority,
        grant: AuthenticatedTenant,
        client: Any,
        *,
        account_id: str,
        version: int,
        tier: str,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            type(authority) is not InvitedTenantAuthority
            or type(account_id) is not str
            or type(version) is not int
            or type(tier) is not str
            or not callable(monotonic)
        ):
            raise AwsTenantSessionReaderError("tenant_reader_configuration_invalid")
        try:
            authority.validate(grant)
        except TenantIsolationError:
            raise AwsTenantSessionReaderError("tenant_reader_grant_invalid") from None
        if type(grant.key) is not str or not _TENANT_KEY.fullmatch(grant.key):
            raise AwsTenantSessionReaderError("tenant_reader_grant_invalid")
        tenant_path = f"/honda-mapit-mcp/prod/tenants/{grant.key}/mapit-refresh-token"
        bridge = _TenantPathClient(client, authority, grant, account_id, tenant_path, version)
        try:
            reader = AwsSessionReader(
                bridge,
                account_id=account_id,
                version=version,
                tier=tier,
                monotonic=monotonic,
            )
        except AwsSessionReaderError:
            raise AwsTenantSessionReaderError("tenant_reader_configuration_invalid") from None
        self._authority = authority
        self._grant = grant
        self._bridge = bridge
        self._reader = reader
        self._attempt_lock = threading.Lock()
        self._read_attempted = False

    def __repr__(self) -> str:
        return "AwsTenantSessionReader(<redacted>)"

    def read_refresh_token(self, *, deadline: float) -> AwsSessionReadResult:
        """Read exactly the tenant-key namespace and revalidate grant before return."""
        self._validate_grant()
        with self._attempt_lock:
            if self._read_attempted:
                raise AwsTenantSessionReaderError("tenant_reader_already_used")
            self._read_attempted = True
        try:
            result = self._reader.read_refresh_token(deadline=deadline)
        except AwsSessionReaderError as exc:
            categories = {
                "invalid_configuration": "tenant_reader_configuration_invalid",
                "deadline_invalid": "tenant_reader_deadline_invalid",
                "deadline_expired": "tenant_reader_deadline_expired",
                "clock_invalid": "tenant_reader_clock_invalid",
                "clock_rollback": "tenant_reader_clock_rollback",
                "parameter_read_failed": "tenant_reader_parameter_read_failed",
                "response_invalid": "tenant_reader_parameter_invalid",
                "parameter_invalid": "tenant_reader_parameter_invalid",
                "value_invalid": "tenant_reader_value_invalid",
                "value_too_large": "tenant_reader_value_too_large",
            }
            raise AwsTenantSessionReaderError(categories.get(exc.category, "tenant_reader_parameter_read_failed")) from None
        self._validate_grant()
        return result

    def _validate_grant(self) -> None:
        try:
            self._authority.validate(self._grant)
        except TenantIsolationError:
            raise AwsTenantSessionReaderError("tenant_reader_grant_invalid") from None


__all__ = ["AwsTenantSessionReader", "AwsTenantSessionReaderError"]
