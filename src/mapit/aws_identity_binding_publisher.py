"""Injected create-only SSM adapter for the opt-in enrollment coordinator.

No SDK, credentials, environment lookup, retry, or default client is constructed.
The coordinator must durably reserve its prepared intent before using this
adapter. A receipt is emitted only after an exact decrypted readback in memory.
This module is preparation, not authorization to publish any real session.
"""
from __future__ import annotations

import hmac
import math
import re
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable

from .durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from .identity_binding import SecretPublicationReceipt
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority


class IdentityPublicationError(ValueError):
    def __init__(self, category: str):
        allowed = {"publication_configuration_invalid", "publication_unauthorized",
                   "publication_request_invalid", "publication_already_used",
                   "publication_deadline_invalid", "publication_deadline_expired",
                   "publication_clock_invalid", "publication_write_failed",
                   "publication_ack_invalid", "publication_readback_failed",
                   "publication_readback_invalid"}
        self.category = category if type(category) is str and category in allowed else "publication_write_failed"
        super().__init__(self.category)


class AwsIdentityBindingPublisher:
    """One PUT and one GET, with caller/grant/deadline checks around each.

    The injected client must have bounded timeouts and total_max_attempts=1.
    An ambiguous write or failed readback consumes this instance. Never replay
    the coordinator's prepared row; no compensating deletion is performed.
    """

    def __init__(self, client: Any, *, authority: InvitedTenantAuthority,
                 grant: AuthenticatedTenant, durable_guard: DurableTenantGuard,
                 snapshot: DurableTenantSnapshot, environment: str,
                 account_id: str, account_verifier: Callable[[Any, str], bool], deadline: float,
                 monotonic: Callable[[], float] = time.monotonic):
        try:
            if (type(authority) is not InvitedTenantAuthority
                or type(durable_guard) is not DurableTenantGuard
                or not durable_guard.is_bound_to(authority)
                or not authority.matches_environment(environment)
                or type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or not callable(monotonic) or not callable(account_verifier)):
                raise ValueError
            meta = client.meta
            config = meta.config
            if (meta.service_model.service_name != "ssm"
                or meta.region_name != "eu-west-1"
                or meta.endpoint_url != "https://ssm.eu-west-1.amazonaws.com"
                or not isinstance(config.retries, Mapping)
                or config.retries.get("total_max_attempts") != 1
                or type(config.retries.get("total_max_attempts")) is not int
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       or not 0 < value <= 3 for value in (config.connect_timeout, config.read_timeout))
                or not callable(client.put_parameter) or not callable(client.get_parameter)):
                raise ValueError
        except Exception:
            raise IdentityPublicationError("publication_configuration_invalid") from None
        self._client, self._authority, self._grant = client, authority, grant
        self._account_id, self._account_verifier = account_id, account_verifier
        self._guard, self._snapshot = durable_guard, snapshot
        self._clock, self._last_clock = monotonic, None
        if type(deadline) not in (int, float) or not math.isfinite(deadline):
            raise IdentityPublicationError("publication_deadline_invalid")
        self._deadline = float(deadline)
        self._check()
        if self._deadline - self._last_clock > 14:
            raise IdentityPublicationError("publication_deadline_invalid")
        self._path = f"/honda-mapit-mcp/{environment}/tenants/{grant.key}/mapit-refresh-token"
        self._arn = f"arn:aws:ssm:eu-west-1:{account_id}:parameter{self._path}"
        self._lock, self._attempted = threading.Lock(), False

    def __repr__(self) -> str:
        return "AwsIdentityBindingPublisher(<redacted>)"

    def _check(self) -> None:
        try:
            now = self._clock()
            if (type(now) not in (int, float) or not math.isfinite(now) or now < 0
                or (self._last_clock is not None and now < self._last_clock)):
                raise ValueError
        except Exception:
            raise IdentityPublicationError("publication_clock_invalid") from None
        self._last_clock = float(now)
        if now >= self._deadline:
            raise IdentityPublicationError("publication_deadline_expired")
        try:
            self._authority.validate(self._grant)
            self._guard.check(self._grant, self._snapshot)
        except Exception:
            raise IdentityPublicationError("publication_unauthorized") from None

    def publish(self, *, path: str, version: int, refresh_token: str,
                create_only: bool) -> SecretPublicationReceipt:
        self._check()
        try:
            valid = (type(path) is str and path == self._path
                     and type(version) is int and version == 1 and create_only is True
                     and type(refresh_token) is str and bool(refresh_token)
                     and len(refresh_token.encode("utf-8", errors="strict")) <= 4096
                     and all(ord(char) >= 32 for char in refresh_token))
        except Exception:
            valid = False
        if not valid:
            raise IdentityPublicationError("publication_request_invalid")
        with self._lock:
            if self._attempted:
                raise IdentityPublicationError("publication_already_used")
            self._attempted = True
        self._check()
        # Explicit trusted operator seam: verify fresh STS identity using the
        # SAME credential/client configuration. A syntactically valid account
        # or a later ARN readback is not permission to write to another account.
        # No default STS/session or historical receipt is constructed here.
        try:
            account_verified = self._account_verifier(self._client, self._account_id) is True
        except Exception:
            account_verified = False
        self._check()
        if not account_verified:
            raise IdentityPublicationError("publication_unauthorized")
        try:
            response = self._client.put_parameter(
                Name=self._path, Value=refresh_token, Type="SecureString",
                Tier="Standard", KeyId="alias/aws/ssm", DataType="text", Overwrite=False,
            )
        except Exception:
            raise IdentityPublicationError("publication_write_failed") from None
        self._check()
        if (not _http_ok(response) or type(response.get("Version")) is not int
            or response.get("Version") != 1 or response.get("Tier") not in (None, "Standard")):
            raise IdentityPublicationError("publication_ack_invalid")
        self._check()
        try:
            readback = self._client.get_parameter(Name=self._path + ":1", WithDecryption=True)
        except Exception:
            raise IdentityPublicationError("publication_readback_failed") from None
        self._check()
        parameter = readback.get("Parameter") if isinstance(readback, Mapping) else None
        if (not _http_ok(readback) or not isinstance(parameter, Mapping)
            or parameter.get("Name") != self._path or parameter.get("ARN") != self._arn
            or parameter.get("Type") != "SecureString" or parameter.get("DataType") != "text"
            or type(parameter.get("Version")) is not int or parameter.get("Version") != 1
            or ("Selector" in parameter and parameter["Selector"] != ":1")
            or "SourceResult" in parameter or type(parameter.get("Value")) is not str):
            raise IdentityPublicationError("publication_readback_invalid")
        try:
            matches = hmac.compare_digest(parameter["Value"].encode("utf-8"), refresh_token.encode("utf-8"))
        except Exception:
            matches = False
        if not matches:
            raise IdentityPublicationError("publication_readback_invalid")
        self._check()
        return SecretPublicationReceipt(path=self._path, version=1, created=True)


def _http_ok(response: Any) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


__all__ = ["AwsIdentityBindingPublisher", "IdentityPublicationError"]
