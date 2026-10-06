"""Injected DynamoDB authorization store; no SDK, credentials or resource creation.

Runtime callers receive only a reader. The separate optional writer is for a
reviewed operator, which must journal writes and reconcile ambiguous outcomes.
The fixed allowlist bounds capacity without scans, deletes or tombstone expiry.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from .durable_tenants import DurableTenantError, DurableTenantRecord, MAX_RECORDS

_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_TABLE = re.compile(r"arn:aws:dynamodb:eu-west-1:[0-9]{12}:table/honda-mapit-mcp-dev-tenants\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,17}\Z")


class DynamoDBTenantStore:
    """Strong reads and single conditional writes on one exact dev table ARN.

Injected low-level clients must use TLS, bounded timeouts and exactly one SDK
attempt. No ambient clients are constructed here. Keys must be pre-authorized
by the operator, not supplied as new invitations by MCP callers.
"""

    def __init__(self, reader: Any, *, table_arn: str,
                 allowed_keys: tuple[str, ...], writer: Any = None):
        if (type(table_arn) is not str or _TABLE.fullmatch(table_arn) is None
            or type(allowed_keys) is not tuple or not 1 <= len(allowed_keys) <= MAX_RECORDS
            or any(type(key) is not str or _KEY.fullmatch(key) is None for key in allowed_keys)
            or len(set(allowed_keys)) != len(allowed_keys)
            or not callable(getattr(reader, "get_item", None))
            or (writer is not None and not callable(getattr(writer, "put_item", None)))):
            raise DurableTenantError("durable_configuration_invalid")
        self._table = table_arn
        self._keys = frozenset(allowed_keys)
        self._reader, self._writer = reader, writer

    def __repr__(self) -> str:
        return "DynamoDBTenantStore(<redacted>)"

    def _key(self, key: str) -> None:
        if type(key) is not str or key not in self._keys:
            raise DurableTenantError("durable_unauthorized")

    @staticmethod
    def _response(response: Any) -> Mapping[str, Any]:
        if not isinstance(response, Mapping):
            raise DurableTenantError("durable_store_failed")
        metadata = response.get("ResponseMetadata")
        if (not isinstance(metadata, Mapping)
            or type(metadata.get("HTTPStatusCode")) is not int
            or metadata["HTTPStatusCode"] != 200):
            raise DurableTenantError("durable_store_failed")
        return response

    def get(self, key: str) -> DurableTenantRecord | None:
        self._key(key)
        try:
            response = self._response(self._reader.get_item(
                TableName=self._table, Key={"key": {"S": key}},
                ConsistentRead=True, ReturnConsumedCapacity="NONE",
            ))
            if set(response) - {"ResponseMetadata", "Item"}:
                raise DurableTenantError("durable_store_failed")
            if "Item" not in response:
                return None
            item = response["Item"]
            if not isinstance(item, Mapping) or set(item) != {"key", "status", "revision"}:
                raise DurableTenantError("durable_store_failed")
            for field, kind in (("key", "S"), ("status", "S"), ("revision", "N")):
                value = item[field]
                if not isinstance(value, Mapping) or set(value) != {kind} or type(value[kind]) is not str:
                    raise DurableTenantError("durable_store_failed")
            number = item["revision"]["N"]
            if _NUMBER.fullmatch(number) is None or item["key"]["S"] != key:
                raise DurableTenantError("durable_store_failed")
            return DurableTenantRecord(key, item["status"]["S"], int(number))
        except Exception:
            raise DurableTenantError("durable_store_failed") from None

    def cas(self, key: str, expected_revision: int | None,
            replacement: DurableTenantRecord) -> bool:
        self._key(key)
        if self._writer is None:
            raise DurableTenantError("durable_configuration_invalid")
        if type(replacement) is not DurableTenantRecord:
            raise DurableTenantError("durable_record_invalid")
        # Recheck at the write boundary rather than trusting a dataclass label.
        DurableTenantRecord(replacement.key, replacement.status, replacement.revision)
        if (type(replacement) is not DurableTenantRecord or replacement.key != key
            or (expected_revision is not None and
                (type(expected_revision) is not int or not 1 <= expected_revision < 10**18))
            or replacement.revision >= 10**18):
            raise DurableTenantError("durable_record_invalid")
        required = 1 if expected_revision is None else expected_revision + 1
        if replacement.revision != required:
            return False
        names = {"#key": "key"}
        values = None
        condition = "attribute_not_exists(#key)"
        if expected_revision is not None:
            # Bind both revision and terminal-state semantics atomically; there
            # is no stale preliminary read or read-modify-write race.
            names = {"#revision": "revision", "#status": "status"}
            values = {":revision": {"N": str(expected_revision)},
                      ":active": {"S": "active"}}
            condition = "#revision = :revision AND #status = :active"
            if replacement.status == "revoked":
                values[":revoked"] = {"S": "revoked"}
                condition = "#revision = :revision AND (#status = :active OR #status = :revoked)"
        request = dict(
            TableName=self._table,
            Item={"key": {"S": key}, "status": {"S": replacement.status},
                  "revision": {"N": str(replacement.revision)}},
            ConditionExpression=condition, ExpressionAttributeNames=names,
            ReturnValues="NONE", ReturnConsumedCapacity="NONE",
        )
        if values is not None:
            request["ExpressionAttributeValues"] = values
        try:
            response = self._response(self._writer.put_item(**request))
            if set(response) != {"ResponseMetadata"}:
                raise DurableTenantError("durable_store_failed")
            return True
        except Exception as exc:
            # Only an explicit service conditional conflict is a known no-write
            # result. All timeouts/other failures remain unknown, never retried.
            error = getattr(exc, "response", None)
            if (isinstance(error, Mapping)
                and isinstance(error.get("Error"), Mapping)
                and error["Error"].get("Code") == "ConditionalCheckFailedException"
                and isinstance(error.get("ResponseMetadata"), Mapping)
                and type(error["ResponseMetadata"].get("HTTPStatusCode")) is int
                and error["ResponseMetadata"]["HTTPStatusCode"] == 400):
                return False
            raise DurableTenantError("durable_store_failed") from None


__all__ = ["DynamoDBTenantStore"]
