"""Injected private S3 journal with optimistic CAS, never automatic retries.

The caller must verify private bucket ownership and supply a single-attempt
client. The local lock is not a distributed lock: conditional S3 writes are the
cross-runner fence. This module neither creates clients nor changes retention.
"""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import json
import re
import threading
from collections.abc import Iterator, Mapping
from typing import Any

from scripts.build_aws_dev_runtime_template import _validate_bucket_name

MAX_BYTES = 64 * 1024
_FIELDS = frozenset({
    "schema", "kind", "upgrade_id", "account_id", "stack_arn", "prod_run_id",
    "api_id", "function_name", "shutdown_state_machine_arn", "bucket",
    "old_zip_sha256", "old_manifest_sha256", "new_zip_sha256", "new_manifest_sha256",
    "authorization_cutoff_epoch", "authorization_start_epoch", "old_template_sha256",
    "new_template_sha256", "preflight_verified", "delivery_binding", "tripwire_fingerprint",
    "original_api_enabled", "original_function_unreserved", "preflight_time_epoch",
    "close_intent", "close_acknowledged", "close_verified", "update_intent",
    "update_acknowledged", "update_verified", "concurrency_restore_intent",
    "concurrency_restore_acknowledged", "api_open_intent", "api_open_acknowledged",
    "production_open_verified",
})
_NESTED = {
    "delivery_binding": {"source_sha", "service_role_arn", "initial_service_role_attachment"},
    "close_intent": {"execution_name", "execution_arn"},
    "update_intent": {"client_request_token"},
}
_FLAGS = frozenset({"preflight_verified", "original_api_enabled", "original_function_unreserved",
    "close_acknowledged", "close_verified", "update_acknowledged", "update_verified",
    "concurrency_restore_intent", "concurrency_restore_acknowledged", "api_open_intent",
    "api_open_acknowledged", "production_open_verified"})
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class DeliveryJournalError(ValueError):
    """Fixed category only; no response, private path or provider text."""


def _bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False,
                      ensure_ascii=True).encode("ascii")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryJournalError("journal_invalid")
        result[key] = value
    return result


def _status(reply: Any) -> bool:
    return (isinstance(reply, Mapping) and isinstance(reply.get("ResponseMetadata"), Mapping)
            and type(reply["ResponseMetadata"].get("HTTPStatusCode")) is int
            and reply["ResponseMetadata"]["HTTPStatusCode"] == 200)


def _etag(value: Any) -> str:
    if type(value) is not str or re.fullmatch(r'"[a-zA-Z0-9-]{1,128}"', value) is None:
        raise DeliveryJournalError("journal_response_invalid")
    return value


class S3DeliveryJournal:
    def __init__(self, client: Any, *, bucket: str, account_id: str,
                 run_id: str, source_sha: str) -> None:
        try:
            _validate_bucket_name(bucket)
        except Exception:
            raise DeliveryJournalError("journal_inputs_invalid") from None
        if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
                or account_id == "0" * 12
                or type(run_id) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is None
                or type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
                or source_sha == "0" * 40
                or any(not callable(getattr(client, name, None)) for name in ("get_object", "put_object"))):
            raise DeliveryJournalError("journal_inputs_invalid")
        self.client, self.bucket, self.account_id = client, bucket, account_id
        self.run_id, self.source_sha = run_id, source_sha
        self.key = f"journals/{run_id}.json"
        self._lock = threading.RLock()
        self._locked = False
        self._loaded = False
        self._blocked = False
        self._revision = 0
        self._etag: str | None = None
        self._digest: str | None = None
        self._prior_state: dict[str, Any] | None = None

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        with self._lock:
            if self._locked:
                raise DeliveryJournalError("journal_lock_invalid")
            self._locked = True
            self._loaded = False
            try:
                yield
            finally:
                self._locked = False

    def _state_valid(self, state: Any) -> bool:
        if (type(state) is not dict or not set(state) <= _FIELDS
                or state.get("schema") != 1 or type(state.get("schema")) is not int
                or state.get("kind") != "prod_cd_delivery"
                or state.get("account_id") != self.account_id or state.get("bucket") != self.bucket
                or type(state.get("delivery_binding")) is not dict
                or state["delivery_binding"].get("source_sha") != self.source_sha):
            return False
        for key, value in state.items():
            if key in _NESTED:
                if type(value) is not dict or set(value) != _NESTED[key]:
                    return False
                if key == "delivery_binding":
                    if (type(value["source_sha"]) is not str
                            or re.fullmatch(r"[0-9a-f]{40}", value["source_sha"]) is None
                            or value["source_sha"] != self.source_sha
                            or type(value["service_role_arn"]) is not str
                            or value["service_role_arn"] != (
                                f"arn:aws:iam::{self.account_id}:role/honda-mapit-mcp-prod-cfn-update")
                            or type(value["initial_service_role_attachment"]) is not bool):
                        return False
                elif any(type(v) is not str or not v or len(v) > 1024 for v in value.values()):
                    return False
                if key == "close_intent" and (re.fullmatch(_UUID, value["execution_name"]) is None
                        or value["execution_arn"] != (f"arn:aws:states:eu-west-1:{self.account_id}:"
                        f"execution:honda-mapit-mcp-prod-shutdown:{value['execution_name']}")):
                    return False
                if key == "update_intent" and re.fullmatch(_UUID, value["client_request_token"]) is None:
                    return False
            elif key in _FLAGS:
                if type(value) is not bool:
                    return False
            elif key.endswith("_sha256") or key == "tripwire_fingerprint":
                if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                    return False
            elif key in {"upgrade_id", "prod_run_id"}:
                if type(value) is not str or re.fullmatch(_UUID, value) is None:
                    return False
            elif key == "stack_arn":
                if type(value) is not str or re.fullmatch(
                        rf"arn:aws:cloudformation:eu-west-1:{self.account_id}:stack/honda-mapit-mcp-prod/{_UUID}", value) is None:
                    return False
            elif key == "shutdown_state_machine_arn":
                if value != f"arn:aws:states:eu-west-1:{self.account_id}:stateMachine:honda-mapit-mcp-prod-shutdown":
                    return False
            elif key == "function_name":
                if value != "honda-mapit-mcp-prod-handler":
                    return False
            elif key == "api_id":
                if type(value) is not str or re.fullmatch(r"[a-z0-9]{10}", value) is None:
                    return False
            elif key in {"authorization_cutoff_epoch", "authorization_start_epoch", "preflight_time_epoch"}:
                if type(value) is not int or not 1 <= value <= 253402300799:
                    return False
            elif type(value) not in (str, int, bool) or (type(value) is str and len(value) > 1024):
                return False
        return True

    def load(self) -> dict[str, Any] | None:
        if not self._locked:
            raise DeliveryJournalError("journal_lock_invalid")
        try:
            reply = self.client.get_object(Bucket=self.bucket, Key=self.key,
                                          ExpectedBucketOwner=self.account_id, ChecksumMode="ENABLED")
        except Exception as exc:
            response = getattr(exc, "response", None)
            if (isinstance(response, Mapping) and isinstance(response.get("Error"), Mapping)
                    and isinstance(response.get("ResponseMetadata"), Mapping)
                    and response["Error"].get("Code") == "NoSuchKey"
                    and type(response["ResponseMetadata"].get("HTTPStatusCode")) is int
                    and response["ResponseMetadata"]["HTTPStatusCode"] == 404):
                self._revision, self._etag, self._digest = 0, None, None
                self._prior_state = None
                self._loaded = True
                return None
            raise DeliveryJournalError("journal_read_failed") from None
        stream = reply.get("Body") if isinstance(reply, Mapping) else None
        try:
            if (not _status(reply) or reply.get("ServerSideEncryption") != "AES256"
                    or type(reply.get("ContentLength")) is not int
                    or not 1 <= reply["ContentLength"] <= MAX_BYTES
                    or not callable(getattr(stream, "read", None))):
                raise DeliveryJournalError("journal_response_invalid")
            raw = stream.read(MAX_BYTES + 1)
            if type(raw) is not bytes or len(raw) != reply["ContentLength"]:
                raise DeliveryJournalError("journal_response_invalid")
            digest = hashlib.sha256(raw).digest()
            if reply.get("ChecksumSHA256") != base64.b64encode(digest).decode("ascii"):
                raise DeliveryJournalError("journal_response_invalid")
            envelope = json.loads(raw, object_pairs_hook=_pairs)
            if (type(envelope) is not dict
                    or set(envelope) != {"schema", "run_id", "source_sha", "revision", "previous_sha256", "state"}
                    or type(envelope["schema"]) is not int or envelope["schema"] != 1
                    or envelope["run_id"] != self.run_id or envelope["source_sha"] != self.source_sha
                    or type(envelope["revision"]) is not int or not 1 <= envelope["revision"] <= 128
                    or not self._state_valid(envelope["state"])
                    or (envelope["revision"] == 1 and envelope["previous_sha256"] is not None)
                    or (envelope["revision"] > 1 and (type(envelope["previous_sha256"]) is not str
                        or re.fullmatch(r"[0-9a-f]{64}", envelope["previous_sha256"]) is None))):
                raise DeliveryJournalError("journal_invalid")
            self._etag = _etag(reply.get("ETag"))
            self._revision, self._digest = envelope["revision"], digest.hex()
            self._loaded = True
            self._prior_state = copy.deepcopy(envelope["state"])
            return copy.deepcopy(envelope["state"])
        except DeliveryJournalError:
            raise
        except Exception:
            raise DeliveryJournalError("journal_invalid") from None
        finally:
            if callable(getattr(stream, "close", None)):
                try:
                    stream.close()
                except Exception:
                    raise DeliveryJournalError("journal_read_failed") from None

    def save(self, state: dict[str, Any]) -> None:
        if not self._locked or not self._loaded or self._blocked:
            raise DeliveryJournalError("journal_write_blocked")
        if not self._state_valid(state) or self._revision >= 128:
            raise DeliveryJournalError("journal_invalid")
        # Intents and binding facts are append-only. An already true receipt
        # cannot be cleared, and an intent cannot be erased to permit replay.
        for key, previous in (self._prior_state or {}).items():
            if key not in state:
                raise DeliveryJournalError("journal_invalid")
            current = state[key]
            if current != previous and not (key in _FLAGS and previous is False and current is True):
                raise DeliveryJournalError("journal_invalid")
        envelope = {"schema": 1, "run_id": self.run_id, "source_sha": self.source_sha,
                    "revision": self._revision + 1, "previous_sha256": self._digest, "state": state}
        try:
            body = _bytes(envelope)
        except Exception:
            raise DeliveryJournalError("journal_invalid") from None
        if len(body) > MAX_BYTES:
            raise DeliveryJournalError("journal_invalid")
        digest = hashlib.sha256(body).digest()
        checksum = base64.b64encode(digest).decode("ascii")
        condition = {"IfMatch": self._etag} if self._etag is not None else {"IfNoneMatch": "*"}
        # Any uncertain write permanently fences this instance. A new reader
        # may reconcile state, but must not retry this write or cloud action.
        self._blocked = True
        try:
            reply = self.client.put_object(Bucket=self.bucket, Key=self.key, Body=body,
                ExpectedBucketOwner=self.account_id, ServerSideEncryption="AES256",
                ContentType="application/json", ChecksumSHA256=checksum, **condition)
            if not _status(reply) or reply.get("ChecksumSHA256") != checksum:
                raise DeliveryJournalError("journal_write_ambiguous")
            written_etag = _etag(reply.get("ETag"))
            observed = self.load()
            if (observed != state or self._etag != written_etag
                    or self._digest != digest.hex() or self._revision != envelope["revision"]):
                raise DeliveryJournalError("journal_write_ambiguous")
            self._blocked = False
        except Exception:
            raise DeliveryJournalError("journal_write_ambiguous") from None
