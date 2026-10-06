"""SDK-free retained-dev S3 CAS journal.

The caller injects a single-attempt S3 client and a phase-specific state
validator.  This module never constructs credentials, lists, deletes, retries
or changes lifecycle/tag retention.  An uncertain conditional write fences the
instance; a new instance may only perform a fresh read-only reconciliation.
"""

from __future__ import annotations

import base64
import contextlib
import copy
from collections.abc import Iterator, Mapping
import hashlib
import json
import math
import re
import threading
import time
from typing import Any, Callable

from scripts.build_aws_retained_dev_runtime import retained_dev_artifact_bucket

MAX_BYTES = 64 * 1024
MAX_REVISION = 128
MAX_STEP_SECONDS = 30.0
PHASES = frozenset({"preflight", "artifact", "update", "recovery", "recovery-update"})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_ETAG = re.compile(r'"[A-Za-z0-9-]{1,128}"\Z')


class RetainedDevJournalError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise RetainedDevJournalError("journal_invalid") from None


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise RetainedDevJournalError("journal_invalid")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise RetainedDevJournalError("journal_invalid")


def _status(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _etag(value: Any) -> str:
    if type(value) is not str or _ETAG.fullmatch(value) is None:
        raise RetainedDevJournalError("journal_response_invalid")
    return value


def _error(exc: Exception) -> tuple[str, int | None]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (
        error.get("Code", "") if isinstance(error, Mapping) and type(error.get("Code", "")) is str else "",
        metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int else None,
    )


class RetainedDevS3Journal:
    """One phase's bounded CAS journal; all state validation is injected."""

    def __init__(self, client: Any, *, account_id: str, run_id: str, source_sha: str, phase: str, state_validator: Callable[[Any], bool], create_first: bool = False, wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> None:
        if not callable(state_validator) or not isinstance(client, object) or not all(callable(getattr(client, method, None)) for method in ("get_object", "put_object")):
            raise RetainedDevJournalError("journal_inputs_invalid")
        if type(create_first) is not bool:
            raise RetainedDevJournalError("journal_inputs_invalid")
        if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000" or type(run_id) is not str or _UUID.fullmatch(run_id) is None or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40 or phase not in PHASES:
            raise RetainedDevJournalError("journal_inputs_invalid")
        if not callable(wall_clock) or not callable(monotonic):
            raise RetainedDevJournalError("journal_inputs_invalid")
        self.client, self.account_id, self.run_id, self.source_sha, self.phase, self.create_first = client, account_id, run_id, source_sha, phase, create_first
        self.bucket = retained_dev_artifact_bucket(account_id)
        self.key = f"journals/{run_id}/{phase}.json"
        self.state_validator, self.wall_clock, self.monotonic = state_validator, wall_clock, monotonic
        self._lock = threading.Lock(); self._locked = False; self._loaded = False; self._blocked = False
        self._create_first_used = False
        self._revision = 0; self._etag: str | None = None; self._digest: str | None = None; self._state: dict[str, Any] | None = None
        self._started = 0.0; self._last_mono = 0.0; self._last_wall = 0.0

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            raise RetainedDevJournalError("journal_lock_invalid")
        if self._locked:
            self._lock.release()
            raise RetainedDevJournalError("journal_lock_invalid")
        self._locked = True
        self._loaded = False
        try:
            self._started = self._last_mono = self._clock(self.monotonic)
            self._last_wall = 0.0
            self._guard()
            yield
        finally:
            self._locked = False
            self._lock.release()

    def _clock(self, clock: Callable[[], float]) -> float:
        value = clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            raise RetainedDevJournalError("window_invalid")
        return float(value)

    def _guard(self) -> None:
        wall, mono = self._clock(self.wall_clock), self._clock(self.monotonic)
        if wall < self._last_wall or mono < self._last_mono or mono - self._started >= MAX_STEP_SECONDS:
            raise RetainedDevJournalError("window_expired")
        self._last_wall, self._last_mono = wall, mono

    def _envelope(self, state: Mapping[str, Any], revision: int, previous_sha256: str | None) -> dict[str, Any]:
        if self.phase == "preflight":
            return {"schema": 1, "kind": "retained-dev-journal", "account_id": self.account_id, "source_sha": self.source_sha, "run_id": self.run_id, "phase": self.phase, "version": revision, "previous_sha256": previous_sha256, "state": state}
        return {"schema": 1, "kind": "retained-dev-journal", "account_id": self.account_id, "source_sha": self.source_sha, "run_id": self.run_id, "phase": self.phase, "revision": revision, "previous_sha256": previous_sha256, "state": state}

    def _read_remote(self) -> dict[str, Any] | None:
        self._guard()
        try:
            reply = self.client.get_object(Bucket=self.bucket, Key=self.key, ExpectedBucketOwner=self.account_id, ChecksumMode="ENABLED")
        except Exception as exc:
            self._guard()
            code, status = _error(exc)
            if code == "NoSuchKey" and status == 404:
                self._revision, self._etag, self._digest, self._state = 0, None, None, None
                self._loaded = True
                return None
            raise RetainedDevJournalError("journal_read_failed") from None
        stream = reply.get("Body") if isinstance(reply, Mapping) else None
        try:
            if not _status(reply) or reply.get("ServerSideEncryption") != "AES256" or reply.get("ContentType") != "application/json" or type(reply.get("ContentLength")) is not int or not 1 <= reply["ContentLength"] <= MAX_BYTES or not callable(getattr(stream, "read", None)):
                raise RetainedDevJournalError("journal_response_invalid")
            self._guard(); raw = stream.read(MAX_BYTES + 1); self._guard()
            if type(raw) is not bytes or len(raw) != reply["ContentLength"] or reply.get("ChecksumSHA256") != base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii"):
                raise RetainedDevJournalError("journal_response_invalid")
            envelope = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                                  parse_constant=_reject_constant)
            expected_counter = "version" if self.phase == "preflight" else "revision"
            if type(envelope) is not dict or set(envelope) != {"schema", "kind", "account_id", "source_sha", "run_id", "phase", expected_counter, "previous_sha256", "state"} or envelope.get("schema") != 1 or envelope.get("kind") != "retained-dev-journal" or envelope.get("account_id") != self.account_id or envelope.get("source_sha") != self.source_sha or envelope.get("run_id") != self.run_id or envelope.get("phase") != self.phase:
                raise RetainedDevJournalError("journal_invalid")
            revision = envelope.get(expected_counter)
            if type(revision) is not int or not 1 <= revision <= MAX_REVISION or (revision == 1 and envelope.get("previous_sha256") is not None) or (revision > 1 and (type(envelope.get("previous_sha256")) is not str or _SHA256.fullmatch(envelope["previous_sha256"]) is None)):
                raise RetainedDevJournalError("journal_invalid")
            if self.state_validator(envelope.get("state")) is not True:
                raise RetainedDevJournalError("journal_state_invalid")
            self._etag = _etag(reply.get("ETag")); self._revision = revision; self._digest = hashlib.sha256(raw).hexdigest(); self._state = copy.deepcopy(envelope["state"]); self._loaded = True
            return copy.deepcopy(self._state)
        except RetainedDevJournalError:
            raise
        except Exception:
            raise RetainedDevJournalError("journal_invalid") from None
        finally:
            if callable(getattr(stream, "close", None)):
                try:
                    self._guard(); stream.close(); self._guard()
                except RetainedDevJournalError:
                    raise
                except Exception:
                    raise RetainedDevJournalError("journal_read_failed") from None

    def load(self) -> dict[str, Any] | None:
        if not self._locked:
            raise RetainedDevJournalError("journal_lock_invalid")
        if self.create_first and self._create_first_used and self._loaded and self._revision == 0 and self._etag is None and self._state is None:
            # Do not turn a repeated pre-CAS load into an existence probe.
            return None
        if self.create_first and not self._create_first_used and not self._loaded:
            # Explicit new-run mode deliberately does not ask S3 whether the
            # key exists.  The first CAS below is the atomic ownership test.
            self._revision, self._etag, self._digest, self._state = 0, None, None, None
            self._loaded = True
            self._create_first_used = True
            return None
        return self._read_remote()

    def compare_and_set(self, expected_revision: int | None, state: Mapping[str, Any]) -> bool:
        if not self._locked or not self._loaded or self._blocked:
            raise RetainedDevJournalError("journal_write_blocked")
        if expected_revision != (None if self._revision == 0 else self._revision) or self.state_validator(state) is not True:
            return False
        if self._revision >= MAX_REVISION:
            raise RetainedDevJournalError("journal_invalid")
        candidate = copy.deepcopy(dict(state)); next_revision = self._revision + 1
        body = _canonical(self._envelope(candidate, next_revision, self._digest));
        if len(body) > MAX_BYTES:
            raise RetainedDevJournalError("journal_invalid")
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        condition = {"IfNoneMatch": "*"} if self._etag is None else {"IfMatch": self._etag}
        self._blocked = True
        try:
            self._guard()
            reply = self.client.put_object(Bucket=self.bucket, Key=self.key, Body=body, ExpectedBucketOwner=self.account_id, ServerSideEncryption="AES256", ContentType="application/json", ChecksumSHA256=checksum, **condition)
            self._guard()
            if not _status(reply) or reply.get("ChecksumSHA256") != checksum:
                raise RetainedDevJournalError("journal_write_ambiguous")
            written_etag = _etag(reply.get("ETag"))
            observed = self._read_remote()
            if observed != candidate or self._revision != next_revision or self._etag != written_etag:
                raise RetainedDevJournalError("journal_write_ambiguous")
            self._blocked = False
            return True
        except RetainedDevJournalError:
            raise
        except Exception as exc:
            code, status = _error(exc)
            if code == "PreconditionFailed" and status == 412:
                try:
                    observed = self._read_remote()
                except RetainedDevJournalError:
                    raise RetainedDevJournalError("journal_write_ambiguous") from None
                if observed is None or self._revision < 1 or self._etag is None:
                    raise RetainedDevJournalError("journal_write_ambiguous")
                self._blocked = False
                return False
            raise RetainedDevJournalError("journal_write_ambiguous") from None


__all__ = ["MAX_BYTES", "PHASES", "RetainedDevJournalError", "RetainedDevS3Journal"]
