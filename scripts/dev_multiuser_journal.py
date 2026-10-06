"""Durable envelope for isolated retained-DEV multi-user state.

The historical ``FileJournal`` stores a state object directly and validates
that object as a rehearsal record.  Multi-user cores have several different
state shapes, so they use this private envelope without changing the legacy
journal implementation or accepting an old state file accidentally.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
from pathlib import Path
from typing import Any, Iterator

from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError

SCHEMA = 1
KIND = "dev-multiuser-private-state"
MAX_BYTES = 64 * 1024


class MultiuserJournalError(ValueError):
    """Stable local journal category with no path or provider details."""

    def __init__(self, category: str = "journal_invalid") -> None:
        self.category = category
        super().__init__(category)


def _json_bytes(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise MultiuserJournalError("journal_invalid") from None
    if len(raw) > MAX_BYTES:
        raise MultiuserJournalError("journal_too_large")
    return raw


class PlainFileJournal:
    """Legacy atomic file/lock mechanics with a strict multi-user envelope."""

    def __init__(self, state_dir: Path):
        try:
            self._base = FileJournal(Path(state_dir))
        except Exception:
            raise MultiuserJournalError("journal_unavailable") from None

    def locked(self) -> Iterator[None]:
        return self._base.locked()

    def load(self) -> dict[str, Any] | None:
        try:
            envelope = self._base.load()
        except RehearsalError:
            raise MultiuserJournalError("journal_invalid") from None
        except Exception:
            raise MultiuserJournalError("journal_read_failed") from None
        if envelope is None:
            return None
        if (type(envelope) is not dict or set(envelope) != {"schema", "kind", "value"}
            or envelope.get("schema") != SCHEMA or envelope.get("kind") != KIND
            or type(envelope.get("value")) is not dict):
            raise MultiuserJournalError("journal_invalid")
        try:
            return json.loads(_json_bytes(envelope["value"]).decode("ascii"))
        except MultiuserJournalError:
            raise
        except Exception:
            raise MultiuserJournalError("journal_invalid") from None

    def save(self, value: Mapping[str, Any]) -> None:
        if type(value) is not dict:
            raise MultiuserJournalError("journal_invalid")
        # Round-trip before writing to reject custom objects and preserve a
        # detached plain-data snapshot across process boundaries.
        detached = json.loads(_json_bytes(value).decode("ascii"))
        envelope = {"schema": SCHEMA, "kind": KIND, "value": detached}
        try:
            self._base.save(envelope)
        except RehearsalError:
            raise MultiuserJournalError("journal_write_failed") from None
        except Exception:
            raise MultiuserJournalError("journal_write_failed") from None


__all__ = ["PlainFileJournal", "MultiuserJournalError", "SCHEMA", "KIND"]
