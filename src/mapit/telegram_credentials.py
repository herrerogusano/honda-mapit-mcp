"""Fail-closed Windows Credential Manager storage for Telegram onboarding.

The keyring dependency is imported lazily so Linux CI and offline tests remain
dependency-free.  The vault contains one canonical, versioned JSON envelope;
each mutation is one ``set_password`` operation, so a failed write leaves the
previous envelope untouched.
"""

from __future__ import annotations

import json
import re
import secrets
import sys
from dataclasses import dataclass, field
from typing import Any, Iterable


class TelegramCredentialStoreError(RuntimeError):
    """Stable safe category for credential-store failures."""

    def __init__(self, category: str = "credential_store_failed") -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class TelegramCredentials:
    token: str = field(repr=False)
    allowed_pairs: frozenset[tuple[int, int]]

    def __repr__(self) -> str:
        return "TelegramCredentials(<redacted>, allowed_pairs=<redacted>)"


class WindowsKeyringTelegramCredentialStore:
    """Use only the native Windows Vault keyring backend."""

    SERVICE = "honda-mapit-telegram"
    STATE_ACCOUNT = "telegram-state-v1"
    EXPECTED_MODULE = "keyring.backends.Windows"
    EXPECTED_CLASS = "WinVaultKeyring"
    STATE_FORMAT = "telegram-state-v1"
    STATE_VERSION = 1
    MAX_STATE_BYTES = 2048
    MAX_TOKEN_BYTES = 512
    MAX_PAIRS = 16
    _STATE_KEYS = frozenset({"format", "version", "token", "pairs", "challenge"})
    _TOKEN_RE = re.compile(r"\A[0-9]{1,20}:[A-Za-z0-9_-]{16,128}\Z")
    _CHALLENGE_RE = re.compile(r"\A[A-Za-z0-9_-]{32,128}\Z")

    def __init__(self, *, keyring_module: Any | None = None, backend: Any | None = None) -> None:
        if keyring_module is None:
            if sys.platform != "win32":
                raise TelegramCredentialStoreError()
            try:
                import keyring as keyring_module  # type: ignore[no-redef]
            except Exception:
                raise TelegramCredentialStoreError() from None
        self._keyring = keyring_module
        self._backend = backend if backend is not None else self._get_backend()
        self._assert_native_backend()

    def _get_backend(self) -> Any:
        try:
            return self._keyring.get_keyring()
        except Exception:
            raise TelegramCredentialStoreError() from None

    def _assert_native_backend(self) -> None:
        backend_type = type(self._backend)
        if backend_type.__module__ != self.EXPECTED_MODULE or backend_type.__name__ != self.EXPECTED_CLASS:
            raise TelegramCredentialStoreError()

    def _get_raw(self) -> str | None:
        try:
            value = self._keyring.get_password(self.SERVICE, self.STATE_ACCOUNT)
        except Exception:
            raise TelegramCredentialStoreError() from None
        if value is not None and not isinstance(value, str):
            raise TelegramCredentialStoreError()
        return value

    def _delete(self) -> None:
        missing = getattr(getattr(self._keyring, "errors", None), "PasswordDeleteError", None)
        if missing is None:
            try:
                from keyring.errors import PasswordDeleteError
            except Exception:
                PasswordDeleteError = None  # type: ignore[assignment]
            missing = PasswordDeleteError
        try:
            self._keyring.delete_password(self.SERVICE, self.STATE_ACCOUNT)
        except Exception as exc:
            if missing is not None and isinstance(exc, missing):
                return
            raise TelegramCredentialStoreError() from None

    @classmethod
    def _normalize_pairs(cls, pairs: Iterable[tuple[int, int]]) -> frozenset[tuple[int, int]]:
        if pairs is None:
            raise TelegramCredentialStoreError()
        try:
            values = list(pairs)
        except (TypeError, ValueError):
            raise TelegramCredentialStoreError() from None
        if not 1 <= len(values) <= cls.MAX_PAIRS:
            raise TelegramCredentialStoreError()
        normalized: set[tuple[int, int]] = set()
        for pair in values:
            if (
                not isinstance(pair, (tuple, list))
                or len(pair) != 2
                or type(pair[0]) is not int
                or type(pair[1]) is not int
                or pair[0] <= 0
                or pair[1] <= 0
            ):
                raise TelegramCredentialStoreError()
            normalized.add((pair[0], pair[1]))
        if len(normalized) != len(values):
            raise TelegramCredentialStoreError()
        return frozenset(normalized)

    @classmethod
    def _validate_token(cls, token: str) -> str:
        if not isinstance(token, str) or not cls._TOKEN_RE.fullmatch(token) or "\x00" in token:
            raise TelegramCredentialStoreError()
        try:
            if len(token.encode("utf-8")) > cls.MAX_TOKEN_BYTES:
                raise TelegramCredentialStoreError()
        except UnicodeEncodeError:
            raise TelegramCredentialStoreError() from None
        return token

    @classmethod
    def _validate_challenge(cls, challenge: str) -> str:
        if not isinstance(challenge, str) or not cls._CHALLENGE_RE.fullmatch(challenge):
            raise TelegramCredentialStoreError()
        return challenge

    @classmethod
    def _canonical(cls, envelope: dict[str, Any]) -> str:
        raw = json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        try:
            if len(raw.encode("utf-8")) > cls.MAX_STATE_BYTES:
                raise TelegramCredentialStoreError()
        except UnicodeEncodeError:
            raise TelegramCredentialStoreError() from None
        return raw

    @classmethod
    def _validated_envelope(
        cls,
        *,
        token: str | None,
        pairs: Iterable[tuple[int, int]] | None,
        challenge: str | None,
    ) -> dict[str, Any]:
        if token is not None:
            token = cls._validate_token(token)
        if challenge is not None:
            challenge = cls._validate_challenge(challenge)
        encoded_pairs: list[list[int]] | None
        if pairs is None:
            encoded_pairs = None
        else:
            normalized = cls._normalize_pairs(pairs)
            encoded_pairs = [[user_id, chat_id] for user_id, chat_id in sorted(normalized)]
        envelope: dict[str, Any] = {
            "format": cls.STATE_FORMAT,
            "version": cls.STATE_VERSION,
            "token": token,
            "pairs": encoded_pairs,
            "challenge": challenge,
        }
        if token is None and (encoded_pairs is not None or challenge is not None):
            raise TelegramCredentialStoreError()
        if challenge is not None and token is None:
            raise TelegramCredentialStoreError()
        cls._canonical(envelope)
        return envelope

    @classmethod
    def _parse_envelope(cls, raw: str | None) -> dict[str, Any] | None:
        if raw is None:
            return None
        if not isinstance(raw, str):
            raise TelegramCredentialStoreError()
        try:
            if len(raw.encode("utf-8")) > cls.MAX_STATE_BYTES:
                raise TelegramCredentialStoreError()
            parsed = json.loads(raw)
        except TelegramCredentialStoreError:
            raise
        except Exception:
            raise TelegramCredentialStoreError() from None
        if not isinstance(parsed, dict) or frozenset(parsed) != cls._STATE_KEYS:
            raise TelegramCredentialStoreError()
        if raw != cls._canonical(parsed):
            raise TelegramCredentialStoreError()
        if parsed["format"] != cls.STATE_FORMAT or type(parsed["version"]) is not int or parsed["version"] != cls.STATE_VERSION:
            raise TelegramCredentialStoreError()
        token = parsed["token"]
        challenge = parsed["challenge"]
        if token is not None:
            cls._validate_token(token)
        if challenge is not None:
            cls._validate_challenge(challenge)
        pairs = parsed["pairs"]
        if pairs is not None:
            cls._normalize_pairs(pairs)
        if token is None and (pairs is not None or challenge is not None):
            raise TelegramCredentialStoreError()
        if challenge is not None and token is None:
            raise TelegramCredentialStoreError()
        return parsed

    def _load_envelope(self) -> dict[str, Any] | None:
        self._assert_native_backend()
        return self._parse_envelope(self._get_raw())

    def _write_envelope(self, envelope: dict[str, Any]) -> None:
        raw = self._canonical(envelope)
        try:
            # This is deliberately the only vault write.  WinVault keeps the
            # previous value when set_password raises, so no rollback/delete
            # sequence can destroy a valid prior state.
            self._keyring.set_password(self.SERVICE, self.STATE_ACCOUNT, raw)
        except Exception:
            raise TelegramCredentialStoreError() from None

    def save_token(self, token: str, *, challenge: str | None = None) -> str:
        self._assert_native_backend()
        challenge = secrets.token_urlsafe(32) if challenge is None else challenge
        envelope = self._validated_envelope(token=token, pairs=None, challenge=challenge)
        self._write_envelope(envelope)
        return challenge

    def load_token(self) -> str | None:
        envelope = self._load_envelope()
        return None if envelope is None else envelope["token"]

    def load_challenge(self) -> str | None:
        envelope = self._load_envelope()
        return None if envelope is None else envelope["challenge"]

    def save_allowlist(self, pair: tuple[int, int]) -> None:
        current = self._load_envelope()
        if current is None or current["token"] is None:
            raise TelegramCredentialStoreError()
        pairs = self._normalize_pairs((pair,))
        envelope = self._validated_envelope(
            token=current["token"], pairs=pairs, challenge=current["challenge"]
        )
        self._write_envelope(envelope)

    def delete_challenge(self, challenge: str) -> None:
        current = self._load_envelope()
        if current is None or current["challenge"] is None:
            raise TelegramCredentialStoreError()
        expected = self._validate_challenge(challenge)
        if not secrets.compare_digest(current["challenge"], expected):
            raise TelegramCredentialStoreError()
        envelope = self._validated_envelope(
            token=current["token"], pairs=current["pairs"], challenge=None
        )
        self._write_envelope(envelope)

    def save(self, token: str, allowed_pairs: Iterable[tuple[int, int]]) -> None:
        envelope = self._validated_envelope(token=token, pairs=allowed_pairs, challenge=None)
        self._write_envelope(envelope)

    def load(self) -> TelegramCredentials | None:
        envelope = self._load_envelope()
        if envelope is None:
            return None
        if envelope["token"] is None or envelope["pairs"] is None or envelope["challenge"] is not None:
            raise TelegramCredentialStoreError()
        pairs = self._normalize_pairs(envelope["pairs"])
        return TelegramCredentials(envelope["token"], pairs)

    def delete(self) -> None:
        self._assert_native_backend()
        self._delete()


__all__ = [
    "TelegramCredentialStoreError",
    "TelegramCredentials",
    "WindowsKeyringTelegramCredentialStore",
]
