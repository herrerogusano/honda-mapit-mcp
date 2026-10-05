"""Fail-closed refresh-token storage and reusable session orchestration."""

from __future__ import annotations

import sys
import hashlib
import hmac
import json
from dataclasses import dataclass, replace
from typing import Any, Callable, Protocol

from .auth import CognitoAuthenticator, CognitoHTTPError, MapitSession, UnsupportedCognitoChallenge
from .config import MapitConfig, RuntimeConfig, fetch_public_runtime_config


class RefreshTokenStoreError(RuntimeError):
    """A refresh-token store is unavailable or not the approved backend."""


class SessionManagerError(RuntimeError):
    """Safe public category for GUI/session orchestration failures."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class RefreshTokenStore(Protocol):
    def save(self, refresh_token: str) -> None: ...
    def load(self) -> str | None: ...
    def delete(self) -> None: ...


class WindowsKeyringRefreshTokenStore:
    """Use only native Windows keyring entries for a bounded v1 token store.

    v1 uses one manifest and up to eight UTF-8 chunks.  The legacy single
    entry is read only for migration and is removed only after v1 is verified.
    No file or alternate keyring backend is ever used.
    """

    SERVICE = "mapit-client"
    ACCOUNT = "refresh-token"
    V1_FORMAT = "mapit-refresh-v1"
    V1_VERSION = 1
    CHUNK_BYTES = 1024
    MAX_CHUNKS = 8
    MAX_TOKEN_BYTES = CHUNK_BYTES * MAX_CHUNKS
    MANIFEST_ACCOUNT = "mapit-refresh-v1-manifest"
    CHUNK_ACCOUNT_PREFIX = "mapit-refresh-v1-chunk-"
    ALTERNATE_CHUNK_ACCOUNT_PREFIX = "mapit-refresh-v1-alt-chunk-"
    # Descriptive aliases kept public for callers/tests that distinguish v1
    # names from the legacy service/account pair.
    V1_MANIFEST_ACCOUNT = MANIFEST_ACCOUNT
    V1_CHUNK_ACCOUNT_PREFIX = CHUNK_ACCOUNT_PREFIX
    EXPECTED_MODULE = "keyring.backends.Windows"
    EXPECTED_CLASS = "WinVaultKeyring"
    _MANIFEST_KEYS = frozenset({"format", "version", "count", "chunk_bytes", "sha256"})

    def __init__(self, *, keyring_module: Any | None = None, backend: Any | None = None) -> None:
        self._injected = keyring_module is not None or backend is not None
        if keyring_module is None:
            if sys.platform != "win32":
                raise RefreshTokenStoreError("Windows keyring is unavailable")
            try:
                import keyring as keyring_module  # type: ignore[no-redef]
            except Exception as exc:
                raise RefreshTokenStoreError("keyring dependency is unavailable") from None
        self._keyring = keyring_module
        self._backend = backend if backend is not None else self._get_backend()
        self._assert_native_backend()

    def _get_backend(self) -> Any:
        try:
            return self._keyring.get_keyring()
        except Exception:
            raise RefreshTokenStoreError("keyring backend is unavailable") from None

    def _assert_native_backend(self) -> None:
        backend_type = type(self._backend)
        if backend_type.__module__ != self.EXPECTED_MODULE or backend_type.__name__ != self.EXPECTED_CLASS:
            raise RefreshTokenStoreError("keyring backend is not native Windows Credential Manager")

    @classmethod
    def _chunk_account(cls, index: int, prefix: str | None = None) -> str:
        return f"{prefix or cls.CHUNK_ACCOUNT_PREFIX}{index:04d}"

    def _get(self, account: str) -> str | None:
        try:
            value = self._keyring.get_password(self.SERVICE, account)
        except Exception:
            raise RefreshTokenStoreError("keyring read failed") from None
        if value is None:
            return None
        if not isinstance(value, str):
            raise RefreshTokenStoreError("keyring value has invalid type")
        return value

    def _set(self, account: str, value: str) -> None:
        try:
            self._keyring.set_password(self.SERVICE, account, value)
        except Exception:
            raise RefreshTokenStoreError("keyring write failed") from None

    def _password_delete_error(self) -> type[BaseException] | None:
        error = getattr(getattr(self._keyring, "errors", None), "PasswordDeleteError", None)
        if error is not None:
            return error
        try:
            from keyring.errors import PasswordDeleteError
        except Exception:
            return None
        return PasswordDeleteError

    def _delete_account(self, account: str) -> None:
        password_delete_error = self._password_delete_error()
        try:
            self._keyring.delete_password(self.SERVICE, account)
        except Exception as exc:
            if password_delete_error is not None and isinstance(exc, password_delete_error):
                return
            raise RefreshTokenStoreError("keyring delete failed") from None

    @classmethod
    def _split_token(cls, refresh_token: str) -> list[str]:
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RefreshTokenStoreError("refresh token is empty")
        try:
            encoded = refresh_token.encode("utf-8")
        except (UnicodeEncodeError, AttributeError):
            raise RefreshTokenStoreError("refresh token is not valid UTF-8") from None
        if not encoded or len(encoded) > cls.MAX_TOKEN_BYTES:
            raise RefreshTokenStoreError("refresh token exceeds storage limit")
        chunks: list[str] = []
        current: list[str] = []
        current_bytes = 0
        for character in refresh_token:
            char_bytes = len(character.encode("utf-8"))
            if current and current_bytes + char_bytes > cls.CHUNK_BYTES:
                chunks.append("".join(current))
                current = []
                current_bytes = 0
            current.append(character)
            current_bytes += char_bytes
        if current:
            chunks.append("".join(current))
        if not 1 <= len(chunks) <= cls.MAX_CHUNKS:
            raise RefreshTokenStoreError("refresh token chunk count is invalid")
        return chunks

    @classmethod
    def _manifest_text(cls, count: int, digest: str) -> str:
        manifest = {
            "format": cls.V1_FORMAT,
            "version": cls.V1_VERSION,
            "count": count,
            "chunk_bytes": cls.CHUNK_BYTES,
            "sha256": digest,
        }
        return json.dumps(manifest, ensure_ascii=True, separators=(",", ":"), sort_keys=True)

    @classmethod
    def _parse_manifest(cls, raw: str) -> dict[str, Any]:
        if not isinstance(raw, str) or not raw:
            raise RefreshTokenStoreError("manifest is missing or invalid")
        try:
            parsed = json.loads(raw)
        except Exception:
            raise RefreshTokenStoreError("manifest is invalid") from None
        if not isinstance(parsed, dict) or set(parsed) != cls._MANIFEST_KEYS:
            raise RefreshTokenStoreError("manifest schema is invalid")
        if raw != json.dumps(parsed, ensure_ascii=True, separators=(",", ":"), sort_keys=True):
            raise RefreshTokenStoreError("manifest is not canonical")
        version = parsed.get("version")
        if (
            parsed.get("format") != cls.V1_FORMAT
            or isinstance(version, bool)
            or not isinstance(version, int)
            or version != cls.V1_VERSION
        ):
            raise RefreshTokenStoreError("manifest version is unsupported")
        count = parsed.get("count")
        chunk_bytes = parsed.get("chunk_bytes")
        digest = parsed.get("sha256")
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 1 <= count <= cls.MAX_CHUNKS
            or isinstance(chunk_bytes, bool)
            or not isinstance(chunk_bytes, int)
            or chunk_bytes != cls.CHUNK_BYTES
            or not isinstance(digest, str)
            or len(digest) != hashlib.sha256().digest_size * 2
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RefreshTokenStoreError("manifest limits are invalid")
        return parsed

    def _read_all_chunks(self, prefix: str | None = None) -> list[str | None]:
        return [self._get(self._chunk_account(index, prefix)) for index in range(self.MAX_CHUNKS)]

    def _load_v1_chunks(self, manifest: dict[str, Any], prefix: str) -> str:
        count = manifest["count"]
        values = self._read_all_chunks(prefix)
        chunks = values[:count]
        stale = values[count:]
        if any(not isinstance(chunk, str) or not chunk for chunk in chunks):
            raise RefreshTokenStoreError("manifest chunks are missing")
        if any(chunk is not None for chunk in stale):
            raise RefreshTokenStoreError("manifest has stale chunks")
        try:
            encoded_chunks = [chunk.encode("utf-8") for chunk in chunks if isinstance(chunk, str)]
        except UnicodeEncodeError:
            raise RefreshTokenStoreError("manifest chunks are not valid UTF-8") from None
        if any(not 1 <= len(chunk) <= self.CHUNK_BYTES for chunk in encoded_chunks):
            raise RefreshTokenStoreError("manifest chunk limits are invalid")
        encoded = b"".join(encoded_chunks)
        if not 1 <= len(encoded) <= self.MAX_TOKEN_BYTES:
            raise RefreshTokenStoreError("manifest token limits are invalid")
        try:
            token = encoded.decode("utf-8")
        except UnicodeDecodeError:
            raise RefreshTokenStoreError("manifest token is not valid UTF-8") from None
        digest = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(digest, manifest["sha256"]):
            raise RefreshTokenStoreError("manifest hash does not match")
        return token

    def _load_v1(self, raw_manifest: str) -> str:
        manifest = self._parse_manifest(raw_manifest)
        for prefix in (self.CHUNK_ACCOUNT_PREFIX, self.ALTERNATE_CHUNK_ACCOUNT_PREFIX):
            try:
                return self._load_v1_chunks(manifest, prefix)
            except RefreshTokenStoreError:
                continue
        raise RefreshTokenStoreError("manifest chunks are invalid")

    def _active_v1(self, raw_manifest: str) -> tuple[str, str]:
        manifest = self._parse_manifest(raw_manifest)
        for prefix in (self.CHUNK_ACCOUNT_PREFIX, self.ALTERNATE_CHUNK_ACCOUNT_PREFIX):
            try:
                return prefix, self._load_v1_chunks(manifest, prefix)
            except RefreshTokenStoreError:
                continue
        raise RefreshTokenStoreError("manifest chunks are invalid")

    def _delete_chunks(self, prefix: str) -> None:
        errors = False
        for index in range(self.MAX_CHUNKS):
            try:
                self._delete_account(self._chunk_account(index, prefix))
            except Exception:
                errors = True
        if errors:
            raise RefreshTokenStoreError("keyring chunk cleanup failed")

    def _delete_v1_chunks_best_effort(self, prefix: str) -> None:
        try:
            self._delete_chunks(prefix)
        except Exception:
            pass

    def save(self, refresh_token: str) -> None:
        self._assert_native_backend()
        chunks = self._split_token(refresh_token)
        encoded = refresh_token.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        manifest_text = self._manifest_text(len(chunks), digest)
        old_manifest = self._get(self.MANIFEST_ACCOUNT)
        active_prefix: str | None = None
        if old_manifest is not None:
            active_prefix, old_token = self._active_v1(old_manifest)
            if not old_token:
                raise RefreshTokenStoreError("existing token is invalid")
        target_prefix = (
            self.ALTERNATE_CHUNK_ACCOUNT_PREFIX
            if active_prefix == self.CHUNK_ACCOUNT_PREFIX
            else self.CHUNK_ACCOUNT_PREFIX
        )
        try:
            # Stage the replacement in the inactive bank.  The currently
            # published manifest and its chunks remain untouched until the
            # staged set has been verified.
            self._delete_chunks(target_prefix)
            for index, chunk in enumerate(chunks):
                self._set(self._chunk_account(index, target_prefix), chunk)
            reread = self._read_all_chunks(target_prefix)
            if reread[: len(chunks)] != chunks or any(chunk is not None for chunk in reread[len(chunks) :]):
                raise RefreshTokenStoreError("chunk verification failed")
            if self._load_v1_chunks(self._parse_manifest(manifest_text), target_prefix) != refresh_token:
                raise RefreshTokenStoreError("staged manifest verification failed")
            self._set(self.MANIFEST_ACCOUNT, manifest_text)
            if self.load() != refresh_token:
                raise RefreshTokenStoreError("manifest verification failed")
            if active_prefix is not None and active_prefix != target_prefix:
                self._delete_v1_chunks_best_effort(active_prefix)
            # Legacy is removed only after complete v1 verification. Failure to
            # remove it is harmless because v1 has precedence on the next load.
            try:
                self._delete_account(self.ACCOUNT)
            except Exception:
                pass
        except Exception:
            # The old manifest remains valid if staging or publication fails.
            # If publication did occur, restore it before removing staged data.
            try:
                if old_manifest is None:
                    self._delete_account(self.MANIFEST_ACCOUNT)
                else:
                    self._set(self.MANIFEST_ACCOUNT, old_manifest)
            except Exception:
                pass
            self._delete_v1_chunks_best_effort(target_prefix)
            raise RefreshTokenStoreError("keyring save failed") from None

    def load(self) -> str | None:
        self._assert_native_backend()
        manifest = self._get(self.MANIFEST_ACCOUNT)
        if manifest is not None:
            token = self._load_v1(manifest)
            # v1 wins if both formats exist; legacy cleanup is best-effort.
            try:
                self._delete_account(self.ACCOUNT)
            except Exception:
                pass
            return token

        values = self._read_all_chunks(self.CHUNK_ACCOUNT_PREFIX) + self._read_all_chunks(self.ALTERNATE_CHUNK_ACCOUNT_PREFIX)
        if any(value is not None for value in values):
            raise RefreshTokenStoreError("stale chunks without manifest")
        legacy = self._get(self.ACCOUNT)
        if legacy is None:
            return None
        # save() verifies v1 before deleting legacy. If it fails, legacy remains.
        self.save(legacy)
        return self._load_v1(self._get(self.MANIFEST_ACCOUNT) or "")

    def delete(self) -> None:
        self._assert_native_backend()
        errors = False
        try:
            self._delete_account(self.MANIFEST_ACCOUNT)
        except Exception:
            errors = True
        for index in range(self.MAX_CHUNKS):
            for prefix in (self.CHUNK_ACCOUNT_PREFIX, self.ALTERNATE_CHUNK_ACCOUNT_PREFIX):
                try:
                    self._delete_account(self._chunk_account(index, prefix))
                except Exception:
                    errors = True
        try:
            self._delete_account(self.ACCOUNT)
        except Exception:
            errors = True
        if errors:
            raise RefreshTokenStoreError("keyring delete failed") from None


@dataclass(frozen=True)
class ManagedSession:
    config: MapitConfig
    session: MapitSession


class SessionManager:
    """Coordinate public discovery, manual login, saved refresh and forgetting."""

    def __init__(
        self,
        *,
        base_config: MapitConfig | None = None,
        store: RefreshTokenStore | None = None,
        discover=fetch_public_runtime_config,
        authenticator_factory=CognitoAuthenticator,
    ) -> None:
        self.base_config = base_config or MapitConfig()
        self.store = store
        self.discover = discover
        self.authenticator_factory = authenticator_factory
        self.last_error_category: str | None = None

    def _discover_config(self, *, email: str | None = None, password: str | None = None) -> MapitConfig:
        config = replace(self.base_config, email=email, password=password)
        runtime: RuntimeConfig = self.discover(config.frontend_url, timeout=config.http_timeout)
        return config.with_runtime(runtime)

    def login_manual(self, email: str, password: str) -> ManagedSession:
        self.last_error_category = None
        try:
            config = self._discover_config(email=email, password=password)
        except Exception:
            self.last_error_category = "discovery_failed"
            raise SessionManagerError(self.last_error_category) from None
        try:
            session = self.authenticator_factory(config).authenticate()
        except Exception as exc:
            self.last_error_category = self._auth_error_category(exc)
            raise SessionManagerError(self.last_error_category) from None
        if self.store is not None and session.refresh_token:
            try:
                self.store.save(session.refresh_token)
            except Exception:
                self.last_error_category = "credential_store_failed"
                raise SessionManagerError(self.last_error_category) from None
        self._bind_refresh_persistence(session)
        return ManagedSession(config, session)

    def login_saved(self) -> ManagedSession | None:
        self.last_error_category = None
        if self.store is None:
            return None
        try:
            refresh_token = self.store.load()
        except Exception:
            self.last_error_category = "credential_store_failed"
            return None
        if not refresh_token:
            return None
        try:
            config = self._discover_config()
        except Exception:
            # Discovery is public and transient; never destroy a usable token
            # merely because the frontend or a bundle is unavailable.
            self.last_error_category = "discovery_failed"
            return None
        try:
            session = self.authenticator_factory(config).authenticate_with_refresh_token(refresh_token)
        except Exception as exc:
            category = self._auth_error_category(exc)
            if self._is_invalid_saved_token_error(exc):
                deleted = self._safe_delete()
                self.last_error_category = category if deleted else "credential_store_failed"
            else:
                # Preserve the token across transient/network/parser failures
                # and unsupported challenges. Only an explicit Cognito HTTP
                # rejection makes the saved token irrecoverable.
                self.last_error_category = category
            return None
        if session.refresh_token and session.refresh_token != refresh_token:
            try:
                self.store.save(session.refresh_token)
            except Exception:
                self.last_error_category = "credential_store_failed"
                return None
        self._bind_refresh_persistence(session)
        return ManagedSession(config, session)

    def forget_saved_session(self) -> bool:
        """Delete the saved token and report whether the operation succeeded."""
        return self._safe_delete()

    @staticmethod
    def _auth_error_category(exc: BaseException) -> str:
        if isinstance(exc, UnsupportedCognitoChallenge):
            return "authentication_rejected"
        if isinstance(exc, CognitoHTTPError) and 400 <= exc.status < 500:
            return "authentication_rejected"
        return "authentication_failed"

    @staticmethod
    def _is_invalid_saved_token_error(exc: BaseException) -> bool:
        """Only an explicit Cognito HTTP 4xx may invalidate a saved token."""
        return isinstance(exc, CognitoHTTPError) and 400 <= exc.status < 500

    def _bind_refresh_persistence(self, session: MapitSession) -> None:
        if self.store is None or session._refresh_callback is None:
            return
        callback: Callable[[MapitSession], None] = session._refresh_callback

        def refresh_and_persist(current: MapitSession) -> None:
            previous = current.refresh_token
            callback(current)
            rotated = current.refresh_token
            if rotated and rotated != previous:
                try:
                    self.store.save(rotated)
                except Exception:
                    raise SessionManagerError("credential_store_failed") from None

        session._refresh_callback = refresh_and_persist

    def _safe_delete(self) -> bool:
        try:
            if self.store is None:
                return True
            self.store.delete()
            return True
        except Exception:
            return False
