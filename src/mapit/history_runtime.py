"""Opt-in local ledger orchestration; no automatic collection or raw logging."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import stat
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .session import ManagedSession, SessionManager, WindowsKeyringRefreshTokenStore

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
KEY_SERVICE = "honda-mapit-distance-ledger"
KEY_ACCOUNT = "hmac-key-v1"
SCOPE_ACCOUNT = "active-scope-v1"


def _regular_path(path: Path, *, directory: bool = False) -> None:
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise HistoryRuntimeError("history_path_invalid")


@contextmanager
def _operation_lock(root: Path):
    """Single local owner; a crash leaves a fail-closed empty lock, not private data."""
    _regular_path(root, directory=True)
    target = root / "history-operation.lock"
    try:
        handle = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise HistoryRuntimeError("history_busy") from None
    except OSError:
        raise HistoryRuntimeError("storage_failed") from None
    try:
        yield
    finally:
        os.close(handle)
        try:
            target.unlink()
        except OSError:
            raise HistoryRuntimeError("storage_failed") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _bounded_client(config, session):
    from .client import MapitClient, MapitResponseTooLarge
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    remaining = [4]  # Two logical GETs, at most one auth recovery per GET.

    def transport(method, url, headers):
        if method != "GET" or remaining[0] <= 0:
            raise HistoryRuntimeError("read_budget_exceeded")
        remaining[0] -= 1
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        with opener.open(request, timeout=min(config.http_timeout, 20)) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MapitResponseTooLarge()
        return raw

    return MapitClient(config, session, transport=transport)


def _validate_local_files(root: Path) -> None:
    _regular_path(root, directory=True)
    db = root / "distance-history.sqlite3"
    for target in [db, *(Path(str(db) + suffix) for suffix in ("-journal", "-wal", "-shm"))]:
        _regular_path(target)


class HistoryRuntimeError(RuntimeError):
    """A safe category, never a payload, identifier or filesystem exception."""

    def __init__(self, category: str = "history_failed") -> None:
        self.category = category
        super().__init__(category)


class WindowsHistorySecrets:
    """Small independent entries; never reuse or remove the MAPIT refresh entry."""

    def __init__(self, *, native_store=None) -> None:
        self._native = native_store or WindowsKeyringRefreshTokenStore()
        self._native._assert_native_backend()
        self._keyring = self._native._keyring

    def _load(self, account: str) -> str | None:
        try:
            value = self._keyring.get_password(KEY_SERVICE, account)
        except Exception:
            raise HistoryRuntimeError("credential_store_failed") from None
        if value is not None and not isinstance(value, str):
            raise HistoryRuntimeError("credential_store_failed")
        return value

    def _save(self, account: str, value: str) -> None:
        try:
            self._keyring.set_password(KEY_SERVICE, account, value)
            if self._load(account) != value:
                raise HistoryRuntimeError("credential_store_failed")
        except Exception:
            raise HistoryRuntimeError("credential_store_failed") from None

    def load_key(self, *, database_exists: bool, create: bool = False) -> bytes:
        value = self._load(KEY_ACCOUNT)
        if value is None:
            if database_exists or not create:
                raise HistoryRuntimeError("history_key_missing")
            value = secrets.token_hex(32)
            self._save(KEY_ACCOUNT, value)
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise HistoryRuntimeError("history_key_invalid")
        return bytes.fromhex(value)

    def active_scope(self) -> str:
        value = self._load(SCOPE_ACCOUNT)
        if value is None or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise HistoryRuntimeError("history_scope_missing")
        return value

    def set_active_scope(self, value: str) -> None:
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise HistoryRuntimeError("history_scope_invalid")
        self._save(SCOPE_ACCOUNT, value)

    def delete(self) -> None:
        for account in (SCOPE_ACCOUNT, KEY_ACCOUNT):
            if self._load(account) is None:
                continue
            try:
                self._keyring.delete_password(KEY_SERVICE, account)
            except Exception:
                raise HistoryRuntimeError("credential_store_failed") from None
            if self._load(account) is not None:
                raise HistoryRuntimeError("credential_store_failed")


def default_history_directory() -> Path:
    if sys.platform != "win32":
        raise HistoryRuntimeError("platform_unsupported")
    raw = os.environ.get("LOCALAPPDATA", "")
    base = Path(raw)
    if not raw or not base.is_absolute():
        raise HistoryRuntimeError("history_path_invalid")
    candidate = base / "HondaMapitMCP"
    _regular_path(candidate, directory=True)
    root = candidate.resolve()
    workspace = Path(__file__).resolve().parents[2]
    protected = [workspace]
    protected.extend(Path(os.environ[name]).resolve() for name in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial") if os.environ.get(name))
    if any(root.is_relative_to(path) for path in protected):
        raise HistoryRuntimeError("history_path_invalid")
    return root


def restrict_directory_access(directory: Path) -> None:
    """Grant only the current user, SYSTEM and administrators; no encryption claim."""
    if sys.platform != "win32":
        raise HistoryRuntimeError("platform_unsupported")
    flags = subprocess.CREATE_NO_WINDOW
    try:
        identity = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True, timeout=10, creationflags=flags,
        )
        sid = identity.stdout.strip()
        if identity.returncode or not sid.startswith("S-1-") or any(character not in "S0123456789-" for character in sid):
            raise HistoryRuntimeError("history_permissions_failed")
        directory.mkdir(parents=True, exist_ok=True)
        _regular_path(directory, directory=True)
        permissions = subprocess.run(
            ["icacls.exe", str(directory), "/inheritance:r", "/grant:r",
             f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            capture_output=True, timeout=10, creationflags=flags,
        )
        if permissions.returncode:
            raise HistoryRuntimeError("history_permissions_failed")
        target_literal = str(directory).replace("'", "''")
        check = (
            f"$ErrorActionPreference='Stop'; $acl=Get-Acl -LiteralPath '{target_literal}'; "
            f"$allowed=@('{sid}','S-1-5-18','S-1-5-32-544'); "
            "if(-not $acl.AreAccessRulesProtected){exit 1}; "
            "$targets=@(Get-Item -LiteralPath '" + target_literal + "'); "
            "$targets+=@(Get-ChildItem -LiteralPath '" + target_literal + "' -Force); "
            "foreach($target in $targets){$acl=Get-Acl -LiteralPath $target.FullName; "
            "foreach($rule in $acl.Access){"
            "$ruleSid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; "
            "if($rule.AccessControlType -eq 'Allow' -and $ruleSid -notin $allowed){exit 1}}}; exit 0"
        )
        verified = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", check],
            capture_output=True, timeout=10, creationflags=flags,
        )
        if verified.returncode:
            raise HistoryRuntimeError("history_permissions_failed")
    except HistoryRuntimeError:
        raise
    except Exception:
        raise HistoryRuntimeError("history_permissions_failed") from None


def _selected_account_vehicle(summary: Any, selected_vehicle: Any) -> tuple[str, str]:
    if not isinstance(summary, dict) or not isinstance(summary.get("account"), dict):
        raise HistoryRuntimeError("account_scope_unavailable")
    account = summary["account"].get("id")
    vehicle = selected_vehicle.get("id") if isinstance(selected_vehicle, dict) else None
    if (not isinstance(account, str) or not account.strip() or len(account) > 256
            or not isinstance(vehicle, str) or not vehicle.strip() or len(vehicle) > 256):
        raise HistoryRuntimeError("account_scope_unavailable")
    return account.strip(), vehicle.strip()


def _month_window(now: datetime) -> tuple[datetime, datetime]:
    if now.tzinfo is None or now.utcoffset() is None:
        raise HistoryRuntimeError("time_invalid")
    current = now.astimezone(timezone.utc)
    start = datetime(current.year, current.month, 1, tzinfo=timezone.utc)
    end = datetime(current.year + 1, 1, 1, tzinfo=timezone.utc) if current.month == 12 else datetime(current.year, current.month + 1, 1, tzinfo=timezone.utc)
    return start, end


def import_current_month(*, directory: Path | None = None, secret_store=None,
                         manager_factory=SessionManager, client_factory=None,
                         now: datetime | None = None, secure_directory=restrict_directory_access,
                         refresh_store_factory=WindowsKeyringRefreshTokenStore) -> dict[str, Any]:
    """One month only; validation precedes the first private SQLite write."""
    from .ledger import DistanceLedger
    from .services import MapitServices
    payload = None
    context = None
    ledger = None
    facts_committed = False
    try:
        root = directory if directory is not None else default_history_directory()
        db = root / "distance-history.sqlite3"
        secrets_store = secret_store or WindowsHistorySecrets()
        context = manager_factory(store=refresh_store_factory()).login_saved()
        if not isinstance(context, ManagedSession):
            raise HistoryRuntimeError("session_failed")
        client = (client_factory or _bounded_client)(context.config, context.session)
        summary, selected_vehicle = MapitServices(client)._account_and_vehicle()
        account, vehicle = _selected_account_vehicle(summary, selected_vehicle)
        summary = None
        window_now = now if now is not None else datetime.now(timezone.utc)
        start, end = _month_window(window_now)
        iso = lambda value: value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        payload = client.get_geo("/v1/routes", params={"vehicleId": vehicle, "from": iso(start), "to": iso(end)}, max_response_bytes=MAX_RESPONSE_BYTES)
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise HistoryRuntimeError("routes_list_invalid")
        if payload.get("lastEvaluatedKey") is not None:
            raise HistoryRuntimeError("pagination_unsupported")
        account_scope = context.config.core_api_url + "\n" + account
        # Validate before creating the DB/key, including a complete bounded batch.
        # Request-window time is captured before the upstream read; validate
        # route timestamps against a fresh post-response instant unless tests
        # supplied one fixed instant for both operations.
        validation_now = now if now is not None else datetime.now(timezone.utc)
        prepared = DistanceLedger.validate_routes(payload["data"], now=validation_now)
        if any(not start.date().isoformat() <= day < end.date().isoformat() for day in prepared):
            raise HistoryRuntimeError("routes_outside_window")
        secure_directory(root)
        with _operation_lock(root):
            _validate_local_files(root)
            key = secrets_store.load_key(database_exists=db.exists(), create=True)
            ledger = DistanceLedger(db, key)
            imported = ledger.import_routes(account_scope, vehicle, payload["data"], now=validation_now)
            facts_committed = True
            secrets_store.set_active_scope(ledger.scope_alias(account_scope, vehicle))
        return {"success": True, "category": "success", "imported_band": _count_band(imported.added),
                "duplicate_band": _count_band(imported.duplicate), "coverage": "PARTIAL",
                "metric_unit": "mapit_native_unconfirmed", "facts_committed": True, "private_values_printed": False}
    except Exception as exc:
        from .ledger import LedgerError
        category = exc.category if isinstance(exc, (HistoryRuntimeError, LedgerError)) else "import_failed"
        return {"success": False, "category": category, "facts_committed": facts_committed, "private_values_printed": False}
    finally:
        ledger = None
        payload = None
        context = None


def _count_band(count: int) -> str:
    return "none" if count == 0 else "few" if count <= 3 else "many"


def local_breakdown(group_by: str, *, directory: Path | None = None, secret_store=None,
                    secure_directory=restrict_directory_access):
    from .ledger import DistanceLedger
    root = directory if directory is not None else default_history_directory()
    db = root / "distance-history.sqlite3"
    if not db.is_file():
        raise HistoryRuntimeError("history_missing")
    secure_directory(root)
    secrets_store = secret_store or WindowsHistorySecrets()
    with _operation_lock(root):
        _validate_local_files(root)
        key = secrets_store.load_key(database_exists=True)
        ledger = DistanceLedger(db, key)
        return ledger.distance_breakdown_by_scope_alias(secrets_store.active_scope(), group_by)


def forget_history(*, directory: Path | None = None, secret_store=None) -> None:
    """Explicit local deletion only; never touch MAPIT auth entries or other files."""
    import sqlite3
    from .ledger import APPLICATION_ID, SCHEMA_VERSION
    root = directory if directory is not None else default_history_directory()
    db = root / "distance-history.sqlite3"
    secrets_store = secret_store or WindowsHistorySecrets()
    if not root.exists():
        secrets_store.delete()
        return
    with _operation_lock(root):
        targets = [db, *(Path(str(db) + suffix) for suffix in ("-journal", "-wal", "-shm"))]
        for target in targets:
            _regular_path(target)
        if db.exists():
            try:
                connection = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
                try:
                    if (connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
                            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
                        raise HistoryRuntimeError("schema_unsupported")
                finally:
                    connection.close()
            except sqlite3.Error:
                raise HistoryRuntimeError("storage_failed") from None
        elif any(target.exists() for target in targets[1:]):
            raise HistoryRuntimeError("schema_unsupported")
        for target in targets:
            if target.exists():
                try:
                    target.unlink()
                except OSError:
                    raise HistoryRuntimeError("storage_failed") from None
        secrets_store.delete()
