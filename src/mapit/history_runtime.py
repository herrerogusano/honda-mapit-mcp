"""Opt-in local ledger orchestration; no automatic collection or raw logging."""

from __future__ import annotations

import os
import json
import re
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
ACL_IDENTITY_TIMEOUT_SECONDS = 10
ACL_APPLY_TIMEOUT_SECONDS = 10
ACL_VERIFY_TIMEOUT_SECONDS = 10
ACL_VERIFY_REJECTED_EXIT = 10
ACL_VERIFY_TRANSLATION_EXIT = 20
ACL_VERIFY_RUNTIME_EXIT = 21
_WINDOWS_SID_RE = re.compile(r"S-1-(?:\d+-)*\d+\Z")
_ACL_VERIFIER_FIELDS = frozenset({"rootProtected", "childrenChecked", "unexpectedAllow"})
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


def _current_user_sid(*, run=None, creationflags=None) -> str:
    """Read the current Windows SID; never include provider output in errors."""
    if creationflags is None:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    selected_run = run or subprocess.run
    try:
        powershell_env = _powershell_child_env()
        identity = selected_run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"],
            capture_output=True, text=True, timeout=ACL_IDENTITY_TIMEOUT_SECONDS,
            creationflags=creationflags, env=powershell_env,
        )
    except subprocess.TimeoutExpired:
        raise HistoryRuntimeError("history_acl_identity_timeout") from None
    except Exception:
        raise HistoryRuntimeError("history_acl_identity_failed") from None
    code = getattr(identity, "returncode", None)
    output = getattr(identity, "stdout", None)
    if type(code) is not int or code != 0 or type(output) is not str:
        raise HistoryRuntimeError("history_acl_identity_failed")
    sid = output.strip()
    if not _WINDOWS_SID_RE.fullmatch(sid):
        raise HistoryRuntimeError("history_acl_identity_failed")
    return sid


def _acl_verifier_script(directory: Path, sid: str) -> str:
    """Build a fixed-result PowerShell verifier; it performs no ACL writes."""
    target_literal = str(directory).replace("'", "''")
    return (
        "$ErrorActionPreference='Stop'; try { "
        f"$allowed=@('{sid}','S-1-5-18','S-1-5-32-544'); "
        f"$root=Get-Acl -LiteralPath '{target_literal}'; "
        "if($null -eq $root -or $root.AreAccessRulesProtected -isnot [bool]){exit 21}; "
        "$rootProtected=($root.AreAccessRulesProtected -eq $true); "
        f"$targets=@(Get-Item -LiteralPath '{target_literal}'); "
        f"$children=@(Get-ChildItem -LiteralPath '{target_literal}' -Force); "
        "$targets+=@($children); $unexpected=$false; "
        "foreach($target in $targets){ "
        "if($null -eq $target -or $null -eq $target.FullName){exit 21}; "
        "$acl=Get-Acl -LiteralPath $target.FullName; "
        "if($null -eq $acl -or $null -eq $acl.Access){exit 21}; "
        "foreach($rule in $acl.Access){ "
        "if($null -eq $rule -or $null -eq $rule.IdentityReference -or "
        "$rule.AccessControlType -isnot [System.Security.AccessControl.AccessControlType]){exit 21}; "
        "try{$ruleSid=$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value} "
        "catch{exit 20}; "
        "if($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and "
        "$ruleSid -notin $allowed){$unexpected=$true} "
        "}}; "
        "$report=@{rootProtected=[bool]$rootProtected;childrenChecked=[bool]$true;unexpectedAllow=[bool]$unexpected}; "
        "$report | ConvertTo-Json -Compress; "
        "if(-not $rootProtected -or $unexpected){exit 10}; exit 0 "
        "} catch { exit 21 }"
    )


def _powershell_child_env() -> dict[str, str]:
    """Avoid passing a PowerShell 7 module path to Windows PowerShell 5.1 children."""
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.casefold() == "psmodulepath":
            del environment[name]
    return environment


def _verify_directory_access(
    directory: Path,
    sid: str,
    *,
    run=None,
    creationflags=None,
) -> None:
    """Read-only ACL check. Missing/mistyped verifier fields never imply success."""
    if creationflags is None:
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    selected_run = run or subprocess.run
    if not isinstance(sid, str) or not _WINDOWS_SID_RE.fullmatch(sid):
        raise HistoryRuntimeError("history_acl_identity_failed")
    try:
        powershell_env = _powershell_child_env()
        verified = selected_run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             _acl_verifier_script(directory, sid)],
            capture_output=True, text=True, timeout=ACL_VERIFY_TIMEOUT_SECONDS,
            creationflags=creationflags, env=powershell_env,
        )
    except subprocess.TimeoutExpired:
        raise HistoryRuntimeError("history_acl_verify_timeout") from None
    except Exception:
        raise HistoryRuntimeError("history_acl_verify_runtime_failed") from None
    code = getattr(verified, "returncode", None)
    output = getattr(verified, "stdout", None)
    if type(code) is not int:
        raise HistoryRuntimeError("history_acl_verify_runtime_failed")
    if code == ACL_VERIFY_REJECTED_EXIT:
        raise HistoryRuntimeError("history_acl_verify_rejected")
    if code == ACL_VERIFY_TRANSLATION_EXIT:
        raise HistoryRuntimeError("history_acl_verify_translation_failed")
    if code != 0:
        raise HistoryRuntimeError("history_acl_verify_runtime_failed")
    if type(output) is not str:
        raise HistoryRuntimeError("history_acl_verify_runtime_failed")
    try:
        report = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        raise HistoryRuntimeError("history_acl_verify_runtime_failed") from None
    if not isinstance(report, dict) or frozenset(report) != _ACL_VERIFIER_FIELDS:
        raise HistoryRuntimeError("history_acl_verify_runtime_failed")
    if any(type(report[key]) is not bool for key in _ACL_VERIFIER_FIELDS):
        raise HistoryRuntimeError("history_acl_verify_runtime_failed")
    if report["rootProtected"] is not True or report["childrenChecked"] is not True or report["unexpectedAllow"] is not False:
        raise HistoryRuntimeError("history_acl_verify_rejected")


def restrict_directory_access(directory: Path) -> None:
    """Grant only the current user, SYSTEM and administrators; no encryption claim."""
    if sys.platform != "win32":
        raise HistoryRuntimeError("platform_unsupported")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    sid = _current_user_sid(creationflags=flags)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        _regular_path(directory, directory=True)
    except HistoryRuntimeError:
        raise
    except Exception:
        raise HistoryRuntimeError("history_acl_apply_failed") from None
    try:
        permissions = subprocess.run(
            ["icacls.exe", str(directory), "/inheritance:r", "/grant:r",
             f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
            capture_output=True, timeout=ACL_APPLY_TIMEOUT_SECONDS, creationflags=flags,
        )
    except subprocess.TimeoutExpired:
        raise HistoryRuntimeError("history_acl_apply_timeout") from None
    except Exception:
        raise HistoryRuntimeError("history_acl_apply_failed") from None
    if type(getattr(permissions, "returncode", None)) is not int or permissions.returncode != 0:
        raise HistoryRuntimeError("history_acl_apply_failed")
    _verify_directory_access(directory, sid, creationflags=flags)


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
