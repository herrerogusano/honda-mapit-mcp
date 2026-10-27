"""Fast native drift checks AFTER owning private provenance validation.

This is not an alternative ACL policy or private receipt parser. Construction
requires a registered accepted input object which has just passed its owning
validator. The captured owner/group/DACL descriptors are compared byte-for-byte
using native Windows APIs; no subprocess runs inside a fourteen-second lease.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import stat
from functools import lru_cache
import threading
import weakref

from scripts import dev_owner_enrolled_accepted_inputs as accepted
from scripts import dev_owner_enrolled_private_inputs as private

_REGISTERED = weakref.WeakKeyDictionary()
_REGISTRY_LOCK = threading.RLock()


class PrivateBaselineError(ValueError):
    def __init__(self):
        super().__init__("owner_mapit_private_inputs_changed")


@lru_cache(maxsize=1)
def _native_functions():
    if os.name != "nt":
        raise PrivateBaselineError()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get = advapi.GetNamedSecurityInfoW
    get.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p)]
    get.restype = wintypes.DWORD
    length = advapi.GetSecurityDescriptorLength
    length.argtypes, length.restype = [ctypes.c_void_p], wintypes.DWORD
    free = kernel.LocalFree
    free.argtypes, free.restype = [ctypes.c_void_p], ctypes.c_void_p
    return get, length, free


def native_security_descriptor(path):
    """Read only owner/group/DACL, including control flags; free native buffer."""
    get, length, free = _native_functions()
    descriptor = ctypes.c_void_p()
    try:
        if get(str(path), 1, 1 | 2 | 4, None, None, None, None, ctypes.byref(descriptor)) != 0 or not descriptor:
            raise PrivateBaselineError()
        size = length(descriptor)
        if not 20 <= size <= 64 * 1024:
            raise PrivateBaselineError()
        return ctypes.string_at(descriptor, size)
    finally:
        if descriptor:
            free(descriptor)


def _info(path, *, ancestors=True):
    for ancestor in (path, *path.parents) if ancestors else (path,):
        info = ancestor.lstat()
        if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise PrivateBaselineError()
    info = path.stat()
    return (int(info.st_dev), int(info.st_ino), int(info.st_size), int(info.st_mtime_ns), int(info.st_mode))


def _file_fingerprint(path, maximum, *, ancestors=True):
    before = _info(path, ancestors=ancestors)
    if not stat.S_ISREG(before[4]) or not 0 < before[2] <= maximum:
        raise PrivateBaselineError()
    digest, total = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while True:
            block = stream.read(min(128 * 1024, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise PrivateBaselineError()
            digest.update(block)
    if _info(path, ancestors=ancestors) != before or total != before[2]:
        raise PrivateBaselineError()
    return (*before[:4], digest.hexdigest())


class AcceptedPrivateBaseline:
    """Registered provenance identity plus native immutable filesystem baseline."""
    def __init__(self, evidence, *, descriptor_reader=native_security_descriptor):
        try:
            if type(evidence) is not accepted.AcceptedDeliveryInputs or evidence.assert_unchanged() is not True:
                raise ValueError
            current = accepted._REGISTERED.get(evidence)
            original = evidence.private_inputs
            old = private._REGISTERED.get(original)
            if current is None or old is None or current[3] is not original:
                raise ValueError
            self.evidence, self.original = evidence, original
            self.current_registration, self.old_registration = current, old
            self.descriptor_reader = descriptor_reader
            self.files, self.descriptors, self.path_identities = {}, {}, {}
            snapshots = [(fp, maximum) for fp, maximum in current[1]]
            snapshots.extend((fp, old[2][fp[0]]) for fp in old[1])
            for fp, maximum in snapshots:
                path = Path(fp[0])
                fingerprint = _file_fingerprint(path, maximum)
                if fingerprint != fp[1:]:
                    raise ValueError
                self._add(path, maximum=maximum)
            self._object_digest = evidence._digest()
            self._private_digest = self._projection_digest()
            if (self._object_digest != current[0] or self._private_digest != old[0]
                or evidence.assert_unchanged() is not True):
                raise ValueError
            # Registration is minted only here after owning provenance checks.
            # No instance registrar may reseal arbitrary mutable fields.
            with _REGISTRY_LOCK:
                _REGISTERED[self] = (evidence, original, current, old, descriptor_reader,
                    self._object_digest, self._private_digest, tuple(self.files.items()),
                    tuple(self.descriptors.items()), tuple(self.path_identities.items()))
            if self.check() is not True:
                raise ValueError
        except Exception:
            raise PrivateBaselineError() from None

    def __repr__(self):
        return "AcceptedPrivateBaseline(<redacted>)"

    def _projection_digest(self):
        return hashlib.sha256(private._canonical({
            "manifest_inputs": private._redacted_projection(self.original.manifest_inputs),
            "prior_template": self.original.prior_template,
            "runtime_binding": self.original.runtime_binding,
            "bootstrap_template": self.original.bootstrap_template})).hexdigest()

    def _add(self, path, *, maximum):
        path = Path(path)
        for target in (path, *path.parents):
            info = _info(target, ancestors=False)
            identity = (info[0], info[1], info[4])
            previous_identity = self.path_identities.get(target)
            if previous_identity is not None and previous_identity != identity:
                raise PrivateBaselineError()
            self.path_identities[target] = identity
            value = self.descriptor_reader(target)
            if type(value) is not bytes or not 0 < len(value) <= 64 * 1024:
                raise PrivateBaselineError()
            previous = self.descriptors.get(target)
            if previous is not None and previous != value:
                raise PrivateBaselineError()
            self.descriptors[target] = value
        fingerprint = _file_fingerprint(path, maximum)
        previous_file = self.files.get(path)
        if previous_file is not None and previous_file != (maximum, fingerprint):
            raise PrivateBaselineError()
        self.files[path] = (maximum, fingerprint)

    def add(self, path, *, maximum, expected_fingerprint):
        """Retain a newly validated private fence; existing evidence cannot reset."""
        with _REGISTRY_LOCK:
            if self.check() is not True:
                raise PrivateBaselineError()
            owning = _REGISTERED[self]
            files, descriptors, identities = dict(owning[7]), dict(owning[8]), dict(owning[9])
            path = Path(path)
            if (type(expected_fingerprint) is not tuple or len(expected_fingerprint) != 6
                or type(expected_fingerprint[0]) is not str
                or str(path.resolve(strict=True)) != expected_fingerprint[0]):
                raise PrivateBaselineError()
            # Derive a strict additive delta from immutable owning copies,
            # never seal the caller-visible dictionaries after mutation.
            for target in (path, *path.parents):
                info = _info(target, ancestors=False)
                identity = (info[0], info[1], info[4])
                value = owning[4](target)
                if (type(value) is not bytes or not 0 < len(value) <= 64 * 1024
                    or target in identities and identities[target] != identity
                    or target in descriptors and descriptors[target] != value):
                    raise PrivateBaselineError()
                identities[target], descriptors[target] = identity, value
            fingerprint = _file_fingerprint(path, maximum)
            if fingerprint != expected_fingerprint[1:]:
                raise PrivateBaselineError()
            if path in files and files[path] != (maximum, fingerprint):
                raise PrivateBaselineError()
            files[path] = (maximum, fingerprint)
            # Additions happen outside the SDK lease. Revalidate the owning
            # private ACL policy after native capture as well: an initial ACL
            # relaxation must not become a newly trusted native descriptor.
            _, _, owning_fingerprint = private._snapshot(path, maximum=maximum, acl_checker=owning[2][2])
            if owning_fingerprint != expected_fingerprint:
                raise PrivateBaselineError()
            if self.check() is not True or _REGISTERED.get(self) is not owning:
                raise PrivateBaselineError()
            self.files, self.descriptors, self.path_identities = files, descriptors, identities
            _REGISTERED[self] = (*owning[:7], tuple(files.items()), tuple(descriptors.items()), tuple(identities.items()))
            if self.check() is not True:
                raise PrivateBaselineError()

    def is_registered_native(self):
        with _REGISTRY_LOCK:
            registered = _REGISTERED.get(self)
        return registered is not None and registered[4] is native_security_descriptor and self.check() is True

    def check(self):
        try:
            with _REGISTRY_LOCK:
                registered = _REGISTERED.get(self)
            if (registered is None or self.evidence is not registered[0] or self.original is not registered[1]
                or self.current_registration is not registered[2] or self.old_registration is not registered[3]
                or self.descriptor_reader is not registered[4] or self._object_digest != registered[5]
                or self._private_digest != registered[6] or self.files != dict(registered[7])
                or self.descriptors != dict(registered[8]) or self.path_identities != dict(registered[9])):
                return False
            if (accepted._REGISTERED.get(self.evidence) is not self.current_registration
                or private._REGISTERED.get(self.original) is not self.old_registration
                or self.evidence.private_inputs is not self.original
                or self.original.manifest_inputs.get("context") is not self.old_registration[4]
                or private._owner_login._ACCEPTED.get(id(self.old_registration[4])) is not self.old_registration[4]
                or self.original.manifest_inputs.get("bootstrap_authority") is not self.old_registration[5]
                or self.evidence._digest() != self._object_digest
                or self._projection_digest() != self._private_digest):
                return False
            for path, baseline in self.descriptors.items():
                info = _info(path, ancestors=False)
                if (info[0], info[1], info[4]) != self.path_identities[path]:
                    return False
                if self.descriptor_reader(path) != baseline:
                    return False
            return all(_file_fingerprint(path, maximum, ancestors=False) == fingerprint
                for path, (maximum, fingerprint) in self.files.items())
        except Exception:
            return False
