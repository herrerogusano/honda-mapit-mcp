from __future__ import annotations

import hashlib
import io
import zipfile

import pytest

from mapit.dev_enrolled_manifest import (
    INVITATION_JWKS_FILENAME,
    MANIFEST_FILENAME,
    MAPIT_JWKS_FILENAME,
)
from scripts.dev_owner_enrolled_delivery import (
    OwnerEnrolledClosedDelivery,
    OwnerEnrolledDeliveryError,
)
from test_dev_owner_enrolled_delivery import Harness, Journal


def _coordinator(harness: Harness, archive_bytes: bytes):
    summary = dict(harness.summary)
    summary["zip_bytes"] = len(archive_bytes)
    summary["sha256"] = hashlib.sha256(archive_bytes).hexdigest()
    return OwnerEnrolledClosedDelivery(
        authority=harness.auth,
        accepted=harness.coordinator.accepted,
        prior_template=harness.prior,
        mapit_bootstrap_template=harness.bootstrap,
        manifest_raw=harness.args["manifest_raw"],
        invitation_jwks=harness.args["invitation_jwks"],
        mapit_jwks=harness.args["mapit_jwks"],
        archive_bytes=archive_bytes,
        archive_summary=summary,
        artifact_journal=Journal(),
        update_journal=Journal(),
        source_check=harness.source_check,
        protection_check=harness.protection_check,
        current_state=harness.state,
        publish_once=harness.publish,
        update_once=harness.update,
        clock=harness.clock,
        monotonic=harness.monotonic_clock,
    )


def _archive_with(harness: Harness, *, replacements=None, duplicate=None) -> bytes:
    replacements = replacements or {}
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for filename, contents in (
            (f"mapit/{MANIFEST_FILENAME}", harness.args["manifest_raw"]),
            (f"mapit/{INVITATION_JWKS_FILENAME}", harness.args["invitation_jwks"]),
            (f"mapit/{MAPIT_JWKS_FILENAME}", harness.args["mapit_jwks"]),
        ):
            archive.writestr(filename, replacements.get(filename, contents))
        if duplicate is not None:
            archive.writestr(duplicate[0], duplicate[1])
    return output.getvalue()


@pytest.mark.parametrize("path", [
    f"mapit/{MANIFEST_FILENAME}",
    f"mapit/{INVITATION_JWKS_FILENAME}",
    f"mapit/{MAPIT_JWKS_FILENAME}",
])
def test_archive_embedded_security_input_must_match_exact_supplied_bytes(path):
    harness = Harness()
    archive = _archive_with(harness, replacements={path: b'{"different":true}'})
    with pytest.raises(OwnerEnrolledDeliveryError, match="artifact_invalid"):
        _coordinator(harness, archive)
    assert harness.publish_calls == harness.update_calls == 0


def test_archive_casefold_duplicate_is_rejected_even_when_expected_entry_matches():
    harness = Harness()
    duplicate_name = f"MAPIT/{MANIFEST_FILENAME}"
    archive = _archive_with(harness, duplicate=(duplicate_name, harness.args["manifest_raw"]))
    with pytest.raises(OwnerEnrolledDeliveryError, match="artifact_invalid"):
        _coordinator(harness, archive)
    assert harness.publish_calls == harness.update_calls == 0


def test_accepted_phase_rejects_stale_original_owner_context_digest():
    harness = Harness()
    harness.coordinator.preflight()
    harness.coordinator.publish()
    harness.coordinator.update()
    current = harness.coordinator._current_state

    def stale_context(phase, binding):
        value = current(phase, binding)
        if phase == "accepted":
            value["owner_context_sha256"] = harness.auth["owner_context_sha256"]
        return value

    harness.coordinator._current_state = stale_context
    with pytest.raises(OwnerEnrolledDeliveryError, match="current_state_unverified"):
        harness.coordinator.readback()
    assert harness.update_calls == 1
    assert harness.update_journal.state["phase"] == "acknowledged"


def test_accepted_phase_requires_persisted_new_context_receipt_to_match_readback():
    harness = Harness()
    harness.coordinator.preflight()
    harness.coordinator.publish()
    harness.coordinator.update()
    accepted = harness.coordinator.readback()
    assert accepted["phase"] == "accepted"
    saved_context = harness.update_journal.state["receipt"]["owner_context_sha256"]
    assert saved_context != harness.auth["owner_context_sha256"]

    # A later readback must not silently accept a modified/stale durable receipt.
    harness.update_journal.state["receipt"]["owner_context_sha256"] = harness.auth["owner_context_sha256"]
    with pytest.raises(OwnerEnrolledDeliveryError, match="journal_invalid"):
        harness.coordinator.readback()
    assert harness.update_calls == 1
