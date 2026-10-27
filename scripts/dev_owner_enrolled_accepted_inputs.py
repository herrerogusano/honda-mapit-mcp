"""Read-only reconstruction of an accepted private owner delivery.

Historical windows remain immutable evidence. No delivery method, AWS call,
key/session decryption, journal save or login is performed by this loader.
An accepted result still needs fresh source/protection checks and actual SDK
readbacks before it can be used for human login.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import weakref

from scripts.dev_owner_enrolled_delivery import (
    OwnerEnrolledClosedDelivery, _canonical, _validate_authority, _MAX_ARCHIVE_BYTES,
)
from scripts.dev_owner_enrolled_observation import validate_capsule_for_accepted_update
from scripts.dev_owner_enrolled_preparation import assemble_delivery_metadata
from scripts.dev_owner_enrolled_private_inputs import (
    load_owner_enrolled_private_inputs, _snapshot, _read_snapshot_now, _issuer_jwks_url,
)
from scripts.run_aws_dev_owner_oauth_bootstrap import _reject_duplicates


class AcceptedDeliveryInputsError(ValueError):
    def __init__(self):
        super().__init__("accepted_delivery_inputs_unverified")


_REGISTERED = weakref.WeakKeyDictionary()


def _json(raw):
    return json.loads(raw, object_pairs_hook=_reject_duplicates,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))


def _terminal(raw, *, phase, binding):
    value = _json(raw)
    if (type(value) is not dict or set(value) != {"schema", "delivery_state"}
            or type(value["schema"]) is not int or value["schema"] != 1):
        raise ValueError
    state = value["delivery_state"]
    if (type(state) is not dict or set(state) != {"binding", "phase", "receipt"}
            or state["phase"] != phase or state["binding"] != binding
            or type(state["receipt"]) is not dict):
        raise ValueError
    return state


def _forbidden(*_args, **_kwargs):
    raise AcceptedDeliveryInputsError()


class AcceptedDeliveryInputs:
    """Registered process-local evidence; repr never reveals private contents."""

    def __repr__(self):
        return "AcceptedDeliveryInputs(<redacted>)"

    def assert_unchanged(self):
        try:
            if type(self) is not AcceptedDeliveryInputs:
                return False
            baseline = _REGISTERED.get(self)
            if baseline is None:
                return False
            digest, snapshots, acl_checker, original = baseline
            if self.private_inputs is not original or original.assert_unchanged() is not True:
                return False
            if self._digest() != digest:
                return False
            return all(_read_snapshot_now(fp, maximum=maximum, acl_checker=acl_checker) == fp
                       for fp, maximum in snapshots)
        except Exception:
            return False

    def _digest(self):
        return hashlib.sha256(_canonical({
            "authority": self.authority, "accepted": self.accepted,
            "binding": self.binding, "target_template": self.target_template,
            "update_state": self.update_state, "capsule": self.capsule,
            "manifest": self.manifest_raw.decode("ascii"),
            "invitation_jwks_sha256": hashlib.sha256(self.invitation_jwks).hexdigest(),
            "mapit_jwks_sha256": hashlib.sha256(self.mapit_jwks).hexdigest(),
            "archive_sha256": hashlib.sha256(self.archive_bytes).hexdigest(),
        })).hexdigest()


def load_accepted_owner_delivery(*, delivery_root: Path, private_paths,
                                acl_checker=None) -> AcceptedDeliveryInputs:
    """Load terminal evidence with original, not renewed, delivery metadata.

    Stored issuer JWKS are replayed only as artifact inputs, not fresh OAuth
    verification keys. No HTTP request is necessary to reconstruct this archive.
    """
    try:
        root = Path(delivery_root)
        snapshots = []
        def read(relative, maximum):
            _resolved, raw, fingerprint = _snapshot(root / relative,
                maximum=maximum, acl_checker=acl_checker)
            snapshots.append((fingerprint, maximum))
            return raw

        authority = _validate_authority(_json(read("authorization.json", 32 * 1024)))
        prior = _json(read("inputs/prior-template.json", 64 * 1024))
        summary = _json(read("inputs/archive-summary.json", 16 * 1024))
        manifest = read("inputs/manifest.json", 2048)
        invitation_jwks = read("inputs/invitation-jwks.json", 32 * 1024)
        mapit_jwks = read("inputs/mapit-jwks.json", 32 * 1024)
        archive = read("runtime.zip", _MAX_ARCHIVE_BYTES)
        artifact_raw = read("artifact-intent/rehearsal-state.json", 128 * 1024)
        update_raw = read("update-intent/rehearsal-state.json", 128 * 1024)
        capsule = _json(read("observation-capsule.json", 32 * 1024))
        # Only fixed original issuer URLs can resolve to these stored public
        # snapshots. Their hashes are pinned again by the delivery constructor.
        owner_url = _issuer_jwks_url(
            "https://cognito-idp.eu-west-1.amazonaws.com/" + authority["owner_pool_id"])
        config = _json(_snapshot(Path(private_paths["public_config_path"]),
            maximum=16 * 1024, acl_checker=acl_checker)[1])
        mapit_url = _issuer_jwks_url(
            "https://cognito-idp.eu-west-1.amazonaws.com/" + config["user_pool_id"])
        def stored_jwks(url):
            if url == owner_url:
                return invitation_jwks
            if url == mapit_url and mapit_url != owner_url:
                return mapit_jwks
            raise ValueError
        original = load_owner_enrolled_private_inputs(**private_paths,
            prior_template=prior, source_sha=authority["source_sha"],
            acl_checker=acl_checker, jwks_fetcher=stored_jwks)
        assembled = assemble_delivery_metadata(manifest_inputs=original.manifest_inputs,
            prior_template=prior, runtime_binding=original.runtime_binding,
            run_id=authority["run_id"], ci_run_id=authority["ci_run_id"],
            start=authority["authorized_from_epoch"], end=authority["authorized_until_epoch"],
            execution_start=authority["execution_start_epoch"],
            execution_end=authority["execution_end_epoch"])
        if assembled["authority"] != authority or assembled["manifest_raw"] != manifest:
            raise ValueError
        # Construction performs pure structural/archive/target validation only.
        # Every IO callback is fenced; do NOT invoke the delivery methods here.
        coordinator = OwnerEnrolledClosedDelivery(authority=authority,
            accepted=assembled["accepted"], prior_template=prior,
            mapit_bootstrap_template=original.bootstrap_template,
            manifest_raw=manifest, invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
            archive_bytes=archive, archive_summary=summary,
            artifact_journal=object(), update_journal=object(),
            source_check=_forbidden, protection_check=_forbidden,
            current_state=_forbidden, publish_once=_forbidden, update_once=_forbidden)
        artifact = _terminal(artifact_raw, phase="published", binding=coordinator.binding)
        if artifact["receipt"] != coordinator._expected_artifact_receipt():
            raise ValueError
        update = _terminal(update_raw, phase="accepted", binding=coordinator.binding)
        validate_capsule_for_accepted_update(capsule, delivery_binding=coordinator.binding,
                                            accepted_update_state=update)
        result = AcceptedDeliveryInputs()
        result.authority = authority
        result.accepted = assembled["accepted"]
        result.binding = coordinator.binding
        result.target_template = coordinator.target
        result.update_state = update
        result.capsule = capsule
        result.manifest_raw = manifest
        result.invitation_jwks = invitation_jwks
        result.mapit_jwks = mapit_jwks
        result.archive_bytes = archive
        result.private_inputs = original
        _REGISTERED[result] = (result._digest(), tuple(snapshots), acl_checker, original)
        if result.assert_unchanged() is not True:
            raise ValueError
        return result
    except Exception:
        raise AcceptedDeliveryInputsError() from None
