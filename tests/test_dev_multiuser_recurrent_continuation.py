from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from scripts.run_dev_multiuser_accepted_continuation import (
    AcceptedContinuationError,
    _valid_platform_preflight,
    _predecessor_mode,
    validate_accepted_pair_lineage,
    validate_recurrent_accepted_pair_lineage,
)
from tests import test_dev_multiuser_accepted_continuation_holdout as accepted
from tests import test_dev_multiuser_confirmed_pair_recovery as pair


def _recurrent_fixture():
    predecessor = accepted._lineage_fixture()
    previous = validate_accepted_pair_lineage(**predecessor)
    original = predecessor["original_creation_users"]
    first = predecessor["first_pair_users"]
    # The recurring reset preserves first-pair creation provenance. The prior
    # accepted pair is separately named as consumed_pair_sha256.
    chain = {
        "first_pair_sha256": previous["first_pair_sha256"],
        "previous_reset_sha256": previous["accepted_reset_sha256"],
        "latest_pair_sha256": previous["accepted_pair_sha256"],
    }
    reset_start = predecessor["accepted_reset"].load()["authorized_until_epoch"] + 100
    # The predecessor reset journal is a checked shape; use a deterministic
    # fresh window after its latest-pair interval.
    reset_start = max(reset_start, previous["accepted_runtime_binding"]["end"] + 100)
    users, reset, _recovery = accepted._completed_reset(
        original, first, source="c" * 40, start=reset_start,
        end=reset_start + 250, chain=chain, include_consumed=True,
    )
    prior_binding = deepcopy(previous["accepted_runtime_binding"])
    current_binding = dict(prior_binding)
    current_binding.update({
        "source": "c" * 40,
        "start": reset_start - 20,
        "end": reset_start + 3_580,
        "prior": prior_binding["target"],
        "target": "f" * 64,
        "token": "dev-multiuser-" + "1" * 32,
    })
    current_runtime = pair.Journal({"phase": "accepted", "binding": current_binding})
    current_manifest = deepcopy(predecessor["accepted_manifest"])
    current_manifest["source_sha"] = "c" * 40
    return predecessor, previous, users, reset, current_runtime, current_manifest


def test_recurrent_lineage_binds_first_pair_and_consumed_predecessor_without_relaxing_history():
    predecessor, previous, users, reset, runtime, manifest = _recurrent_fixture()
    result = validate_recurrent_accepted_pair_lineage(
        current_users=users, current_reset=reset, current_runtime=runtime,
        previous_lineage=previous, previous_manifest=predecessor["accepted_manifest"],
        current_manifest=manifest, account=pair.ACCOUNT, pool=pair.POOL,
    )
    assert result["first_pair_sha256"] == previous["first_pair_sha256"]
    assert result["previous_reset_sha256"] == previous["accepted_reset_sha256"]
    assert result["consumed_pair_sha256"] == previous["accepted_pair_sha256"]
    assert result["accepted_runtime_binding"]["prior"] == previous["accepted_runtime_binding"]["target"]


def test_recurrent_lineage_rejects_wrong_consumed_reset_or_changed_tenant_binding():
    predecessor, previous, users, reset, runtime, manifest = _recurrent_fixture()
    reset.state["consumed_pair_sha256"] = "0" * 64
    try:
        validate_recurrent_accepted_pair_lineage(
            current_users=users, current_reset=reset, current_runtime=runtime,
            previous_lineage=previous, previous_manifest=predecessor["accepted_manifest"],
            current_manifest=manifest, account=pair.ACCOUNT, pool=pair.POOL,
        )
    except AcceptedContinuationError as exc:
        assert exc.category == "history_invalid"
    else:
        raise AssertionError("incorrect consumed-pair binding was accepted")

    predecessor, previous, users, reset, runtime, manifest = _recurrent_fixture()
    manifest["tenants"][1]["key"] = "tenant-" + "3" * 64
    try:
        validate_recurrent_accepted_pair_lineage(
            current_users=users, current_reset=reset, current_runtime=runtime,
            previous_lineage=previous, previous_manifest=predecessor["accepted_manifest"],
            current_manifest=manifest, account=pair.ACCOUNT, pool=pair.POOL,
        )
    except AcceptedContinuationError as exc:
        assert exc.category == "history_invalid"
    else:
        raise AssertionError("changed tenant key was accepted")


def test_platform_preflight_requires_exact_complete_fixed_checks():
    from scripts.probe_aws_dev_multiuser_arm import CHECKS

    good = {"success": True, "category": "multiuser_arm_probe_passed",
            "checks": {name: True for name in CHECKS}, "wheel_count": 28}
    assert _valid_platform_preflight(good)
    assert not _valid_platform_preflight({**good, "checks": {}})
    bad_checks = dict(good["checks"])
    bad_checks[CHECKS[-1]] = False
    assert not _valid_platform_preflight({**good, "checks": bad_checks})
    assert not _valid_platform_preflight({**good, "category": "other"})


def test_predecessor_paths_are_opt_in_all_or_none_and_distinct(tmp_path):
    base = {name: Path(tmp_path / f"{name}.json") for name in (
        "predecessor_users_path", "predecessor_reset_path",
        "predecessor_runtime_path", "predecessor_artifact_dir",
    )}
    assert _predecessor_mode(SimpleNamespace(**{name: None for name in base})) is False
    with_partial = dict(base)
    with_partial["predecessor_artifact_dir"] = None
    try:
        _predecessor_mode(SimpleNamespace(**with_partial))
    except AcceptedContinuationError as exc:
        assert exc.category == "bindings_invalid"
    else:
        raise AssertionError("partial predecessor binding was accepted")
    assert _predecessor_mode(SimpleNamespace(**base)) is True
    duplicate = dict(base)
    duplicate["predecessor_reset_path"] = base["predecessor_users_path"]
    try:
        _predecessor_mode(SimpleNamespace(**duplicate))
    except AcceptedContinuationError as exc:
        assert exc.category == "bindings_invalid"
    else:
        raise AssertionError("aliased predecessor journals were accepted")
