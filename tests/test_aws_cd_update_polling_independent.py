"""Independent checks that cleanup polling still requires final readbacks."""
import copy
import hashlib
import json

import pytest

from mapit.aws_prod_geography_upgrade import ProdGeographyUpgradeError
from test_aws_cd_recovery_independent import CloudFormation
from test_aws_prod_geography_upgrade import make_core


@pytest.mark.parametrize("tamper", [None, "template", "function"])
def test_cleanup_transition_requires_exact_completed_template_and_closed_function(tamper):
    core, journal = make_core(retained_recovery=True)
    core._step_started = core.monotonic()
    state = core._save_new_state()
    tripwire = {"fixed": True}
    state.update(preflight_verified=True, close_verified=True,
                 update_intent={"client_request_token": "00000000-0000-4000-8000-000000000000"},
                 update_acknowledged=True,
                 tripwire_fingerprint=hashlib.sha256(json.dumps(
                     tripwire, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest())
    journal.save(state)
    cf = CloudFormation(core, "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", resource_status="UPDATE_COMPLETE")
    core.clients["cloudformation"] = cf
    reads = []

    def template(**kwargs):
        cf.calls.append(("get_template", kwargs))
        body = copy.deepcopy(core.new_template)
        if tamper == "template":
            body["Resources"]["McpHandler"]["Properties"]["Timeout"] = 16
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "TemplateBody": body}

    def function(**kwargs):
        reads.append("function")
        assert kwargs == {"zip_digest": core.new_zip, "manifest_digest": core.new_manifest, "reserve_zero": True}
        if tamper == "function":
            raise ProdGeographyUpgradeError("function_code_mismatch")
        return 0

    cf.get_template = template
    core._api = lambda **kwargs: reads.append(("api", kwargs))
    core._function = function
    core._capacity = lambda: reads.append("capacity")
    core._tripwire = lambda **kwargs: tripwire
    pending = core.run_step("check-update")
    assert pending["category"] == "update_pending" and not reads
    assert journal.load().get("update_verified") is not True
    assert [name for name, _ in cf.calls] == ["describe_stacks"]

    cf.status = "UPDATE_COMPLETE"
    completed = core.run_step("check-update")
    if tamper is None:
        assert completed.get("verified") is True
        assert journal.load()["update_verified"] is True
        assert reads == [("api", {"closed": True}), "function", "capacity"]
    else:
        assert completed.get("verified") is not True
        assert completed["category"] == ("template_mismatch" if tamper == "template" else "function_code_mismatch")
        assert journal.load().get("update_verified") is not True
    assert [name for name, _ in cf.calls][:3] == ["describe_stacks", "describe_stacks", "get_template"]
