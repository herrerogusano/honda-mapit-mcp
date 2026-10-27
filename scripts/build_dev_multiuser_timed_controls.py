"""Fixed five-minute independent DEV stop, without another Lambda or timer.

The existing state machine gains one bounded opt-in wait. Empty EventBridge
tripwire input still takes the immediate shutdown path. Arbitrary durations,
timestamps, reopening and other project targets are not accepted.
"""
import copy
import json

from scripts.build_aws_retained_dev_support import build_retained_dev_controls


def build_dev_multiuser_timed_controls(api_id):
    template = copy.deepcopy(build_retained_dev_controls(api_id))
    resources = template["Resources"]
    machine = resources["ShutdownStateMachine"]["Properties"]
    # DefinitionString is a fixed JSON ASL string, not an arbitrary operator
    # definition. Keep all original stop/readback states byte-identical.
    definition = json.loads(machine["DefinitionString"])
    first = definition["StartAt"]
    definition["States"]["ChooseBoundedDevWait"] = {
        "Type": "Choice", "Choices": [{"And": [
            {"Variable": "$.bounded_dev_probe", "IsPresent": True},
            {"Variable": "$.bounded_dev_probe", "IsBoolean": True},
            {"Variable": "$.bounded_dev_probe", "BooleanEquals": True}],
            "Next": "WaitFiveMinutes"}], "Default": first}
    definition["States"]["WaitFiveMinutes"] = {"Type": "Wait", "Seconds": 300, "Next": first}
    definition["StartAt"] = "ChooseBoundedDevWait"
    definition["TimeoutSeconds"] += 300
    machine["DefinitionString"] = json.dumps(definition, separators=(",", ":"))
    template["Metadata"].update({"FixedProbeWaitSeconds": 300, "TripwireRemainsImmediate": True,
                                  "NoNewResource": True, "NotDeployReady": True})
    return template
