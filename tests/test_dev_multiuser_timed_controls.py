import json

from scripts.build_aws_retained_dev_support import build_retained_dev_controls
from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls


def test_only_two_bounded_states_added_and_original_shutdown_unchanged():
    base = build_retained_dev_controls("a1b2c3d4e5")
    new = build_dev_multiuser_timed_controls("a1b2c3d4e5")
    assert set(base["Resources"]) == set(new["Resources"])
    for name, value in base["Resources"].items():
        if name != "ShutdownStateMachine":
            assert new["Resources"][name] == value
    old_asl = json.loads(base["Resources"]["ShutdownStateMachine"]["Properties"]["DefinitionString"])
    new_asl = json.loads(new["Resources"]["ShutdownStateMachine"]["Properties"]["DefinitionString"])
    assert new_asl["TimeoutSeconds"] == old_asl["TimeoutSeconds"] + 300
    for key, value in old_asl["States"].items():
        assert new_asl["States"][key] == value
    assert new_asl["States"]["WaitFiveMinutes"] == {"Type": "Wait", "Seconds": 300, "Next": old_asl["StartAt"]}
    choice = new_asl["States"]["ChooseBoundedDevWait"]
    assert choice["Default"] == old_asl["StartAt"]
    assert choice["Choices"][0]["And"] == [
        {"Variable": "$.bounded_dev_probe", "IsPresent": True},
        {"Variable": "$.bounded_dev_probe", "IsBoolean": True},
        {"Variable": "$.bounded_dev_probe", "BooleanEquals": True}]
    assert "TimestampPath" not in json.dumps(new_asl)
    assert "SecondsPath" not in json.dumps(new_asl)
