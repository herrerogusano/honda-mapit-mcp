from __future__ import annotations

import pytest

from scripts.aws_retained_dev_controls_bootstrap import RetainedDevControlsCoordinator
from test_aws_retained_dev_controls_bootstrap import APP_STACK_ID, CloudFormation, Sfn, _clients, _coordinator, _readback_with, _seed_preflight


@pytest.mark.parametrize(
    "document",
    [
        '{"Statement":1,"Statement":2}',
        '{"Statement":{"Effect":"Allow"},"Statement":{"Effect":"Deny"}}',
    ],
)
def test_iam_policy_document_parser_rejects_duplicate_keys(document):
    assert RetainedDevControlsCoordinator._document(document) is None


def test_iam_policy_document_parser_rejects_malformed_percent_encoding():
    assert RetainedDevControlsCoordinator._document('{"Statement":"%zz"}') is None


def test_unknown_create_reconciliation_state_can_be_reloaded():
    journal = None
    coordinator = _coordinator(journal)
    _seed_preflight(coordinator, coordinator.journal)
    original = coordinator.clients["cloudformation"].create_stack

    def ambiguous(**kwargs):
        coordinator.clients["cloudformation"].created = True
        raise RuntimeError("ambiguous")

    coordinator.clients["cloudformation"].create_stack = ambiguous
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    coordinator.clients["cloudformation"].create_stack = original
    assert coordinator.run_step("readback")["category"] == "readback_verified"
    assert coordinator.run_step("readback")["category"] != "journal_invalid"


def test_stepfunctions_tag_readback_uses_real_lowercase_sdk_shape():
    class RealSdkShapeSfn(Sfn):
        def list_tags_for_resource(self, **kwargs):
            reply = super().list_tags_for_resource(**kwargs)
            reply["tags"] = [{"key": item["Key"], "value": item["Value"]} for item in reply["tags"]]
            return reply

    result = _readback_with(_clients(sfn=RealSdkShapeSfn()))
    assert result["category"] == "readback_verified"

    class DuplicateRealSdkShapeSfn(RealSdkShapeSfn):
        def list_tags_for_resource(self, **kwargs):
            reply = super().list_tags_for_resource(**kwargs)
            reply["tags"].append(dict(reply["tags"][0]))
            return reply

    duplicate = _readback_with(_clients(sfn=DuplicateRealSdkShapeSfn()))
    assert duplicate["category"] == "stack_readback_mismatch"


@pytest.mark.parametrize("field,value", [("Code", {"ZipFile": "private-mutation"}), ("Handler", "private.handler"), ("Environment", {"Variables": {"UNEXPECTED": "1"}})])
def test_initial_app_binding_rejects_runtime_handler_mutations(field, value):
    class MutatedAppTemplate(CloudFormation):
        def get_template(self, **kwargs):
            reply = super().get_template(**kwargs)
            if kwargs.get("StackName") == APP_STACK_ID:
                reply["TemplateBody"]["Resources"]["McpHandler"]["Properties"][field] = value
            return reply

    result = _coordinator(clients=_clients(cfn=MutatedAppTemplate())).run_step("preflight")
    assert result["category"] == "binding_invalid"
