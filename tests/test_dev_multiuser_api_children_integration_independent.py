"""Independent source-order guard for the hosted API-child preflight."""
from __future__ import annotations

import ast
from pathlib import Path

from scripts.dev_multiuser_api_children import verify_empty_api_children


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_dev_multiuser_hosted_acceptance.py"


def _runner_function():
    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    return next(
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "run_hosted_acceptance"
    )


def _call_lines(function, predicate):
    return [node.lineno for node in ast.walk(function) if isinstance(node, ast.Call) and predicate(node)]


def test_api_child_failure_gate_precedes_login_and_user_provisioning():
    function = _runner_function()
    helper = _call_lines(function, lambda node: isinstance(node.func, ast.Name)
                         and node.func.id == "verify_empty_api_children")
    dry_login = _call_lines(function, lambda node: isinstance(node.func, ast.Attribute)
                            and node.func.attr == "dry_login_page")
    later_provision = _call_lines(function, lambda node: (
        isinstance(node.func, ast.Name)
        and node.func.id in {
            "prepare_confirmed_pair_reset", "prepare_confirmed_a_reset",
            "recover_partial_users", "provision_and_login_pair", "reset_a_then_provision_b",
        }
    ))
    assert len(helper) == 1
    assert dry_login and later_provision
    assert helper[0] < min(dry_login)
    assert helper[0] < min(later_provision)

    constants = {node.value for node in ast.walk(function)
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    assert "api_children_readback_failed" in constants


def test_api_child_failure_category_is_stable_and_redacted():
    class FailingApi:
        def get_authorizers(self, **kwargs):
            raise RuntimeError("private endpoint/token must not escape")

        def get_routes(self, **kwargs):
            raise AssertionError("must stop after the first failed read")

        def get_integrations(self, **kwargs):
            raise AssertionError("must stop after the first failed read")

    result = verify_empty_api_children(FailingApi(), api_id="abcdefghij")
    assert result == {"success": False, "category": "api_children_read_failed", "calls": 1}
    assert "private" not in repr(result) and "token" not in repr(result)
