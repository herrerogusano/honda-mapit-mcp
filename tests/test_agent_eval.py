from __future__ import annotations

import pytest

from mapit.agent_eval import evaluate_case, evaluate_dataset, normalize_arguments


def test_synthetic_dataset_has_two_cases_per_contract_class_and_passes():
    result = evaluate_dataset()
    assert result.success is True
    assert result.total_cases >= 12
    assert all(count >= 2 for count in result.class_counts.values())


def test_argument_normalization_handles_date_forms():
    assert normalize_arguments({"from_time": "2026-01-01"}) == {"from_time": "2026-01-01T00:00:00Z"}
    assert normalize_arguments({"to_time": "2026-01-01T01:00:00+01:00"}) == {"to_time": "2026-01-01T00:00:00Z"}


def test_evaluator_fails_closed_for_tool_policy_and_unsupported_claims():
    case = {
        "case_id": "bad",
        "class_name": "direct_single_tool",
        "question": "status",
        "allowed_tools": ["get_vehicle_status"],
        "required_tools": ["get_vehicle_status"],
        "forbidden_tools": [],
        "required_caveats": [],
        "forbidden_claims": [],
        "needs_clarification": False,
        "max_tool_calls": 1,
        "argument_constraints": [],
        "synthetic_run": {
            "answer": {"answer": "It travelled 10 km.", "caveats": [], "needs_clarification": False},
            "used_tool_names": ["get_vehicle_status", "get_vehicle_status"],
            "tool_calls": [{"name": "get_vehicle_status", "args": {}}, {"name": "get_vehicle_status", "args": {}}],
            "tool_results": []
        }
    }
    result = evaluate_case(case)
    assert result.passed is False
    assert "too_many_tool_calls" in result.failures
    assert "unsupported_claim" in result.failures


def test_evaluator_rejects_invalid_structured_answer():
    case = {
        "case_id": "invalid-answer",
        "class_name": "direct_single_tool",
        "question": "status",
        "allowed_tools": [],
        "required_tools": [],
        "forbidden_tools": [],
        "required_caveats": [],
        "forbidden_claims": [],
        "needs_clarification": False,
        "max_tool_calls": 0,
        "argument_constraints": [],
        "synthetic_run": {
            "answer": {"answer": "ok", "caveats": [], "needs_clarification": "false"},
            "used_tool_names": [],
            "tool_calls": [],
            "tool_results": []
        }
    }
    result = evaluate_case(case)
    assert result.passed is False
    assert result.failures == ("answer_schema",)


def test_realtime_term_is_rejected_even_when_capability_is_unavailable():
    case = {
        "case_id": "unavailable-realtime",
        "class_name": "unavailable_capability",
        "question": "subscribe realtime",
        "allowed_tools": [],
        "required_tools": [],
        "forbidden_tools": [],
        "required_caveats": ["unavailable"],
        "forbidden_claims": [],
        "needs_clarification": False,
        "max_tool_calls": 0,
        "argument_constraints": [],
        "synthetic_run": {
            "answer": {"answer": "Realtime subscription is unavailable.", "caveats": ["unavailable"], "needs_clarification": False},
            "used_tool_names": [],
            "tool_calls": [],
            "tool_results": []
        }
    }
    result = evaluate_case(case)
    assert result.passed is False
    assert "unsupported_claim" in result.failures


def _base_case(answer: str, *, calls=None, results=None, caveats=None):
    calls = calls or []
    results = results or []
    return {
        "case_id": "hardening",
        "class_name": "direct_single_tool",
        "question": "status",
        "allowed_tools": ["get_vehicle_status"],
        "required_tools": ["get_vehicle_status"] if calls else [],
        "forbidden_tools": [],
        "required_caveats": [],
        "forbidden_claims": [],
        "needs_clarification": False,
        "max_tool_calls": 2,
        "argument_constraints": [],
        "synthetic_run": {
            "answer": {"answer": answer, "caveats": caveats or [], "needs_clarification": False},
            "used_tool_names": [call["name"] for call in calls],
            "tool_calls": calls,
            "tool_results": results,
        },
    }


def test_evaluator_rejects_unit_and_completion_claim_variants_without_values():
    unit = evaluate_case(_base_case("The distance is measured in kilometers."))
    complete = evaluate_case(_base_case("All route history is complete."))
    unconfirmed = evaluate_case(_base_case("The unit is unconfirmed; no kilometers are asserted."))
    assert "unsupported_claim" in unit.failures
    assert "unsupported_claim" in complete.failures
    assert "unsupported_claim" in unconfirmed.failures


def test_evaluator_requires_corresponding_readonly_results_and_status_acknowledgement():
    calls = [{"name": "get_vehicle_status", "args": {}}]
    missing = evaluate_case(_base_case("Status returned.", calls=calls))
    orphan = evaluate_case(
        _base_case(
            "Status returned.",
            results=[{"name": "delete_everything", "status": "ok"}],
        )
    )
    unacknowledged = evaluate_case(
        _base_case(
            "The tool response was received.",
            calls=calls,
            results=[{"name": "get_vehicle_status", "status": "partial"}],
        )
    )
    assert "tool_result_missing" in missing.failures
    assert "tool_result_without_call" in orphan.failures
    assert "tool_result_not_read_only" in orphan.failures
    assert "tool_status_caveat_missing" in unacknowledged.failures


@pytest.mark.parametrize(
    "claim",
    [
        "measured in kph",
        "measured in miles",
        "measured in mile",
        "measured in mi",
        "measured in meters",
        "measured in metres",
        "measured in m/s",
        "measured in km/h",
    ],
)
def test_evaluator_rejects_unit_assertions_without_numeric_values(claim):
    result = evaluate_case(_base_case(f"The distance is {claim}."))
    assert "unsupported_claim" in result.failures


@pytest.mark.parametrize(
    "claim",
    [
        "The unit is unconfirmed; distance is measured in miles.",
        "The unit is unknown; speed is measured in kph.",
        "The unit is not confirmed; distance is measured in meters.",
    ],
)
def test_evaluator_rejects_unit_mentions_even_in_unconfirmed_context(claim):
    result = evaluate_case(_base_case(claim))
    assert "unsupported_claim" in result.failures


@pytest.mark.parametrize(
    "claim",
    [
        "All route data is complete.",
        "Route data is full.",
        "All records are complete.",
        "Routes are complete.",
        "History is complete.",
    ],
)
def test_evaluator_rejects_completeness_variants(claim):
    result = evaluate_case(_base_case(claim))
    assert "unsupported_claim" in result.failures


@pytest.mark.parametrize(
    "claim",
    [
        "The route set is exhaustive.",
        "The route history is comprehensive.",
        "Every route is covered.",
        "Coverage of all routes is confirmed.",
        "100% of routes are present.",
        "No route is missing.",
        "The entire dataset is available.",
        "Todos los recorridos están completos.",
        "La cobertura incluye todas las rutas.",
        "No falta ninguna ruta.",
        "El historial completo está disponible.",
    ],
)
def test_evaluator_rejects_lexical_completeness_synonyms_and_translations(claim):
    result = evaluate_case(_base_case(claim))
    assert "unsupported_claim" in result.failures


def test_evaluator_rejects_completeness_mentions_even_when_negated_or_unconfirmed():
    for claim in ("Route data is not complete.", "All route data is unconfirmed."):
        result = evaluate_case(_base_case(claim))
        assert "unsupported_claim" in result.failures


def test_conservative_claim_policy_accepts_only_abstract_metadata_forms():
    contaminated = (
        "The unit is unconfirmed; distance is measured in kilometers.",
        "Realtime subscription is unavailable.",
        "All route data is not complete.",
    )
    for claim in contaminated:
        assert "unsupported_claim" in evaluate_case(_base_case(claim)).failures

    allowed = (
        "metric_unit=mapit_native_unconfirmed",
        "The requested capability is unavailable.",
        "completeness=unverified",
    )
    for claim in allowed:
        assert "unsupported_claim" not in evaluate_case(_base_case(claim)).failures


def test_evaluator_requires_exact_normalized_status_caveats():
    calls = [{"name": "get_vehicle_status", "args": {}}]
    error_free = evaluate_case(
        _base_case(
            "The response is error-free.",
            calls=calls,
            results=[{"name": "get_vehicle_status", "status": "error"}],
            caveats=["error-free"],
        )
    )
    no_error = evaluate_case(
        _base_case(
            "No error is reported.",
            calls=calls,
            results=[{"name": "get_vehicle_status", "status": "error"}],
            caveats=["No error"],
        )
    )
    partial_free = evaluate_case(
        _base_case(
            "The result is partial-free.",
            calls=calls,
            results=[{"name": "get_vehicle_status", "status": "partial"}],
            caveats=["partial-free"],
        )
    )
    valid = evaluate_case(
        _base_case(
            "The result is safe to report.",
            calls=calls,
            results=[{"name": "get_vehicle_status", "status": "error"}],
            caveats=["Tool Error"],
        )
    )
    assert "tool_status_caveat_missing" in error_free.failures
    assert "tool_status_caveat_missing" in no_error.failures
    assert "tool_status_caveat_missing" in partial_free.failures
    assert valid.passed is True
