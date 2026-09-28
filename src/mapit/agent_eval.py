"""Deterministic, model-free evaluator for the Phase 4 agent contract."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .agent import AgentAnswer, READ_ONLY_TOOL_NAMES

EVAL_CLASSES = (
    "direct_single_tool",
    "multi_tool",
    "period_comparison",
    "ambiguous_period",
    "unavailable_capability",
    "tool_error_or_partial",
)


class SyntheticToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    args: dict[str, Any] = Field(default_factory=dict)


class SyntheticToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    status: str


class SyntheticRun(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    answer: AgentAnswer
    used_tool_names: list[str]
    tool_calls: list[SyntheticToolCall]
    tool_results: list[SyntheticToolResult] = Field(default_factory=list)


class ArgumentConstraint(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    case_id: str
    class_name: str
    question: str
    allowed_tools: list[str]
    required_tools: list[str]
    forbidden_tools: list[str]
    argument_constraints: list[ArgumentConstraint] = Field(default_factory=list)
    required_caveats: list[str] = Field(default_factory=list)
    forbidden_claims: list[str] = Field(default_factory=list)
    needs_clarification: bool
    max_tool_calls: int = Field(ge=0)
    synthetic_run: SyntheticRun


class EvaluationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: str
    class_name: str
    passed: bool
    failures: tuple[str, ...]


class DatasetEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    success: bool
    total_cases: int
    passed_cases: int
    failed_cases: int
    class_counts: dict[str, int]
    results: tuple[EvaluationResult, ...]


def normalize_arguments(value: Any, *, key: str | None = None) -> Any:
    """Canonicalize synthetic tool arguments without calling a provider."""
    if isinstance(value, Mapping):
        return {str(name): normalize_arguments(item, key=str(name)) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [normalize_arguments(item) for item in value]
    if isinstance(value, str):
        text = value.strip()
        if key in {"from_time", "to_time"}:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed.utcoffset() is not None:
                    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            except ValueError:
                pass
        return text
    return value


def _contains_mapping(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
    for key, value in expected.items():
        if key not in actual:
            return False
        if isinstance(value, Mapping) and isinstance(actual[key], Mapping):
            if not _contains_mapping(value, actual[key]):
                return False
        elif actual[key] != value:
            return False
    return True


_UNIT_CLAIM = re.compile(
    r"\b(?:\d+(?:[.,]\d+)?\s*)?(?:km/h|kmh|kph|km|kil[oó]metros?|kilomet(?:er|re)s?|mph|miles?|mi|meters?|metres?|m/s)\b",
    re.IGNORECASE,
)
_UNSUPPORTED_PHRASES = (
    "historial completo",
    "complete history",
    "todos los recorridos",
    "all history",
)
_REALTIME_CLAIM = re.compile(r"\b(?:real[- ]?time|realtime|tiempo real)\b", re.IGNORECASE)
# Versioned lexical denylist.  This is intentionally conservative: it does not
# try to infer whether a completeness term was negated or merely quoted.
_COMPLETENESS_CLAIM = re.compile(
    r"\b(?:exhaustive|comprehensive|exhaustiv[oa]s?|complet[oa]s?|integral(?:es)?)\b|"
    r"\b(?:all|every|each|complete|entire|full)\s+(?:the\s+)?(?:route\s+)?"
    r"(?:history|data|records?|routes?|dataset)\b|"
    r"\b(?:route\s+)?(?:history|data|records?|routes?|dataset)"
    r"(?:\s+\w+){0,6}\s+(?:complete|full|all|exhaustive|comprehensive)\b|"
    r"\b(?:covers?|covered|coverage)\s+(?:of\s+)?(?:all|every|each)\s+(?:the\s+)?routes?\b|"
    r"\b100\s*%\s*(?:of\s+)?(?:the\s+)?routes?\b|"
    r"\bno\s+routes?\s+(?:\w+\s+){0,2}(?:missing|omitted)\b|"
    r"\b(?:todo|toda|todos|todas)\s+(?:los\s+|las\s+)?"
    r"(?:recorridos?|rutas?|historial|datos?|registros?|conjunto\s+de\s+datos)\b|"
    r"\b(?:cubre|cubierto|cobertura)\s+(?:de\s+)?(?:todas?|cada)\s+(?:las\s+)?rutas?\b|"
    r"\b100\s*%\s*(?:de\s+)?(?:las\s+)?rutas?\b|"
    r"\b(?:ninguna|ningún)\s+ruta\s+(?:\w+\s+){0,2}(?:falta|omitida|ausente)\b|"
    r"\bno\s+(?:falta|se\s+omite)\s+(?:ninguna|ningún)\s+ruta\b|"
    r"\b(?:historial|datos?|rutas?|recorridos?|registros?|conjunto\s+de\s+datos)\s+"
    r"(?:completo|completa|exhaustivo|exhaustiva|integral)\b",
    re.IGNORECASE,
)


def _unsupported_claim(text: str) -> bool:
    if _UNIT_CLAIM.search(text):
        return True
    lowered = text.lower()
    for phrase in _UNSUPPORTED_PHRASES:
        if phrase in lowered:
            return True
    return bool(_COMPLETENESS_CLAIM.search(text) or _REALTIME_CLAIM.search(text))


def evaluate_case(case: EvalCase | Mapping[str, Any], run: SyntheticRun | Mapping[str, Any] | None = None) -> EvaluationResult:
    """Evaluate one synthetic record using only declared contract metadata."""
    if isinstance(case, Mapping) and run is None:
        raw_run = case.get("synthetic_run")
        if isinstance(raw_run, Mapping):
            try:
                AgentAnswer.model_validate(raw_run.get("answer"))
            except ValidationError:
                return EvaluationResult(
                    case_id=str(case.get("case_id", "invalid_case")),
                    class_name=str(case.get("class_name", "invalid")),
                    passed=False,
                    failures=("answer_schema",),
                )
    try:
        selected = case if isinstance(case, EvalCase) else EvalCase.model_validate(case)
    except ValidationError:
        return EvaluationResult(case_id="invalid_case", class_name="invalid", passed=False, failures=("invalid_case",))
    failures: list[str] = []
    try:
        record = selected.synthetic_run if run is None else SyntheticRun.model_validate(run)
    except ValidationError:
        return EvaluationResult(
            case_id=selected.case_id,
            class_name=selected.class_name,
            passed=False,
            failures=("answer_schema",),
        )
    if selected.class_name not in EVAL_CLASSES:
        failures.append("unknown_case_class")
    calls = record.tool_calls
    call_names = [call.name for call in calls]
    unique_call_names = list(dict.fromkeys(call_names))
    if any(name not in selected.allowed_tools for name in call_names):
        failures.append("tool_not_allowed")
    if any(name in selected.forbidden_tools for name in call_names):
        failures.append("forbidden_tool_used")
    if any(name not in READ_ONLY_TOOL_NAMES for name in call_names):
        failures.append("tool_not_read_only")
    if any(name not in unique_call_names for name in selected.required_tools):
        failures.append("required_tool_missing")
    if len(calls) > selected.max_tool_calls:
        failures.append("too_many_tool_calls")
    if list(record.used_tool_names) != unique_call_names:
        failures.append("used_tool_names_mismatch")
    actual_by_name = {call.name: normalize_arguments(call.args) for call in calls}
    for constraint in selected.argument_constraints:
        expected = normalize_arguments(constraint.args)
        actual = actual_by_name.get(constraint.tool)
        if not isinstance(actual, Mapping) or not _contains_mapping(expected, actual):
            failures.append("argument_constraint_failed")
    answer_text = " ".join([record.answer.answer, *record.answer.caveats])
    lowered_answer = answer_text.lower()
    for caveat in selected.required_caveats:
        if caveat.lower() not in lowered_answer:
            failures.append("required_caveat_missing")
    for claim in selected.forbidden_claims:
        if claim.lower() in lowered_answer:
            failures.append("forbidden_claim")
    if _unsupported_claim(answer_text):
        failures.append("unsupported_claim")
    if record.answer.needs_clarification is not selected.needs_clarification:
        failures.append("clarification_mismatch")
    call_counts = {name: call_names.count(name) for name in unique_call_names}
    result_counts: dict[str, int] = {}
    for result in record.tool_results:
        result_counts[result.name] = result_counts.get(result.name, 0) + 1
        if result.status not in {"ok", "error", "partial"}:
            failures.append("invalid_tool_result")
        if result.name not in call_names:
            failures.append("tool_result_without_call")
        if result.name not in READ_ONLY_TOOL_NAMES:
            failures.append("tool_result_not_read_only")
        if result.status in {"error", "partial"}:
            normalized_caveats = {
                re.sub(r"\s+", "_", caveat.strip().lower())
                for caveat in record.answer.caveats
            }
            required_marker = "tool_error" if result.status == "error" else "partial_result"
            if required_marker not in normalized_caveats:
                failures.append("tool_status_caveat_missing")
    if any(result_counts.get(name, 0) < count for name, count in call_counts.items()):
        failures.append("tool_result_missing")
    return EvaluationResult(
        case_id=selected.case_id,
        class_name=selected.class_name,
        passed=not failures,
        failures=tuple(dict.fromkeys(failures)),
    )


def default_dataset_path() -> Path:
    return Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "phase4-agent-cases.json"


def evaluate_dataset(path: str | Path | None = None) -> DatasetEvaluation:
    """Load and evaluate the versioned synthetic dataset."""
    dataset_path = Path(path) if path is not None else default_dataset_path()
    try:
        raw = json.loads(dataset_path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError
        cases = [EvalCase.model_validate(item) for item in raw]
    except (OSError, ValueError, TypeError, json.JSONDecodeError, ValidationError):
        return DatasetEvaluation(
            success=False,
            total_cases=0,
            passed_cases=0,
            failed_cases=0,
            class_counts={},
            results=(),
        )
    counts = {name: sum(case.class_name == name for case in cases) for name in EVAL_CLASSES}
    ids = [case.case_id for case in cases]
    coverage_ok = len(cases) >= 12 and len(ids) == len(set(ids)) and all(counts[name] >= 2 for name in EVAL_CLASSES)
    results = tuple(evaluate_case(case) for case in cases)
    passed = sum(result.passed for result in results)
    success = coverage_ok and passed == len(results)
    return DatasetEvaluation(
        success=success,
        total_cases=len(results),
        passed_cases=passed,
        failed_cases=len(results) - passed,
        class_counts=counts,
        results=results,
    )


__all__ = [
    "ArgumentConstraint",
    "DatasetEvaluation",
    "EVAL_CLASSES",
    "EvalCase",
    "EvaluationResult",
    "SyntheticRun",
    "SyntheticToolCall",
    "SyntheticToolResult",
    "evaluate_case",
    "evaluate_dataset",
    "normalize_arguments",
]
