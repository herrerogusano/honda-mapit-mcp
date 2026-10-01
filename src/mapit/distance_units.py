"""Explicit presentation conversion for MAPIT's unconfirmed native distance."""

from __future__ import annotations

import math
from typing import Any, Final

# UI-correlated meter interpretation only; not a provider unit contract.
DISTANCE_CONVERSION_BASIS: Final[str] = "ui_correlated_meter_interpretation_unconfirmed"


def native_distance_to_km(value: Any) -> float | None:
    """Convert a valid non-negative native value under the documented UI interpretation."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        native = float(value)
    except OverflowError:
        return None
    if not math.isfinite(native) or native < 0:
        return None
    converted = native / 1000.0
    return converted if math.isfinite(converted) else None

