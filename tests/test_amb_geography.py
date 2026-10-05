from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

pytest.importorskip("shapely")

from mapit.geographic_tools import (
    _AMB_MUNICIPALITIES,
    _AREA_BY_NORMALIZED_NAME,
    _AreaSelection,
    _load_selected_area,
    _normalize_area_name,
    _register,
    _resolve_area,
)
from mapit.geography_engine import (
    AMB_AREA_VERSION,
    AMB_EXPECTED_RINGS,
    AMB_EXPECTED_VERTICES,
    AMB_FEATURE_CODES,
    AMB_GEOJSON_SHA256,
    load_frozen_amb_area,
)
from mapit.services import ServiceError

ASSET = Path(__file__).parents[1] / "src" / "mapit" / "data" / "amb-ign-20261003.geojson"


def test_frozen_amb_asset_has_exact_pinned_codes_counts_and_valid_union():
    raw = ASSET.read_bytes()
    assert 0 < len(raw) <= 1024 * 1024
    assert hashlib.sha256(raw).hexdigest() == AMB_GEOJSON_SHA256
    area = load_frozen_amb_area(raw, AMB_FEATURE_CODES)
    assert area.source_version == AMB_AREA_VERSION
    assert area.feature_count == 36
    assert area.vertex_count == AMB_EXPECTED_VERTICES == 32_299
    assert area.ring_count == AMB_EXPECTED_RINGS == 38
    assert area.geometry.geom_type == "MultiPolygon"
    assert area.geometry.is_valid
    assert "41." not in repr(area) and "2." not in repr(area)


def test_barcelona_selection_is_one_exact_ign_code_and_is_not_the_amb_union():
    raw = ASSET.read_bytes()
    barcelona = load_frozen_amb_area(raw, frozenset({"34090808019"}))
    whole_amb = load_frozen_amb_area(raw, AMB_FEATURE_CODES)
    assert barcelona.feature_count == 1
    assert barcelona.source_version.endswith(":34090808019")
    assert barcelona.geometry.is_valid
    assert not barcelona.geometry.equals(whole_amb.geometry)


def test_registry_contains_union_city_and_each_of_the_36_named_municipalities():
    selections = {item.key for item in _AREA_BY_NORMALIZED_NAME.values()}
    assert "amb" in selections
    assert "amb-34090808019" in selections
    assert {f"amb-{code}" for code in AMB_FEATURE_CODES} <= selections
    assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name("Barcelona")].key == "amb-34090808019"
    assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name("ÀREA METROPOLITANA DE BARCELONA")].key == "amb"
    assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name("Badia del Valles")].key == "amb-34090808904"
    assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name("Menorca")].key == "menorca"
    for name, code in _AMB_MUNICIPALITIES:
        assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name(name)].key == f"amb-{code}"


def test_prod_builder_pins_the_same_amb_asset_as_the_runtime_engine():
    from scripts import build_aws_prod_runtime

    assert build_aws_prod_runtime.GEOGRAPHY_AMB_ASSET == "data/amb-ign-20261003.geojson"
    assert build_aws_prod_runtime.GEOGRAPHY_AMB_ASSET_SHA256 == AMB_GEOJSON_SHA256


def test_alrededores_and_arbitrary_geojson_names_are_not_resolved():
    for value in ("alrededores", "Barcelona 10km", "https://example.invalid/area", ""):
        with pytest.raises(ServiceError) as error:
            _resolve_area(value)
        assert error.value.code == "unknown_geographic_area"


def test_registry_rejects_normalized_alias_collisions_and_is_frozen():
    menorca = _AREA_BY_NORMALIZED_NAME[_normalize_area_name("Menorca")]
    with pytest.raises(RuntimeError, match="fixed geographic registry alias collision"):
        _register(_AreaSelection("amb-test", frozenset({"34090808019"}), "test"), "MENORCA")
    assert _AREA_BY_NORMALIZED_NAME[_normalize_area_name("Menorca")] == menorca
    with pytest.raises(TypeError):
        _AREA_BY_NORMALIZED_NAME["invented area"] = menorca


def test_selected_public_geometry_cache_is_bounded_to_two_entries():
    _load_selected_area.cache_clear()
    _resolve_area("Barcelona")
    _resolve_area("Badalona")
    _resolve_area("AMB")
    assert _load_selected_area.cache_info().maxsize == 2
    assert _load_selected_area.cache_info().currsize == 2
    _load_selected_area.cache_clear()
