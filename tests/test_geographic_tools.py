from __future__ import annotations

import pytest
from mcp import Client

from mapit.mcp_server import create_server
from mapit.services import GeographicRouteSummary


class GeoServices:
    def __init__(self):
        self.calls = []

    def get_geographic_summary(self, from_time, to_time, area, area_source):
        self.calls.append((from_time, to_time, area_source))
        return GeographicRouteSummary(
            from_time=from_time,
            to_time=to_time,
            area_source=area_source,
            area_type="MultiPolygon",
            matched_routes=0,
            fully_inside_routes=0,
            outside_routes=0,
            crossing_routes=0,
            unknown_routes=0,
            fully_inside_distance=0,
            inferred_marked_inside_routes=0,
            not_marked_inferred_inside_routes=0,
            inference_unknown_inside_routes=0,
        )

    def get_summer_geographic_summary(self, area, year, *, area_source):
        self.calls.append((year, area_source))
        return GeographicRouteSummary(
            from_time="2026-05-31T22:00:00.000Z",
            to_time="2026-08-31T22:00:00.000Z",
            area_source=area_source,
            area_type="MultiPolygon",
            matched_routes=0,
            fully_inside_routes=0,
            outside_routes=0,
            crossing_routes=0,
            unknown_routes=0,
            fully_inside_distance=0,
            inferred_marked_inside_routes=0,
            not_marked_inferred_inside_routes=0,
            inference_unknown_inside_routes=0,
        )


class Provider:
    def __init__(self):
        self.service = GeoServices()
        self.gets = 0

    def get(self):
        self.gets += 1
        return self.service


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_geographic_tools_are_opt_in_and_default_tool_contract_stays_ten():
    async with Client(create_server(Provider())) as client:
        default = await client.list_tools()
    assert len(default.tools) == 10
    assert "geographic_summary" not in {item.name for item in default.tools}

    async with Client(create_server(Provider(), geographic_queries=True)) as client:
        enabled = await client.list_tools()
    names = {item.name for item in enabled.tools}
    assert len(names) == 12
    assert {"geographic_summary", "summer_geographic_summary"} <= names


@pytest.mark.anyio
async def test_tool_rejects_unknown_area_and_bad_window_before_provider_get():
    provider = Provider()
    async with Client(create_server(provider, geographic_queries=True)) as client:
        bad_areas = [
            await client.call_tool(
                "geographic_summary",
                {"area_name": area, "from_time": "2026-01-01", "to_time": "2026-02-01"},
            )
            for area in ("not-menorca", "Sabadell", "Barcelona 10 km", "alrededores")
        ]
        bad_window = await client.call_tool(
            "geographic_summary",
            {"area_name": "menorca", "from_time": "2026-01-01", "to_time": "2026-06-01"},
        )
        bad_year = await client.call_tool("summer_geographic_summary", {"area_name": "menorca", "year": 2040})
    assert all(result.is_error for result in bad_areas) and bad_window.is_error and bad_year.is_error
    assert provider.gets == 0


@pytest.mark.anyio
async def test_named_amb_area_and_barcelona_select_distinct_registry_sources_before_reads():
    pytest.importorskip("shapely")
    provider = Provider()
    async with Client(create_server(provider, geographic_queries=True)) as client:
        amb = await client.call_tool(
            "geographic_summary",
            {"area_name": "Àrea Metropolitana de Barcelona", "from_time": "2026-01-01", "to_time": "2026-02-01"},
        )
        city = await client.call_tool(
            "geographic_summary",
            {"area_name": "barcelona", "from_time": "2026-01-01", "to_time": "2026-02-01"},
        )
        surroundings = await client.call_tool(
            "geographic_summary",
            {"area_name": "alrededores", "from_time": "2026-01-01", "to_time": "2026-02-01"},
        )
    assert not amb.is_error and not city.is_error
    assert surroundings.is_error
    assert provider.gets == 2
    assert provider.service.calls[0][2] == "ign_amb_36_municipalities_union_2026_10_03"
    assert provider.service.calls[1][2] == "ign_amb_municipality_34090808019_2026_10_03"


@pytest.mark.anyio
async def test_menorca_public_area_is_loaded_before_service_and_tool_output_has_no_geometry():
    # This positive optional-engine case runs in the dedicated geography job;
    # ordinary runtime jobs intentionally do not install the geography extra.
    pytest.importorskip("shapely")
    provider = Provider()
    async with Client(create_server(provider, geographic_queries=True)) as client:
        result = await client.call_tool(
            "geographic_summary",
            {"area_name": "Menorca", "from_time": "2026-01-01", "to_time": "2026-02-01"},
        )
    assert not result.is_error, result.content
    assert provider.gets == 1
    text = str(result.structured_content)
    assert "menorca" in text
    assert "features" not in text and "[[" not in text


def test_default_server_does_not_import_optional_geometry_engine(monkeypatch):
    import builtins

    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name.endswith("geography_engine") or name.endswith("geographic_tools"):
            raise AssertionError("default server must not import the optional geography engine")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    create_server(Provider())
