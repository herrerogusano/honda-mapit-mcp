"""Independent network-bound checks for geographic service execution."""

from __future__ import annotations

import pytest

import mapit.services as services_module
from mapit.services import MapitServices, ServiceError


AREA = {"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]]}


def _route(route_id: str):
    return {
        "id": route_id,
        "startedAt": "2026-01-10T00:00:00Z",
        "distance": 1000,
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [
                {
                    "type": "Feature",
                    "properties": {"inferred": False, "name": "private-label-canary"},
                    "geometry": {"type": "LineString", "coordinates": [[1, 1], [3, 3]]},
                }
            ],
        },
    }


class _Client:
    def __init__(self):
        self.geo_calls = []

    def get_core(self, path, *, params=None, max_response_bytes=None):
        return {"vehicles": [{"id": "synthetic-vehicle"}]}

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        self.geo_calls.append((path, params))
        if len(self.geo_calls) == 1:
            return {"data": [_route("synthetic-route") ]}
        return {"data": []}


def test_work_budget_exhaustion_stops_before_fetching_a_later_month(monkeypatch):
    client = _Client()
    service = MapitServices(client)
    monkeypatch.setattr(services_module, "MAX_GEOGRAPHIC_BATCH_OPERATIONS", 1)
    with pytest.raises(ServiceError) as error:
        service.get_geographic_summary("2026-01-01", "2026-03-01", AREA)
    assert error.value.code == "geometry_budget_exceeded"
    assert len(client.geo_calls) == 1
    assert client.geo_calls[0][0] == "/v1/routes"
