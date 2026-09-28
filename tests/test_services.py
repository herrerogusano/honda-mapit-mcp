from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mapit.services import (
    DateRangeInput,
    MapitServices,
    ServiceError,
    _number,
    split_month_windows,
)


class RecordingClient:
    def __init__(self, *, summary=None, detail=None, route_windows=None, route_detail=None):
        self.summary = summary or {
            "vehicles": [
                {
                    "id": "vehicle/one",
                    "km": 123.0,
                    "product": "connected",
                    "device": {
                        "state": {
                            "status": "AT_REST",
                            "speed": 0,
                            "battery": 77,
                            "voltage": 12.4,
                            "lastTs": 1000,
                            "lastCoordTs": 900,
                            "lat": 40.0,
                            "lng": -3.0,
                            "location": "Madrid",
                            "hdop": 1.2,
                            "odometer": None,
                        }
                    },
                    "dealerData": {
                        "name": "Dealer",
                        "shop": {
                            "telephone": "+34 000",
                            "email": "dealer@example.invalid",
                            "openingHours": ["Mo-Fr"],
                            "address": {
                                "streetAddress": "Street",
                                "postalCode": "00000",
                                "addressLocality": "Madrid",
                                "addressRegion": "Madrid",
                                "addressCountry": "ES",
                            },
                        },
                    },
                }
            ]
        }
        self.detail = detail or {
            "id": "vehicle/one",
            "model": "Model",
            "registrationNumber": "REG",
            "vin": "VIN",
            "km": 456,
            "products": ["product-a", "product-b"],
            "productPlanName": "plan",
            "branch": "branch",
        }
        self.route_windows = list(route_windows or [])
        self.route_detail = route_detail or {
            "id": "route/one",
            "distance": 10,
            "startedAt": "2026-01-01T01:00:00Z",
            "endedAt": "2026-01-01T02:00:00Z",
            "complete": True,
            "merged": False,
            "geoJSON": {"type": "FeatureCollection", "features": []},
        }
        self.calls = []

    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("GET", "core", path, params, max_response_bytes))
        return self.summary if path == "/v1/account-summary" else self.detail

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("GET", "geo", path, params, max_response_bytes))
        if path == "/v1/routes":
            return self.route_windows.pop(0) if self.route_windows else {"data": []}
        return self.route_detail


def test_split_month_windows_handles_partial_boundaries():
    start = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    end = datetime(2026, 3, 2, 6, tzinfo=timezone.utc)

    assert split_month_windows(start, end) == [
        (start, datetime(2026, 2, 1, tzinfo=timezone.utc)),
        (datetime(2026, 2, 1, tzinfo=timezone.utc), datetime(2026, 3, 1, tzinfo=timezone.utc)),
        (datetime(2026, 3, 1, tzinfo=timezone.utc), end),
    ]


def test_vehicle_status_is_allowlisted_and_keeps_units_unconfirmed():
    service = MapitServices(RecordingClient())

    result = service.get_vehicle_status()

    assert result.model_dump() == {
        "status": "AT_REST",
        "speed": 0.0,
        "battery": 77.0,
        "voltage": 12.4,
        "last_communication": 1000.0,
        "last_coordinate_update": 900.0,
        "position": {"latitude": 40.0, "longitude": -3.0, "label": "Madrid", "gps_accuracy": 1.2},
        "odometer": 123.0,
        "units_confirmed": False,
    }


def test_vehicle_details_encodes_id_and_normalizes_dealer():
    client = RecordingClient()
    service = MapitServices(client)

    result = service.get_vehicle_details()

    assert client.calls[1][2] == "/v1/vehicles/vehicle%2Fone"
    assert result.product == "product-a, product-b"
    assert result.dealer is not None
    assert result.dealer.address == "Street, 00000, Madrid, Madrid, ES"
    assert result.units_confirmed is False


def test_list_routes_splits_months_deduplicates_and_sorts():
    first = {
        "data": [
            {"id": "route-b", "startedAt": "2026-01-20T00:00:00Z", "distance": 2},
            {"id": "route-a", "startedAt": "2026-01-10T00:00:00Z", "distance": 1},
        ]
    }
    second = {
        "data": [
            {"id": "route-b", "startedAt": "2026-01-20T00:00:00Z", "distance": 2},
            {"id": "route-c", "startedAt": "2026-02-10T00:00:00Z", "distance": 3},
        ]
    }
    client = RecordingClient(route_windows=[first, second])

    result = MapitServices(client).list_routes("2026-01-01", "2026-03-01")

    route_calls = [call for call in client.calls if call[1] == "geo"]
    assert len(route_calls) == 2
    assert route_calls[0][3] == {
        "vehicleId": "vehicle/one",
        "from": "2026-01-01T00:00:00.000Z",
        "to": "2026-02-01T00:00:00.000Z",
    }
    assert [route.route_id for route in result.routes] == ["route-a", "route-b", "route-c"]
    assert result.matched_routes == 3
    assert result.completeness == "unverified"
    assert result.metric_unit == "mapit_native_unconfirmed"


@pytest.mark.parametrize(
    ("start", "end", "code"),
    [
        ("bad", "2026-01-02", "invalid_date_range"),
        ("2026-01-02", "2026-01-01", "invalid_date_range"),
        ("2024-01-01", "2026-01-01", "period_too_large"),
        ("2026-01-01T00:00:00", "2026-01-02T00:00:00Z", "invalid_date_range"),
    ],
)
def test_invalid_period_stops_before_upstream_data_calls(start, end, code):
    client = RecordingClient()

    with pytest.raises(ServiceError) as error:
        MapitServices(client).list_routes(start, end)

    assert error.value.code == code
    assert client.calls == []


def test_route_cursor_fails_closed_instead_of_claiming_completeness():
    secret_cursor = "cursor-secret-value"
    client = RecordingClient(route_windows=[{"data": [], "lastEvaluatedKey": {"secret": secret_cursor}}])

    with pytest.raises(ServiceError) as error:
        MapitServices(client).list_routes("2026-01-01", "2026-02-01")

    assert error.value.code == "pagination_unsupported"
    assert secret_cursor not in str(error.value)


def test_vehicle_status_preserves_zero_odometer_without_vehicle_km_fallback():
    client = RecordingClient()
    client.summary["vehicles"][0]["device"]["state"]["odometer"] = 0

    result = MapitServices(client).get_vehicle_status()

    assert result.odometer == 0.0


def test_number_rejects_integer_that_overflows_float_conversion():
    assert _number(10**10000) is None


def test_distance_fails_closed_when_any_route_has_no_distance():
    client = RecordingClient(route_windows=[{"data": [{"id": "a"}, {"id": "b", "distance": 10}]}])

    with pytest.raises(ServiceError) as error:
        MapitServices(client).get_distance("2026-01-01", "2026-02-01")

    assert error.value.code == "distance_unavailable"


def test_route_detail_uses_current_encoded_get_contract():
    client = RecordingClient()

    result = MapitServices(client).get_route_detail("route/one ?")

    assert client.calls[-1][0:4] == (
        "GET",
        "geo",
        "/v1/vehicles/vehicle%2Fone/routes/route%2Fone%20%3F",
        {"includeStats": "true"},
    )
    assert result.geojson == {"type": "FeatureCollection", "features": []}


def test_distance_comparison_uses_native_values_without_inventing_units():
    client = RecordingClient(
        route_windows=[
            {"data": [{"id": "a", "distance": 10}]},
            {"data": [{"id": "b", "distance": 15}]},
        ]
    )
    service = MapitServices(client)

    result = service.compare_distance_periods(
        DateRangeInput(from_time="2026-01-01", to_time="2026-02-01"),
        DateRangeInput(from_time="2026-02-01", to_time="2026-03-01"),
    )

    assert result.period_a.distance == 10
    assert result.period_b.distance == 15
    assert result.absolute_difference == 5
    assert result.percentage_difference == 50
    assert result.metric_unit == "mapit_native_unconfirmed"


def test_only_read_methods_are_required_by_the_service_layer():
    client = RecordingClient(route_windows=[{"data": []}])
    service = MapitServices(client)

    service.get_vehicle_status()
    service.get_vehicle_details()
    service.list_routes("2026-01-01", "2026-02-01")
    service.get_route_detail("route")

    assert {call[0] for call in client.calls} == {"GET"}
