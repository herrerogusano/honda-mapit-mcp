from __future__ import annotations

from datetime import date

from mapit.ledger import DistanceLedger
from mapit.services import MapitServices


ACCOUNT_ID = "synthetic-account"
VEHICLE_ID = "synthetic-vehicle"
KEY = bytes(range(32))
ROUTES = [
    {
        "id": "synthetic-route-1",
        "startedAt": "2026-01-08T04:00:00Z",
        "endedAt": "2026-01-08T04:30:00Z",
        "distance": 4.0,
    },
    {
        "id": "synthetic-route-2",
        "startedAt": "2026-01-19T14:00:00Z",
        "endedAt": "2026-01-19T15:00:00Z",
        "distance": 6.0,
    },
]


class CountingSyntheticClient:
    """Count logical Core/Geo GETs without making a network request."""

    def __init__(self):
        self.logical_gets = 0

    def get_core(self, path, *, max_response_bytes):
        assert path == "/v1/account-summary"
        self.logical_gets += 1
        return {"vehicles": [{"id": VEHICLE_ID, "device": {"state": {}}}]}

    def get_geo(self, path, *, params, max_response_bytes):
        assert path == "/v1/routes"
        assert params["vehicleId"] == VEHICLE_ID
        self.logical_gets += 1
        return {"data": ROUTES}


def test_ten_identical_legacy_queries_vs_setup_and_warm_local_queries(tmp_path):
    client = CountingSyntheticClient()
    service = MapitServices(client)

    for _ in range(10):
        result = service.get_distance_breakdown(
            "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z", "month"
        )
        assert sum(bucket.distance for bucket in result.buckets) == 10
    legacy_logical_gets = client.logical_gets
    assert legacy_logical_gets == 20

    setup_client = CountingSyntheticClient()
    setup_before = setup_client.logical_gets
    setup_summary = setup_client.get_core("/v1/account-summary", max_response_bytes=2 * 1024 * 1024)
    setup_history = setup_client.get_geo(
        "/v1/routes",
        params={"vehicleId": VEHICLE_ID, "from": "2026-01-01T00:00:00.000Z", "to": "2026-02-01T00:00:00.000Z"},
        max_response_bytes=2 * 1024 * 1024,
    )
    ledger_import_setup_gets = setup_client.logical_gets - setup_before
    assert setup_summary["vehicles"][0]["id"] == VEHICLE_ID

    database = tmp_path / "distance-history.sqlite3"
    ledger = DistanceLedger(database, KEY)
    added = ledger.import_routes(ACCOUNT_ID, VEHICLE_ID, setup_history["data"])
    assert added.added == 2

    before_warm_queries = setup_client.logical_gets
    for _ in range(10):
        reopened_ledger = DistanceLedger(database, KEY)
        breakdown = reopened_ledger.distance_breakdown(
            ACCOUNT_ID,
            VEHICLE_ID,
            "month",
            date_from=date(2026, 1, 1),
            date_to=date(2026, 2, 1),
        )
        assert sum(bucket.distance for bucket in breakdown.buckets) == 10
    warm_query_gets = setup_client.logical_gets - before_warm_queries

    assert legacy_logical_gets == 20
    assert ledger_import_setup_gets == 2
    assert warm_query_gets == 0
