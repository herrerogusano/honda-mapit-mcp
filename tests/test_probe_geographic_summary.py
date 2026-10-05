from __future__ import annotations

import pytest
pytest.importorskip("shapely")

from mapit.services import MapitServices
from scripts import probe_geographic_summary as probe


class Client:
    def __init__(self): self.calls = []
    def get_core(self, path, **kwargs):
        self.calls.append(("core", path))
        return {"vehicles": [{"id": "private-device-canary"}]}
    def get_geo(self, path, **kwargs):
        self.calls.append(("geo", path))
        return {"data": []}


def test_one_core_four_geo_reads_and_no_private_identifiers():
    client = Client()
    services = MapitServices(client)
    result = probe.run_probe(lambda: services)
    assert result["success"] is True
    assert result["core_logical_reads"] == 1 and result["geo_logical_reads"] == 4
    assert result["summary"]["matched_routes"] == 0
    assert "private-device-canary" not in str(result)
    assert services.client is client


@pytest.mark.parametrize("year", [True, 2025, 2027, "2026", None])
def test_only_the_documented_probe_year_before_factory(year):
    with pytest.raises(probe.ProbeError):
        probe.run_probe(lambda: pytest.fail("factory touched"), year=year)


def test_budget_rejects_details_extra_core_and_wrong_month():
    start, end = probe.summer_window_utc(2026)
    budget = probe._ReadBudget(Client(), start, end)
    with pytest.raises(probe.ProbeError): budget.get_core("/v1/vehicles/private")
    budget.get_core("/v1/account-summary", max_response_bytes=2*1024*1024)
    with pytest.raises(probe.ProbeError): budget.get_core("/v1/account-summary")
    for path, params in (
        ("/v1/vehicles/private/routes/private", {"vehicleId": "private", "from": start, "to": end}),
        ("/v1/routes", {"vehicleId": "private", "from": "2025-01-01", "to": "2025-02-01"}),
    ):
        with pytest.raises(probe.ProbeError): budget.get_geo(path, params=params, max_response_bytes=2*1024*1024)


def test_failure_does_not_repeat_read_or_leave_wrapper_installed():
    class Failing(Client):
        def get_geo(self, path, **kwargs):
            super().get_geo(path, **kwargs)
            raise RuntimeError("private-body-canary")
    client = Failing()
    services = MapitServices(client)
    with pytest.raises(Exception): probe.run_probe(lambda: services)
    assert client.calls == [("core", "/v1/account-summary"), ("geo", "/v1/routes")]
    assert services.client is client
