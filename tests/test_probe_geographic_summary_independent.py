from __future__ import annotations

import pytest

pytest.importorskip("shapely")

from scripts import probe_geographic_summary as probe


class RecordingClient:
    def __init__(self):
        self.calls = []

    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("core", path, params, max_response_bytes))
        return {"vehicles": [{"id": "synthetic-vehicle"}]}

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("geo", path, dict(params or {}), max_response_bytes))
        return {"data": []}


def test_probe_dispatches_only_fixed_windows_with_two_mib_caps():
    client = RecordingClient()
    result = probe.run_probe(lambda: __import__("mapit.services", fromlist=["MapitServices"]).MapitServices(client))

    assert result["success"] is True
    assert len(client.calls) == 5
    assert client.calls[0] == ("core", "/v1/account-summary", None, 2 * 1024 * 1024)
    assert [call[0] for call in client.calls] == ["core", "geo", "geo", "geo", "geo"]
    assert all(call[3] == 2 * 1024 * 1024 for call in client.calls)
    starts = [call[2]["from"] for call in client.calls[1:]]
    ends = [call[2]["to"] for call in client.calls[1:]]
    assert starts == [
        "2026-05-31T22:00:00.000Z", "2026-06-01T00:00:00.000Z",
        "2026-07-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z",
    ]
    assert ends == [
        "2026-06-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z",
        "2026-08-01T00:00:00.000Z", "2026-08-31T22:00:00.000Z",
    ]


@pytest.mark.parametrize("cap", [None, 2 * 1024 * 1024 + 1])
def test_read_budget_rejects_core_without_exact_response_cap(cap):
    client = RecordingClient()
    start, end = probe.summer_window_utc(2026)
    budget = probe._ReadBudget(client, start, end)

    with pytest.raises(probe.ProbeError):
        budget.get_core("/v1/account-summary", max_response_bytes=cap)
    assert client.calls == []
