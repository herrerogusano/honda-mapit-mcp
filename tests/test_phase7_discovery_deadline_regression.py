from __future__ import annotations

import pytest

from mapit import config, http_transport


def test_default_discovery_stops_between_body_chunks_when_deadline_expires(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(config.time, "monotonic", lambda: clock[0])
    body = b'<script src="/must-not-fetch.js"></script>' + b" " * (http_transport.READ_CHUNK_BYTES + 100)
    reads: list[int] = []
    opens = []

    class Response:
        def __init__(self):
            self.remaining = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read1(self, requested: int) -> bytes:
            reads.append(requested)
            chunk, self.remaining = self.remaining[:requested], self.remaining[requested:]
            if len(reads) == 1:
                # Simulate a slow-drip response crossing the wall-clock budget
                # while remaining far below the allowed body-size limit.
                clock[0] = config.DISCOVERY_BUDGET_SECONDS + 1
            return chunk

    class Opener:
        def open(self, request, timeout):
            opens.append((request, timeout))
            return Response()

    monkeypatch.setattr(http_transport, "direct_opener", lambda: Opener())

    with pytest.raises(config.RuntimeConfigDiscoveryError) as caught:
        config.fetch_public_runtime_config()

    assert caught.value.category == "discovery_budget_exceeded"
    assert len(opens) == 1  # The bundle URL from the body was never dispatched.
    assert len(reads) == 1  # No second body chunk is consumed after the deadline.
    assert opens[0][1] <= config.DISCOVERY_BUDGET_SECONDS
