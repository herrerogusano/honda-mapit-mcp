from __future__ import annotations

from tests.test_dev_multiuser_window import setup


def test_close_retries_both_stop_primitives_after_an_incomplete_close_intent():
    """A durable close intent must remain actionable until both stops read back closed."""
    window, client, journal, _ = setup()
    assert window.preflight()["success"] is True
    assert window.open()["success"] is True

    original_update = client.update_api

    def failed_update(**kwargs):
        raise RuntimeError("ambiguous-close")

    client.update_api = failed_update
    client.put_function_concurrency = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("ambiguous-close"))
    first = window.close()
    assert first["success"] is False
    assert journal.value["phase"] == "close_intent"
    operations = list(client.operations)

    client.update_api = original_update
    client.put_function_concurrency = lambda **kwargs: setattr(client, "reserve", 0)
    second = window.close()

    assert second["success"] is True
    assert client.operations != operations
