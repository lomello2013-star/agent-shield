import pytest

from stml.server.bus import BusUnavailable, LocalBus, NatsBus, build_bus


def test_local_bus_publishes():
    bus = LocalBus()
    bus.publish("reports", {"acked": ["r1"]})
    assert bus.events == [("reports", {"acked": ["r1"]})]
    bus.close()


def test_nats_adapter_is_explicitly_unavailable():
    with pytest.raises(BusUnavailable):
        NatsBus()


def test_build_bus_rejects_unknown():
    with pytest.raises(ValueError):
        build_bus("kafka")
    assert isinstance(build_bus("local"), LocalBus)
