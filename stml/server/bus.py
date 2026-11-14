"""Event bus abstraction (S5): local in-process, NATS/Kafka adapters later."""

from __future__ import annotations

from typing import Any, Protocol


class BusUnavailable(RuntimeError):
    pass


class EventBus(Protocol):
    def publish(self, topic: str, event: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class LocalBus:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def publish(self, topic: str, event: dict[str, Any]) -> None:
        self.events.append((topic, event))

    def close(self) -> None:
        return


class NatsBus:
    """Adapter placeholder: enabled only when nats-py is installed and a server exists."""

    def __init__(self, url: str = "nats://127.0.0.1:4222") -> None:
        self.url = url
        try:
            import nats  # noqa: F401
        except ImportError as exc:
            raise BusUnavailable("nats-py is not installed") from exc
        raise BusUnavailable("NATS connection is not configured (S5 external gate)")

    def publish(self, topic: str, event: dict[str, Any]) -> None:
        raise BusUnavailable("NATS not connected")

    def close(self) -> None:
        return


def build_bus(kind: str) -> EventBus:
    if kind == "local":
        return LocalBus()
    if kind == "nats":
        return NatsBus()
    raise ValueError(f"unknown event bus: {kind}")
