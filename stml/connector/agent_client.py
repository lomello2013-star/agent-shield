"""Thin client for the existing agent RPC (`core/ipc.py`).

This is the only place that speaks pickle. Everything above it receives plain
dicts and never sees the transport.
"""

from __future__ import annotations

from typing import Any

from core.ipc import RpcClient


class AgentUnavailable(RuntimeError):
    pass


class AgentClient:
    def __init__(
        self,
        address: str,
        authkey: bytes,
        token: str,
        timeout_s: float = 2.0,
    ) -> None:
        self.address = address
        self.authkey = authkey
        self.token = token
        self.timeout_s = timeout_s

    def _call(self, method: str, params: dict | None = None) -> Any:
        client: RpcClient | None = None
        try:
            client = RpcClient(self.address, self.authkey, self.token)
            return client.call(method, params)
        except Exception as exc:  # connection/refused/timeout/protocol
            raise AgentUnavailable(f"{method}: {exc}") from exc
        finally:
            if client is not None:
                client.close()

    def ping(self) -> dict:
        return self._call("ping")

    def health(self) -> dict:
        return self._call("health")

    def stats(self) -> dict:
        return self._call("stats")

    def self_test(self) -> dict:
        return self._call("self_test")

    def immutable_check(self) -> dict:
        return self._call("immutable_check")

    def confirmations(self) -> dict:
        return self._call("confirmations")

    def policy_state(self) -> dict:
        return self._call("policy_state")

    def apply_policy(self, policy: dict, pubkey: str = "", dry_run: bool = True) -> dict:
        return self._call("apply_policy", {"policy": policy, "pubkey": pubkey,
                                           "dry_run": dry_run})

    def command_poll(self) -> dict:
        return self._call("command_poll")

    def command_ack(self, command_id: str, status: str = "acked",
                    result: dict | None = None) -> dict:
        return self._call("command_ack", {"command_id": command_id, "status": status,
                                          "result": result or {}})

    def execute_command(self, kind: str, payload: dict | None = None) -> dict:
        return self._call("command_execute", {"kind": kind, "payload": payload or {}})
