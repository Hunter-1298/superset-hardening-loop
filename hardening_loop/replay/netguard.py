"""Zero-outbound-network guard for replay: any socket connect raises and is recorded."""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


class NetworkAttemptError(RuntimeError):
    pass


class NetworkGuard:
    def __init__(self) -> None:
        self.attempts: list[str] = []
        self._orig_connect = socket.socket.connect
        self._orig_connect_ex = socket.socket.connect_ex
        self._orig_create_connection = socket.create_connection
        self._orig_getaddrinfo = socket.getaddrinfo

    def _blocked(self, what: str) -> None:
        self.attempts.append(what)
        raise NetworkAttemptError(f"outbound network attempted during replay: {what}")

    def __enter__(self) -> NetworkGuard:
        guard = self

        def connect(_self: socket.socket, address: Any) -> None:
            guard._blocked(f"connect {address!r}")

        def connect_ex(_self: socket.socket, address: Any) -> int:
            guard._blocked(f"connect_ex {address!r}")
            return 1

        def create_connection(address: Any, *a: Any, **kw: Any) -> socket.socket:
            guard._blocked(f"create_connection {address!r}")
            raise AssertionError("unreachable")

        def getaddrinfo(host: Any, *a: Any, **kw: Any) -> list[Any]:
            guard._blocked(f"getaddrinfo {host!r}")
            return []

        socket.socket.connect = connect  # type: ignore[method-assign,assignment]
        socket.socket.connect_ex = connect_ex  # type: ignore[method-assign,assignment]
        socket.create_connection = create_connection
        socket.getaddrinfo = getaddrinfo
        return self

    def __exit__(self, *exc: object) -> None:
        socket.socket.connect = self._orig_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = self._orig_connect_ex  # type: ignore[method-assign]
        socket.create_connection = self._orig_create_connection
        socket.getaddrinfo = self._orig_getaddrinfo


@contextmanager
def no_network() -> Iterator[NetworkGuard]:
    with NetworkGuard() as g:
        yield g
