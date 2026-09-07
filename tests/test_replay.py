"""Replay scenarios are the M3 acceptance tests: every scenario must pass all its checks with zero
outbound network attempts, driving the real orchestrator against the in-memory doubles."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from hardening_loop.replay.netguard import NetworkAttemptError, no_network
from hardening_loop.replay.runner import run_all, run_scenario
from hardening_loop.replay.scenarios import SCENARIOS

EXPECTED = [
    *(f"R{i}" for i in range(15)),
    *(f"N{i}" for i in range(1, 6)),
]


def test_scenario_catalogue_complete() -> None:
    assert list(SCENARIOS) == EXPECTED


@pytest.mark.parametrize("name", EXPECTED)
def test_scenario(name: str, tmp_path: Path) -> None:
    result = run_scenario(name, tmp_path)
    failed = [f"{c.description}: {c.detail}" for c in result.checks if not c.ok]
    assert not failed, "\n".join(failed)
    assert result.network_attempts == []
    assert result.checks, "scenario recorded no checks"


def test_network_guard_blocks_and_records() -> None:
    with no_network() as guard, pytest.raises(NetworkAttemptError):
        socket.create_connection(("example.invalid", 443), timeout=0.01)
    assert guard.attempts and "example.invalid" in guard.attempts[0]
    with no_network() as guard2, pytest.raises(NetworkAttemptError):
        socket.getaddrinfo("example.invalid", 443)
    assert guard2.attempts


def test_network_guard_restores_socket() -> None:
    before = (socket.socket.connect, socket.create_connection, socket.getaddrinfo)
    with no_network():
        pass
    assert (socket.socket.connect, socket.create_connection, socket.getaddrinfo) == before


def test_run_all_writes_reports(tmp_path: Path) -> None:
    report = run_all(tmp_path, ["R1", "N4"])
    assert report.passed
    assert (tmp_path / "replay-report.json").exists()
    md = (tmp_path / "replay-report.md").read_text()
    assert "| R1 | PASS |" in md and "| N4 | PASS |" in md
    assert (tmp_path / "replay.sqlite3").exists()
