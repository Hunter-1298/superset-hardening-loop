"""A dispatch the controller crashed out of leaves a work item locked in `dispatching`; the next
tick adopts the session Devin already holds for it. That adopted session is the only one owed an
extra poll: every other active session was polled at tick start and must not be asked again."""

from __future__ import annotations

from pathlib import Path

import pytest

from hardening_loop.devin.fake import ControllerCrash
from hardening_loop.domain.enums import WorkItemState
from hardening_loop.replay.world import World


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path / "replay.sqlite3", max_concurrent_sessions=2)


def _polls(w: World, since: int) -> dict[str, int]:
    counts: dict[str, int] = {}
    for method, target in w.devin.calls[since:]:
        if method == "get_session":
            counts[target] = counts.get(target, 0) + 1
    return counts


def test_only_the_adopted_orphan_is_polled_again_after_recovery(w: World) -> None:
    w.baseline("cryptography", "pillow")
    w.devin.crash_after.add("create_session")
    with pytest.raises(ControllerCrash):
        w.tick()  # pillow (CRITICAL, first) exists at Devin; its row was never written
    states = {i.group_key.split(":")[-1]: i.state for i in w.work_items()}
    assert states == {
        "pillow": WorkItemState.dispatching,
        "cryptography": WorkItemState.issue_open,
    }
    orphan = next(iter(w.devin.sessions))

    mark = len(w.devin.calls)
    report = w.tick()  # restart: adopt pillow's orphan, then launch cryptography
    assert (report.sessions_adopted, report.sessions_created) == (1, 1)
    fresh = [sid for sid in w.devin.sessions if sid != orphan]
    assert len(fresh) == 1
    assert _polls(w, mark) == {orphan: 1}, "the fresh session is not polled in its own tick"
    assert report.sessions_polled == 1

    mark = len(w.devin.calls)
    report = w.tick()
    assert _polls(w, mark) == {orphan: 1, fresh[0]: 1}
    assert report.sessions_polled == 2 and report.sessions_adopted == 0
