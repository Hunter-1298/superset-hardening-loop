"""Replay runner: executes scenarios under the network guard, one SQLite database per scenario
(plus a combined `replay.sqlite3` the dashboard can serve), and writes a JSON + Markdown report."""

from __future__ import annotations

import json
import shutil
import traceback
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from hardening_loop.db import rollback_journal_mode
from hardening_loop.replay.netguard import NetworkAttemptError, no_network
from hardening_loop.replay.scenarios import SCENARIOS
from hardening_loop.replay.world import ScenarioResult, World


@dataclass
class ReplayReport:
    started_at: str
    finished_at: str = ""
    results: list[dict[str, object]] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(bool(r["passed"]) for r in self.results) and not self.network_attempts


def run_scenario(name: str, out_dir: Path) -> ScenarioResult:
    title, fn = SCENARIOS[name]
    result = ScenarioResult(name=name, title=title)
    db_path = out_dir / f"{name.lower()}.sqlite3"
    for stale in out_dir.glob(f"{name.lower()}*.sqlite3*"):
        stale.unlink()
    with no_network() as guard:
        world = World(db_path)
        try:
            fn(world, result)
        except NetworkAttemptError as exc:
            result.expect("no outbound network", False, str(exc))
        except Exception:
            result.expect("scenario ran without exception", False, traceback.format_exc())
        finally:
            world.engine.dispose()  # checkpoints the WAL so the .sqlite3 file is self-contained
        result.network_attempts = list(guard.attempts)
    return result


def run_all(out_dir: Path, names: list[str] | None = None) -> ReplayReport:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = ReplayReport(started_at=datetime.now(UTC).isoformat())
    for name in names or list(SCENARIOS):
        res = run_scenario(name, out_dir)
        report.results.append(
            {
                "name": res.name,
                "title": res.title,
                "passed": res.passed,
                "checks": [asdict(c) for c in res.checks],
                "notes": res.notes,
                "network_attempts": res.network_attempts,
                "database": str(out_dir / f"{name.lower()}.sqlite3"),
            }
        )
        report.network_attempts.extend(res.network_attempts)
    report.finished_at = datetime.now(UTC).isoformat()
    (out_dir / "replay-report.json").write_text(json.dumps(asdict(report), indent=2, default=str))
    (out_dir / "replay-report.md").write_text(render_markdown(report))
    # The dashboard's default replay database: the all-kinds showcase, else the real baseline
    # fixture (R0), else the end-to-end dependency scenario (R1).
    preferred = next(
        (n for n in ("DEMO", "R0", "R1") if (out_dir / f"{n.lower()}.sqlite3").exists()), None
    )
    if preferred is not None:
        served = out_dir / "replay.sqlite3"
        shutil.copyfile(out_dir / f"{preferred.lower()}.sqlite3", served)
        rollback_journal_mode(served)
    return report


def render_markdown(report: ReplayReport) -> str:
    lines = [
        "# Replay report",
        "",
        f"Started {report.started_at}, finished {report.finished_at}. ",
        f"**{'PASS' if report.passed else 'FAIL'}** — "
        f"{sum(1 for r in report.results if r['passed'])}/{len(report.results)} scenarios passed, "
        f"{len(report.network_attempts)} outbound network attempts.",
        "",
        "| Scenario | Result | Checks | Title |",
        "|---|---|---|---|",
    ]
    for r in report.results:
        checks = r["checks"]
        assert isinstance(checks, list)
        ok = sum(1 for c in checks if c["ok"])
        verdict = "PASS" if r["passed"] else "FAIL"
        lines.append(f"| {r['name']} | {verdict} | {ok}/{len(checks)} | {r['title']} |")
    for r in report.results:
        checks = r["checks"]
        assert isinstance(checks, list)
        failed = [c for c in checks if not c["ok"]]
        if failed:
            lines += ["", f"## {r['name']} failures", ""]
            for c in failed:
                lines.append(f"- {c['description']}: {c['detail']}")
    return "\n".join(lines) + "\n"


__all__ = ["ReplayReport", "render_markdown", "run_all", "run_scenario"]
