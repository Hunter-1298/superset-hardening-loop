"""`hardening-loop` command line: replay, report, serve.

Live orchestration (`run`) is intentionally absent until the real GitHub/Devin clients land;
nothing here can spend ACUs."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from hardening_loop.config import Settings
from hardening_loop.dashboard.app import build_report_for, create_app
from hardening_loop.db import open_database
from hardening_loop.logging_utils import configure_logging
from hardening_loop.replay.runner import run_all
from hardening_loop.replay.scenarios import SCENARIOS
from hardening_loop.report.run_report import persist_report, render_markdown


def _settings_for(db: Path | None) -> Settings:
    settings = Settings()
    if db is not None:
        settings = settings.model_copy(
            update={"data_dir": db.parent, "database_file": db.name}, deep=True
        )
    return settings


def cmd_replay(args: argparse.Namespace) -> int:
    out = Path(args.out)
    names = list(args.only) if args.only else None
    unknown = [n for n in names or [] if n not in SCENARIOS]
    if unknown:
        print(f"unknown scenario(s): {', '.join(unknown)}; known: {', '.join(SCENARIOS)}")
        return 2
    report = run_all(out, names)
    for res in report.results:
        status = "PASS" if res["passed"] else "FAIL"
        print(f"{status:4} {res['name']!s:5} {res['title']}")
        checks = res["checks"]
        if not res["passed"] and isinstance(checks, list):
            for check in checks:
                if not check["ok"]:
                    print(f"       - {check['description']}: {check['detail']}")
    if report.network_attempts:
        print("NETWORK ATTEMPTS (must be zero):")
        for attempt in report.network_attempts:
            print(f"  {attempt}")
    print(f"report: {out / 'replay-report.md'}  dashboard db: {out / 'replay.sqlite3'}")
    return 0 if report.passed else 1


def cmd_report(args: argparse.Namespace) -> int:
    settings = _settings_for(Path(args.db) if args.db else None)
    if args.upstream_sha:
        settings = settings.model_copy(update={"upstream_master_sha": args.upstream_sha})
    if args.acu_cost_usd is not None:
        settings = settings.model_copy(update={"acu_cost_usd": args.acu_cost_usd})
    engine = open_database(settings.database_path)
    body = build_report_for(engine, settings, datetime.now(UTC))
    markdown = render_markdown(body)
    if args.persist:
        row_id = persist_report(engine, body, markdown)
        print(f"persisted run_reports.id={row_id}", file=sys.stderr)
    if args.out:
        Path(args.out).write_text(markdown)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(markdown)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    settings = _settings_for(Path(args.db) if args.db else None)
    if args.replay:
        settings = settings.model_copy(update={"replay_mode": True})
    app = create_app(settings)
    uvicorn.run(
        app, host=args.host or settings.dashboard_host, port=args.port or settings.dashboard_port
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hardening-loop")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("replay", help="run no-spend replay scenarios (zero outbound network)")
    r.add_argument("--out", default="data/replay")
    r.add_argument("--only", nargs="*", metavar="SCENARIO")
    r.set_defaults(fn=cmd_replay)

    rep = sub.add_parser("report", help="database-backed baseline/latest/upstream report")
    rep.add_argument("--db", help="SQLite file (default: HL_DATA_DIR/HL_DATABASE_FILE)")
    rep.add_argument("--upstream-sha", help="upstream-master SHA with a fixtures/source snapshot")
    rep.add_argument("--acu-cost-usd", type=float)
    rep.add_argument("--persist", action="store_true", help="store a RunReport row")
    rep.add_argument("--out", help="write Markdown here instead of stdout")
    rep.set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="read-only dashboard")
    s.add_argument("--db")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--replay", action="store_true", help="label the UI as replay (no spend)")
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = build_parser().parse_args(argv)
    fn = args.fn
    assert callable(fn)
    result = fn(args)
    assert isinstance(result, int)
    return result


if __name__ == "__main__":
    sys.exit(main())
