"""`hardening-loop` command line: replay, report, serve, plus the CI helpers the fork's
`security-scan` workflow runs (gate, vex-lint, forbid-ignore-files, scan-manifest).

Only `serve --operator` (without `--doubles`) can spend ACUs: it runs the poll loop with live
clients and lets an operator launch a Devin session from the dashboard. Every other command,
including plain `serve`, is read-only and never talks to GitHub or Devin."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import uvicorn

from hardening_loop.ci import (
    DEFAULT_EXPECTED_JOBS,
    WorkflowRun,
    find_ignore_files,
    gate_job,
    lint_approved_vex,
    load_registry_image,
    write_scan_manifest,
)
from hardening_loop.config import Settings
from hardening_loop.dashboard.app import build_report_for, create_app
from hardening_loop.db import open_database
from hardening_loop.domain.enums import GateMode, ImageTarget
from hardening_loop.github.rest import GitHubError, GitHubRest
from hardening_loop.ingest.evidence import EvidenceError
from hardening_loop.logging_utils import configure_logging
from hardening_loop.negative import CASES, MutationError, NegativeRunner, mutate
from hardening_loop.operator import (
    OperatorConfigError,
    OperatorContext,
    OperatorRuntime,
    build_doubles_orchestrator,
    build_live_orchestrator,
    require_loopback_bind,
)
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
    host, port = args.host or settings.dashboard_host, args.port or settings.dashboard_port
    if not args.operator:
        if args.doubles or args.operator_login:
            print("error: --doubles and --operator-login require --operator", file=sys.stderr)
            return 2
        uvicorn.run(create_app(settings), host=host, port=port)
        return 0

    update: dict[str, object] = {"operator_mode": True}
    if args.operator_login:
        update["operator_login"] = args.operator_login
    settings = settings.model_copy(update=update)
    try:
        require_loopback_bind(host)
        if args.doubles:
            orch = build_doubles_orchestrator(settings)
            assert settings.operator_login is not None
            ctx = OperatorContext.for_doubles(orch, login=settings.operator_login)
        else:
            orch = build_live_orchestrator(settings)
            assert settings.operator_login is not None
            ctx = OperatorContext(
                orch, settings.operator_login, auto_dispatch=settings.auto_dispatch
            )
        app = create_app(settings, operator=ctx)
    except (OperatorConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    runtime = OperatorRuntime(ctx, poll_interval_seconds=settings.poll_interval_seconds)
    print(
        f"operator mode as {ctx.login} ({'local doubles, no spend' if not ctx.live else 'LIVE'}); "
        f"auto-dispatch {'on' if ctx.auto_dispatch else 'off'}; polling every {runtime.interval}s",
        file=sys.stderr,
    )
    runtime.start()
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        runtime.stop()
    return 0


def _step_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as fh:
            fh.write(markdown + "\n")


def cmd_gate(args: argparse.Namespace) -> int:
    mode = GateMode(args.mode)
    try:
        result = gate_job(Path(args.job), mode)
    except EvidenceError as exc:
        print(f"::error::gate: evidence rejected: {exc}")
        return 2
    payload = result.to_dict()
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    v = result.verdict
    line = (
        f"SCAN_GATE_MODE={v.mode.value}: {v.policy_critical} CRITICAL + {v.policy_high} HIGH "
        f"policy findings on {result.image_target} ({result.image_ref})"
    )
    print(json.dumps(payload, sort_keys=True))
    _step_summary(
        f"### policy gate ({result.image_target})\n\n"
        f"- mode: `{v.mode.value}`\n- verdict: **{'PASS' if v.passed else 'FAIL'}** — {v.reason}\n"
        f"- counts: `{json.dumps(payload['counts_by_severity'])}`\n"
        f"- ready for enforce: `{v.ready_for_enforce}`\n"
    )
    if not v.passed:
        print(f"::error::{line}: {v.reason}")
        return 1
    print(line + (" (recorded, not gated)" if mode is GateMode.report else ""))
    return 0


def cmd_vex_lint(args: argparse.Namespace) -> int:
    approvers = frozenset(a.strip() for a in args.approvers.split(",") if a.strip()) or None
    report = lint_approved_vex(Path(args.src), repo=args.repo, approvers=approvers)
    for rel in report.checked:
        print(f"checked {rel}")
    for problem in report.problems:
        print(f"::error::vex-lint: {problem}")
    if args.issues_out:
        Path(args.issues_out).write_text(json.dumps(report.issue_urls, indent=2, sort_keys=True))
    print(f"vex-lint: {len(report.checked)} document(s), {len(report.problems)} problem(s)")
    return 0 if report.ok else 1


def cmd_forbid_ignore_files(args: argparse.Namespace) -> int:
    hits = find_ignore_files(Path(args.src))
    for hit in hits:
        print(f"::error file={hit}::scanner ignore files are forbidden; use an approved OpenVEX")
    print(f"forbid-ignore-files: {len(hits)} forbidden file(s)")
    return 1 if hits else 0


def cmd_scan_manifest(args: argparse.Namespace) -> int:
    out = Path(args.out)
    images = {}
    for spec in args.image:
        # target=tag@digest:manifest.json:config.json
        target_s, rest = spec.split("=", 1)
        ref, manifest_path, config_path = rest.rsplit(":", 2)
        tag, digest = ref.rsplit("@", 1)
        target = ImageTarget(target_s)
        images[target] = load_registry_image(
            target, tag, digest, Path(manifest_path), Path(config_path)
        )
    run = WorkflowRun(
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        event=args.event,
        workflow_sha=args.workflow_sha,
        ref=args.ref,
        gate_mode=GateMode(args.gate_mode),
        server_url=args.server_url,
        head_sha=args.head_sha or None,
        job_results=dict(spec.split("=", 1) for spec in args.job_result or []),
    )
    gate_files = {}
    for spec in args.gate or []:
        name, path = spec.split("=", 1)
        gate_files[name] = Path(path)
    try:
        manifest = write_scan_manifest(
            out,
            source_repo=args.source_repo,
            source_branch=args.source_branch,
            source_sha=args.source_sha,
            platform=args.platform,
            images=images,
            run=run,
            expected_jobs=tuple(args.expect_job or DEFAULT_EXPECTED_JOBS),
            gate_files=gate_files,
        )
    except EvidenceError as exc:
        print(f"::error::scan-manifest: {exc}")
        return 1
    delta = manifest["ci_layer_delta"]
    _step_summary(
        "### scan manifest\n\n"
        f"- source: `{args.source_repo}@{args.source_sha}` ({args.source_branch}, {args.event})\n"
        f"- jobs: `{', '.join(manifest['jobs'])}`\n"
        + "".join(
            f"- {t}: `{img['image_id']}` ({img['size_bytes']} bytes, user={img['config_user']})\n"
            for t, img in manifest["images"].items()
        )
        + (
            f"- ci-over-lean delta: {delta['ci_extra_bytes']} bytes in "
            f"{len(delta['ci_only_layers'])} extra layer(s)\n"
            if delta
            else ""
        )
    )
    print(f"wrote {out / 'manifest.json'} with {len(manifest['files'])} checksummed files")
    return 0


def cmd_negative_mutate(args: argparse.Namespace) -> int:
    try:
        changed = mutate(args.case, Path(args.checkout))
    except (MutationError, OSError) as exc:
        print(f"::error::ci-negative mutate {args.case}: {exc}")
        return 1
    for path in changed:
        print(path)
    if args.changed_out:
        Path(args.changed_out).write_text("\n".join(changed) + "\n")
    return 0


def cmd_negative_run(args: argparse.Namespace) -> int:
    settings = Settings()
    if settings.github_token is None:
        print("::error::HL_GITHUB_TOKEN is required to drive the fork")
        return 2
    gh = GitHubRest(settings.github_token, api_base=settings.github_api_base)
    runner = NegativeRunner(
        gh,
        repo=args.repo,
        base_branch=args.base,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_minutes * 60,
        work_dir=Path(args.work_dir),
    )
    try:
        report = runner.run(
            args.case, branch=args.branch, head_sha=args.head_sha, run_url=args.run_url
        )
    except GitHubError as exc:
        print(f"::error::ci-negative {args.case}: GitHub error: {exc}")
        return 2
    finally:
        gh.close()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    verdict = "PASS" if report.passed else "FAIL"
    _step_summary(
        f"### ci-negative `{report.case}`: **{verdict}**\n\n{report.summary}\n\n"
        f"PR: {report.pr_url}\n\n"
        + "\n".join(f"- `{k}`: {v}" for k, v in sorted(report.check_results.items()))
        + (
            "\n\nUnmet expectations:\n" + "\n".join(f"- {f}" for f in report.expectation_failures)
            if report.expectation_failures
            else ""
        )
        + (
            f"\n\nraw lean findings main -> PR: {report.counts['main']['total']} -> "
            f"{report.counts['pr']['total']} (HIGH+CRITICAL "
            f"{report.counts['main']['high_critical']} -> {report.counts['pr']['high_critical']})"
            if "pr" in report.counts and "main" in report.counts
            else ""
        )
    )
    print(f"ci-negative {report.case}: {verdict} ({report.pr_url})")
    for failure in report.expectation_failures:
        print(f"::error::{report.case}: {failure}")
    return 0 if report.passed else 1


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

    s = sub.add_parser("serve", help="dashboard (read-only unless --operator)")
    s.add_argument("--db")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--replay", action="store_true", help="label the UI as replay (no spend)")
    s.add_argument(
        "--operator",
        action="store_true",
        help="writable: run the poll loop and allow 'Launch Devin' (needs HL_GITHUB_TOKEN, "
        "HL_DEVIN_API_KEY, HL_OPERATOR_LOGIN)",
    )
    s.add_argument(
        "--doubles",
        action="store_true",
        help="with --operator: use the in-memory GitHub/Devin doubles (no credentials, no spend)",
    )
    s.add_argument("--operator-login", help="overrides HL_OPERATOR_LOGIN")
    s.set_defaults(fn=cmd_serve)

    g = sub.add_parser("gate", help="apply SCAN_GATE_MODE to one policy scan job directory")
    g.add_argument("--job", required=True, help="scan_image.sh output dir (mode=policy)")
    g.add_argument("--mode", required=True, choices=[m.value for m in GateMode])
    g.add_argument("--out", help="write gate.json here")
    g.set_defaults(fn=cmd_gate)

    vl = sub.add_parser("vex-lint", help="validate security/vex/approved/ OpenVEX documents")
    vl.add_argument("src", help="Superset checkout")
    vl.add_argument("--repo", help="owner/name the x-approval issue URLs must belong to")
    vl.add_argument("--approvers", default="", help="comma-separated allowed approver logins")
    vl.add_argument("--issues-out", help="write {file: issue_url} JSON for a follow-up label check")
    vl.set_defaults(fn=cmd_vex_lint)

    fi = sub.add_parser("forbid-ignore-files", help="fail if any scanner ignore file exists")
    fi.add_argument("src", help="Superset checkout")
    fi.set_defaults(fn=cmd_forbid_ignore_files)

    sm = sub.add_parser("scan-manifest", help="aggregate CI scan jobs into manifest.json")
    sm.add_argument("--out", required=True, help="evidence root holding <target>/<mode>/ dirs")
    sm.add_argument("--source-repo", required=True)
    sm.add_argument("--source-branch", required=True)
    sm.add_argument("--source-sha", required=True)
    sm.add_argument("--platform", default="linux/amd64")
    sm.add_argument("--run-id", type=int, required=True)
    sm.add_argument("--run-attempt", type=int, required=True)
    sm.add_argument("--event", required=True, help="github.event_name")
    sm.add_argument("--workflow-sha", required=True, help="github.workflow_sha")
    sm.add_argument("--ref", required=True, help="github.ref")
    sm.add_argument("--gate-mode", required=True, choices=[m.value for m in GateMode])
    sm.add_argument("--server-url", default="https://github.com")
    sm.add_argument(
        "--image",
        action="append",
        default=[],
        metavar="TARGET=TAG@DIGEST:MANIFEST.json:CONFIG.json",
        help="registry metadata for one image target (repeatable)",
    )
    sm.add_argument(
        "--expect-job",
        action="append",
        metavar="TARGET-MODE",
        help=(
            "job dir that must be present, e.g. lean-raw (repeatable; "
            f"default: {' '.join(DEFAULT_EXPECTED_JOBS)})"
        ),
    )
    sm.add_argument("--gate", action="append", metavar="JOB=gate.json", help="gate verdicts")
    sm.add_argument("--head-sha", help="PR head SHA when --source-sha is the merge commit")
    sm.add_argument(
        "--job-result",
        action="append",
        metavar="JOB=RESULT",
        help="GitHub `needs.<job>.result` of a runtime job to record (repeatable)",
    )
    sm.set_defaults(fn=cmd_scan_manifest)

    neg = sub.add_parser("ci-negative", help="operator-triggered negative suite against the fork")
    neg_sub = neg.add_subparsers(dest="negative_command", required=True)
    nm = neg_sub.add_parser("mutate", help="apply one case to a checkout (prints changed paths)")
    nm.add_argument("case", choices=sorted(CASES))
    nm.add_argument("--checkout", required=True, help="fork checkout at the base branch")
    nm.add_argument("--changed-out", help="also write the changed paths here, one per line")
    nm.set_defaults(fn=cmd_negative_mutate)
    nr = neg_sub.add_parser("run", help="open the draft PR, wait for checks, evaluate, clean up")
    nr.add_argument("case", choices=sorted(CASES))
    nr.add_argument("--repo", required=True)
    nr.add_argument("--base", default="main")
    nr.add_argument("--branch", required=True, help="already-pushed mutated branch")
    nr.add_argument("--head-sha", required=True)
    nr.add_argument("--run-url", required=True, help="URL of the driving workflow run")
    nr.add_argument("--out", required=True, help="ci-negative-report.json path")
    nr.add_argument("--work-dir", default="data/ci-negative")
    nr.add_argument("--poll-seconds", type=float, default=30.0)
    nr.add_argument("--timeout-minutes", type=float, default=90.0)
    nr.set_defaults(fn=cmd_negative_run)
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
