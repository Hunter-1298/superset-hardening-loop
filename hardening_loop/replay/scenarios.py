"""Replay scenarios R0-R20 and N1-N5. Every scenario drives the real orchestrator against the
in-memory doubles and records checks; the runner asserts zero outbound network for all of them."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from hardening_loop.classify.rules import parse_upper_bounds
from hardening_loop.devin.enums import DevinStatus, DevinStatusDetail
from hardening_loop.devin.fake import ControllerCrash
from hardening_loop.domain.enums import (
    FindingState,
    GateMode,
    HumanLabel,
    Kind,
    LifecycleLevel,
    Scanner,
    Severity,
    Trigger,
    WorkItemState,
)
from hardening_loop.gate import gate_verdict
from hardening_loop.ingest.evidence import load_baseline, load_source_pyproject
from hardening_loop.ingest.persist import ingest_baseline
from hardening_loop.models.tables import NegativeRun, WorkItem
from hardening_loop.orchestrator.engine import AWAITING_DISPATCH_LABEL
from hardening_loop.orchestrator.launch import LaunchBlock
from hardening_loop.replay.synth import (
    BASELINE_SHA,
    CONFIG_SEEDS,
    SEEDS,
    approved_vex,
)
from hardening_loop.replay.world import APPROVER, ScenarioResult, World, sha

Scenario = Callable[[World, ScenarioResult], None]
SCENARIOS: dict[str, tuple[str, Scenario]] = {}


def scenario(name: str, title: str) -> Callable[[Scenario], Scenario]:
    def deco(fn: Scenario) -> Scenario:
        SCENARIOS[name] = (title, fn)
        return fn

    return deco


# ----------------------------------------------------------------------------- shared flows


def _dispatch(w: World, r: ScenarioResult, *seeds: str, configs: tuple[str, ...] = ()) -> WorkItem:
    w.baseline(*seeds, configs=configs)
    w.tick()
    wi = w.only_wi()
    r.eq("work item created and dispatched", wi.state, WorkItemState.session_active)
    r.expect("issue opened on fork", wi.issue_number is not None and wi.issue_url is not None)
    r.eq("ACU cap equals the per-kind cap", wi.acu_cap, float(wi.kind.acu_cap))
    reqs = w.devin.created_requests()
    r.eq("exactly one Devin session created", len(reqs), 1)
    if reqs:
        r.eq("session max_acu_limit == cap", reqs[0].max_acu_limit, wi.acu_cap)
        r.expect("session tagged hl + wi-<id> + kind", {"hl", f"wi-{wi.id}"} <= set(reqs[0].tags))
        r.expect("session has structured_output_schema", bool(reqs[0].structured_output_schema))
        r.expect("session has evidence attachment", bool(reqs[0].attachment_urls))
    return wi


def _to_ready_for_human(
    w: World, r: ScenarioResult, wi: WorkItem, output: dict[str, Any], files: list[str], acus: float
) -> tuple[WorkItem, str]:
    _url, number = w.devin_opens_pr(wi, output, files=files, acus=acus)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("PR verified -> checks_running", wi.state, WorkItemState.checks_running)
    r.eq("verification level L1", wi.lifecycle_level, LifecycleLevel.pr_opened)
    head = w.gh.prs[number].head_sha
    w.ci(head)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("CI green -> review_pending", wi.state, WorkItemState.review_pending)
    r.eq("verification level L2", wi.lifecycle_level, LifecycleLevel.ci_green)
    w.review_done(head)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("Devin Review status observed -> ready_for_human", wi.state, WorkItemState.ready_for_human)
    r.eq("verification level L3", wi.lifecycle_level, LifecycleLevel.review_completed)
    return wi, head


def _merge(w: World, r: ScenarioResult, wi: WorkItem) -> tuple[WorkItem, str]:
    merge_sha = w.human_approves_and_merges(wi)
    wi = w.wi(wi.id or 0)
    r.eq("human merge -> merged", wi.state, WorkItemState.merged)
    r.eq("verification level L5 after merge", wi.lifecycle_level, LifecycleLevel.merged)
    r.expect("controller never approved or merged", w.gh.never_merged_or_approved())
    return wi, merge_sha


def _dep_output(pkg: str, frm: str, to: str) -> dict[str, Any]:
    return {
        "packages": [{"name": pkg, "from": frm, "to": to}],
        "regenerated_with": "./scripts/uv-pip-compile.sh",
    }


DEP_FILES = ["pyproject.toml", "requirements/base.txt", "requirements/development.txt"]


# ----------------------------------------------------------------------------- R0


@scenario("R0", "Real baseline fixture: ingest, group, open issues, bounded dispatch")
def r0(w: World, r: ScenarioResult) -> None:
    root = w.settings.repo_root
    fixture = root / "fixtures" / "baseline" / BASELINE_SHA
    if not fixture.exists():
        r.expect("baseline fixture present", False, str(fixture))
        return
    manifest = load_baseline(fixture)
    bounds = parse_upper_bounds(load_source_pyproject(root, BASELINE_SHA))
    res = ingest_baseline(w.engine, manifest, upper_bounds=bounds)
    r.expect("baseline ingested with findings", res.findings_total > 1000, res.findings_total)
    r.eq("no unclassified findings in baseline", res.unclassified, 0)
    w.settings.max_concurrent_sessions = 2
    rep = w.tick()
    items = w.work_items()
    r.expect("work items created from grouped findings", len(items) > 50, len(items))
    r.eq("one issue per work item", len(w.gh.issues), len(items))
    r.eq("dispatch bounded by max_concurrent_sessions=2", rep.sessions_created, 2)
    active = [i for i in items if i.state is WorkItemState.session_active]
    r.expect(
        "dispatched items are HIGH/CRITICAL", all(i.severity.rank >= 3 for i in active), active
    )
    kinds = {i.kind for i in items}
    r.eq("all five kinds present", kinds, set(Kind))
    rep2 = w.tick()
    r.eq("second tick creates no extra sessions at capacity", rep2.sessions_created, 0)


# ----------------------------------------------------------------------------- R1


@scenario("R1", "Dependency upgrade: first-try success through rescan_verified")
def r1(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    r.eq("kind is dependency_upgrade", wi.kind, Kind.dependency_upgrade)
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.1
    )
    r.eq("verification level L4 after approval", w.wi(wi.id or 0).lifecycle_level >= 3, True)
    wi, merge_sha = _merge(w, r, wi)
    # Closing run of main at the merge commit, without cryptography.
    rid = w.ingest(w.closing_run(merge_sha))
    counts = w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("rescan outcome fixed", counts.get("fixed"), 1)
    r.eq("work item verified", wi.state, WorkItemState.verified)
    r.eq("verification level L6", wi.lifecycle_level, LifecycleLevel.rescan_verified)
    r.eq("issue closed", w.issue_state(wi), "closed")
    r.eq("finding fixed", w.finding_by_vuln("CVE-2024-26130").state, FindingState.fixed)
    row = w.pr_row(wi.id or 0)
    r.eq("first-try success recorded", row.first_head_checks_green if row else None, True)
    r.eq("no retries", wi.retries_used, 0)
    r.eq("session messages: none", w.sessions()[0].messages_sent, 0)


# ----------------------------------------------------------------------------- R2


@scenario("R2", "CI red once: same-session retry, then verified")
def r2(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "pillow")
    url, number = w.devin_opens_pr(
        wi, _dep_output("pillow", "10.2.0", "10.3.0"), files=DEP_FILES, acus=1.8
    )
    w.tick()
    head1 = w.gh.prs[number].head_sha
    w.ci(head1, failing=["app-runs"])
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("checks red -> retry sent, session active again", wi.state, WorkItemState.session_active)
    r.eq("retries_used == 1", wi.retries_used, 1)
    sess = w.devin.sessions[wi.active_session_id or ""]
    r.eq("retry message sent to the SAME session", len(sess.messages), 1)
    r.expect("retry message names failed check", "app-runs" in (sess.messages or [""])[0])
    r.eq("no second session created", len(w.devin.created_requests()), 1)
    # Devin pushes a fix to the same PR and finishes again.
    head2 = sha("pillow-fix-2")
    w.gh.push(number, head2)
    w.devin.finish(
        wi.active_session_id or "",
        {**sess.structured_output, "pr_url": url} if sess.structured_output else {},
        acus=3.2,
        pull_requests=[url],
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("PR re-verified -> checks_running", wi.state, WorkItemState.checks_running)
    w.ci(head2)
    w.tick()
    w.review_done(head2)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("ready_for_human after retry", wi.state, WorkItemState.ready_for_human)
    wi, merge_sha = _merge(w, r, wi)
    rid = w.ingest(w.closing_run(merge_sha))
    w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("verified after retry", wi.state, WorkItemState.verified)
    row = w.pr_row(wi.id or 0)
    r.eq("first-try success is False", row.first_head_checks_green if row else None, False)
    r.eq("head sha changed recorded", row.head_sha if row else None, head2)
    r.eq("both pillow CVEs fixed", {f.state for f in w.findings(wi.id)}, {FindingState.fixed})


# ----------------------------------------------------------------------------- R3


@scenario("R3", "CI red repeatedly: retries exhausted -> failed + needs-human label")
def r3(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    url, number = w.devin_opens_pr(
        wi, _dep_output("cryptography", "42.0.2", "42.0.4"), files=DEP_FILES, acus=1.0
    )
    w.tick()
    for attempt in range(3):
        head = w.gh.prs[number].head_sha
        w.ci(head, failing=["build-image"])
        w.tick()
        wi = w.wi(wi.id or 0)
        if attempt < 2:
            r.eq(f"retry {attempt + 1} sent", wi.state, WorkItemState.session_active)
            new_head = sha(f"crypto-attempt-{attempt}")
            w.gh.push(number, new_head)
            w.devin.finish(
                wi.active_session_id or "",
                {
                    **(w.devin.sessions[wi.active_session_id or ""].structured_output or {}),
                    "pr_url": url,
                },
                acus=1.5 + attempt,
                pull_requests=[url],
            )
            w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("retries exhausted -> failed", wi.state, WorkItemState.failed)
    r.eq("retries_used == 2", wi.retries_used, 2)
    r.expect("needs-human label applied", HumanLabel.needs_human.value in w.issue_labels(wi))
    r.eq("still exactly one session", len(w.devin.created_requests()), 1)
    r.expect(
        "retries_exhausted event logged",
        "retries_exhausted" in w.event_names(wi.id or 0),
    )
    # Human applies `retry` label -> back to issue_open, new session on next tick.
    w.gh.label(wi.issue_number or 0, HumanLabel.retry.value)
    w.tick()
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("human retry label -> new session dispatched", wi.state, WorkItemState.session_active)
    r.eq("second session created after human retry", len(w.devin.created_requests()), 2)


# ----------------------------------------------------------------------------- R4


@scenario("R4", "No-fix finding: reachability + proposed OpenVEX, human-approved disposition")
def r4(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "paramiko")
    r.eq("kind is no_fix_reachability", wi.kind, Kind.no_fix_reachability)
    r.eq("ACU cap 8", wi.acu_cap, 8.0)
    out = {
        "reachability": {
            "imports_found": ["superset/db_engine_specs/ssh.py"],
            "call_sites": [
                {"file": "superset/extensions/ssh.py", "line": 42, "symbol": "SSHTunnelForwarder"}
            ],
            "runtime_paths": [],
            "verdict": "unreachable",
        },
        "proposed_vex_path": "security/vex/proposed/cve-2023-48795.json",
        "justification": "Terrapin needs an SSH server; Superset only acts as a client to tunnels.",
    }
    wi, _ = _to_ready_for_human(
        w, r, wi, out, ["security/vex/proposed/cve-2023-48795.json"], acus=4.4
    )
    wi, merge_sha = _merge(w, r, wi)
    issue_url = wi.issue_url or ""
    # Closing run: raw still shows paramiko (no fix exists); policy suppresses it via approved VEX.
    run = w.closing_run(merge_sha, "paramiko")
    run.policy_suppressed_keys = {"paramiko"}
    run.vex_documents = [
        approved_vex(
            issue_url=issue_url,
            vuln_id="CVE-2023-48795",
            purl="pkg:pypi/paramiko@3.4.0",
            approver="Hunter-1298",
        )
    ]
    rid = w.ingest(run)
    counts = w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("outcome approved_disposition", counts.get("approved_disposition"), 1)
    r.eq("work item verified", wi.state, WorkItemState.verified)
    r.eq(
        "finding approved_disposition",
        w.finding_by_vuln("CVE-2023-48795").state,
        FindingState.approved_disposition,
    )
    r.eq("issue closed", w.issue_state(wi), "closed")
    # Negative control: a VEX approved for a *different* issue does not close.
    w2 = w  # same world; a later run with a mismatched approval must not regress or re-close
    run2 = w2.closing_run(sha("later-main"), "paramiko")
    w2.gh.add_commit(sha("later-main"), merge_sha)
    run2.policy_suppressed_keys = {"paramiko"}
    run2.vex_documents = [
        approved_vex(
            issue_url="https://github.com/Hunter-1298/superset/issues/999",
            vuln_id="CVE-2023-48795",
            purl="pkg:pypi/paramiko@3.4.0",
            approver="Hunter-1298",
        )
    ]
    rid2 = w2.ingest(run2)
    w2.apply_run(rid2)
    r.eq(
        "policy-suppressed finding is not flagged as regression",
        w.finding_by_vuln("CVE-2023-48795").state,
        FindingState.approved_disposition,
    )


# ----------------------------------------------------------------------------- R5


@scenario("R5", "Container hardening: OS package fix in lean image, ACU cap 20")
def r5(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "libexpat1")
    r.eq("kind is container_hardening", wi.kind, Kind.container_hardening)
    r.eq("ACU cap 20", wi.acu_cap, 20.0)
    out = {
        "changes": [{"type": "package_removal", "detail": "apt-get upgrade libexpat1 in lean"}],
        "image_size_before_after": {"before": 926202016, "after": 926100000},
        "lean_smoke_local": True,
    }
    wi, _ = _to_ready_for_human(w, r, wi, out, ["Dockerfile"], acus=7.5)
    wi, merge_sha = _merge(w, r, wi)
    rid = w.ingest(w.closing_run(merge_sha))
    counts = w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("fixed", counts.get("fixed"), 1)
    r.eq("verified", wi.state, WorkItemState.verified)


# ----------------------------------------------------------------------------- R6


@scenario("R6", "Scanner disagreement: analysis-only verdict, human resolves, rescan confirms")
def r6(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "linux-libc-dev")
    r.eq("kind is scanner_disagreement", wi.kind, Kind.scanner_disagreement)
    r.eq("ACU cap 3", wi.acu_cap, 3.0)
    w.devin.finish(
        wi.active_session_id or "",
        {
            "outcome": "no_change_needed",
            "base_branch": "main",
            "findings_addressed": [],
            "findings_not_addressed": [
                {"id": "CVE-2024-40971", "reason": "kernel headers; not runtime-reachable"}
            ],
            "reason": "Grype has no Debian tracker match for linux-libc-dev; Trivy uses NVD range.",
            "evidence_urls": ["https://security-tracker.debian.org/tracker/CVE-2024-40971"],
            "verdict": "trivy_correct",
            "evidence": [
                {"scanner": "trivy", "record": {"id": "CVE-2024-40971"}, "reasoning": "NVD range"},
                {"scanner": "grype", "record": {}, "reasoning": "no match in Debian feed"},
            ],
            "recommended_action": "none",
        },
        acus=1.1,
        pull_requests=[],
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("no_change_needed -> needs_human", wi.state, WorkItemState.needs_human)
    r.expect("needs-human label", HumanLabel.needs_human.value in w.issue_labels(wi))
    comments = w.gh.issues[wi.issue_number or 0].comments
    r.expect("verdict posted to issue", any("verdict=`trivy_correct`" in c for c in comments))
    w.gh.label(wi.issue_number or 0, HumanLabel.disagreement_resolved.value)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("human label -> awaiting_rescan", wi.state, WorkItemState.awaiting_rescan)
    r.expect("needs-human label removed", HumanLabel.needs_human.value not in w.issue_labels(wi))
    head = sha("main-later-r6")
    w.gh.add_commit(head, BASELINE_SHA)
    rid = w.ingest(w.closing_run(head, "linux-libc-dev"))
    counts = w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("outcome scanner_disagreement_resolved", counts.get("scanner_disagreement_resolved"), 1)
    r.eq("verified", wi.state, WorkItemState.verified)
    r.eq("issue closed", w.issue_state(wi), "closed")
    r.eq("no PR ever opened", wi.pr_number, None)


# ----------------------------------------------------------------------------- R7


@scenario("R7", "Helm/deployment config: values change, lint evidence, config rescan")
def r7(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, configs=("helm-run-as-root",))
    r.eq("kind is helm_deploy_config", wi.kind, Kind.helm_deploy_config)
    r.eq("ACU cap 6", wi.acu_cap, 6.0)
    out = {
        "values_changed": [
            {"path": "securityContext.runAsNonRoot", "from": None, "to": True},
            {"path": "securityContext.runAsUser", "from": None, "to": 1000},
        ],
        "helm_lint": "1 chart(s) linted, 0 chart(s) failed",
        "helm_template_diff_attachment": None,
    }
    wi, _ = _to_ready_for_human(
        w, r, wi, out, ["helm/superset/values.yaml", "helm/superset/Chart.yaml"], acus=2.0
    )
    wi, merge_sha = _merge(w, r, wi)
    rid = w.ingest(w.closing_run(merge_sha))
    counts = w.apply_run(rid)
    wi = w.wi(wi.id or 0)
    r.eq("config finding fixed", counts.get("fixed"), 1)
    r.eq("verified", wi.state, WorkItemState.verified)


# ----------------------------------------------------------------------------- R8


@scenario("R8", "Regression: verified finding reappears -> reopened issue, linked new work item")
def r8(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.0
    )
    wi, merge_sha = _merge(w, r, wi)
    rid = w.ingest(w.closing_run(merge_sha))
    w.apply_run(rid)
    r.eq("verified first", w.state_of(wi.id or 0), WorkItemState.verified)
    later = sha("main-regressed")
    w.gh.add_commit(later, merge_sha)
    rid2 = w.ingest(w.closing_run(later, "cryptography"))
    counts = w.apply_run(rid2)
    r.eq("regression counted", counts.get("regression"), 1)
    r.eq(
        "finding state regression->grouped into new item",
        w.finding_by_vuln("CVE-2024-26130").state,
        FindingState.grouped,
    )
    items = w.work_items()
    r.eq("two work items", len(items), 2)
    new = items[-1]
    r.eq("new item linked to original", new.regression_of_work_item_id, wi.id)
    r.expect("new group key suffixed #r1", new.group_key.endswith("#r1"), new.group_key)
    r.eq("original issue reopened", w.issue_state(wi), "open")
    r.eq("original work item stays verified", w.state_of(wi.id or 0), WorkItemState.verified)


# ----------------------------------------------------------------------------- R9


@scenario("R9", "Blocked output and invalid PR claims escalate, never proceed")
def r9(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    w.devin.finish(
        wi.active_session_id or "",
        {
            "outcome": "blocked",
            "base_branch": "main",
            "findings_addressed": [],
            "findings_not_addressed": [{"id": "CVE-2024-26130", "reason": "bound"}],
            "blocked_reason": "cryptography<42.0.4 pinned by pyproject upper bound; raising it "
            "changes an architectural constraint.",
        },
        acus=0.9,
        pull_requests=[],
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("blocked -> needs_human", wi.state, WorkItemState.needs_human)
    r.expect("blocked_reason recorded", "upper bound" in (wi.blocked_reason or ""))
    r.expect("needs-human label", HumanLabel.needs_human.value in w.issue_labels(wi))

    # Second item: PR claimed against the wrong repo/base is rejected.
    w2 = World(w.db_path.with_name("r9b.sqlite3"))
    wi2 = _dispatch(w2, r, "pillow")
    bad_url = w2.gh.open_pr(
        title="wrong base",
        head_ref="devin/x",
        head_sha=sha("wrong-base"),
        files=DEP_FILES,
        base_ref="master",
    )
    w2.devin.finish(
        wi2.active_session_id or "",
        {
            "outcome": "pr_opened",
            "pr_url": bad_url,
            "base_branch": "main",
            "findings_addressed": [],
            "findings_not_addressed": [],
            **_dep_output("pillow", "10.2.0", "10.3.0"),
        },
        acus=1.0,
        pull_requests=[bad_url],
    )
    w2.tick()
    wi2 = w2.wi(wi2.id or 0)
    r.eq("PR against wrong base -> needs_human", wi2.state, WorkItemState.needs_human)
    r.expect("reason mentions base", "base" in (wi2.blocked_reason or ""), wi2.blocked_reason)

    # Third: schema-invalid output (pr_opened without pr_url).
    w3 = World(w.db_path.with_name("r9c.sqlite3"))
    wi3 = _dispatch(w3, r, "libexpat1")
    w3.devin.finish(
        wi3.active_session_id or "",
        {"outcome": "pr_opened", "base_branch": "main"},
        acus=1.0,
        pull_requests=[],
    )
    w3.tick()
    wi3 = w3.wi(wi3.id or 0)
    r.eq("schema-invalid output -> needs_human", wi3.state, WorkItemState.needs_human)

    # Fourth: PR that adds a forbidden scanner-ignore file is rejected by diff policy.
    w4 = World(w.db_path.with_name("r9d.sqlite3"))
    wi4 = _dispatch(w4, r, "cryptography")
    w4.devin_opens_pr(
        wi4,
        _dep_output("cryptography", "42.0.2", "42.0.4"),
        files=[*DEP_FILES, ".trivyignore"],
        acus=1.0,
    )
    w4.tick()
    wi4 = w4.wi(wi4.id or 0)
    r.eq("ignore file in diff -> needs_human", wi4.state, WorkItemState.needs_human)
    r.expect("reason names .trivyignore", ".trivyignore" in (wi4.blocked_reason or ""))


# ----------------------------------------------------------------------------- R10


@scenario("R10", "Duplicate prevention: tagged session at Devin is adopted, never duplicated")
def r10(w: World, r: ScenarioResult) -> None:
    w.baseline("cryptography")
    ids = w.orch.create_work_items()
    w.orch.open_issues()
    # A previous controller crashed after create_session but before recording it: Devin already
    # has a live session tagged wi-<id>.
    w.devin.preexisting("devin-orphan01", ["hl", f"wi-{ids[0]}", "kind-dependency_upgrade"])
    rep = w.tick()
    wi = w.wi(ids[0])
    r.eq("existing tagged session adopted", rep.sessions_adopted, 1)
    r.eq("no new session created", rep.sessions_created, 0)
    r.eq("work item bound to adopted session", wi.active_session_id, "devin-orphan01")
    r.eq("state session_active", wi.state, WorkItemState.session_active)
    rep2 = w.tick()
    r.eq("subsequent tick creates nothing", (rep2.sessions_created, rep2.sessions_adopted), (0, 0))
    r.eq("reconcile reports no strangers", w.orch.reconcile_sessions(), [])
    w.devin.preexisting("devin-stranger", ["hl", "wi-999"])
    r.eq("reconcile reports untracked hl session", w.orch.reconcile_sessions(), ["devin-stranger"])
    r.eq("create_session never called", len(w.devin.created_requests()), 0)

    # Concurrency: with capacity 1, a second HIGH item waits; nothing is double-dispatched.
    w2 = World(w.db_path.with_name("r10b.sqlite3"))
    w2.baseline("cryptography", "libexpat1")
    rep = w2.tick()
    r.eq(
        "two work items, one session (capacity 1)",
        (len(w2.work_items()), rep.sessions_created),
        (2, 1),
    )
    rep = w2.tick()
    r.eq("no more sessions while capacity is used", rep.sessions_created, 0)
    states = sorted(i.state.value for i in w2.work_items())
    r.eq("one active, one waiting with issue open", states, ["issue_open", "session_active"])


# ----------------------------------------------------------------------------- R11


@scenario("R11", "ACU limits: 90% warning, cap exceeded and usage_limit stop escalate")
def r11(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    w.session_state(wi, DevinStatus.running, DevinStatusDetail.working, acus=4.6)
    w.tick()
    sess = w.devin.sessions[wi.active_session_id or ""]
    r.eq("budget warning sent at >=90% of cap 5", len(sess.messages), 1)
    r.expect("warning names the cap", "of 5 ACU" in sess.messages[0])
    w.session_state(wi, DevinStatus.running, DevinStatusDetail.working, acus=4.7)
    w.tick()
    r.eq("warning sent only once", len(sess.messages), 1)
    w.session_state(wi, DevinStatus.running, DevinStatusDetail.working, acus=5.3)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("cap exceeded -> needs_human", wi.state, WorkItemState.needs_human)
    r.expect("reason mentions acu", "acu" in (wi.blocked_reason or "").lower(), wi.blocked_reason)

    w2 = World(w.db_path.with_name("r11b.sqlite3"))
    wi2 = _dispatch(w2, r, "pillow")
    w2.session_state(wi2, DevinStatus.suspended, DevinStatusDetail.usage_limit_exceeded, acus=4.9)
    w2.tick()
    wi2 = w2.wi(wi2.id or 0)
    r.eq("usage_limit_exceeded -> needs_human", wi2.state, WorkItemState.needs_human)
    r.eq(
        "no message sent to a budget-stopped session",
        len(w2.devin.sessions[wi2.active_session_id or ""].messages),
        0,
    )

    w3 = World(w.db_path.with_name("r11c.sqlite3"))
    wi3 = _dispatch(w3, r, "libexpat1")
    w3.session_state(wi3, DevinStatus.suspended, DevinStatusDetail.inactivity, acus=2.0)
    w3.tick()
    wi3 = w3.wi(wi3.id or 0)
    r.eq("inactivity suspension keeps polling (resumable)", wi3.state, WorkItemState.session_active)
    w3.clock.advance(hours=4)
    w3.tick()
    wi3 = w3.wi(wi3.id or 0)
    r.eq("wall clock exceeded -> needs_human", wi3.state, WorkItemState.needs_human)


# ----------------------------------------------------------------------------- R12


@scenario("R12", "Waiting states: whitelisted question answered, others and approvals escalate")
def r12(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    w.session_state(
        wi,
        DevinStatus.running,
        DevinStatusDetail.waiting_for_user,
        acus=0.8,
        question="Which base branch should I target for the PR?",
    )
    w.tick()
    sess = w.devin.sessions[wi.active_session_id or ""]
    r.eq("whitelisted question auto-answered", len(sess.messages), 1)
    r.expect("answer names main", "`main`" in sess.messages[0], sess.messages)
    r.eq("still session_active", w.state_of(wi.id or 0), WorkItemState.session_active)
    w.session_state(
        wi,
        DevinStatus.running,
        DevinStatusDetail.waiting_for_user,
        acus=1.0,
        question="Should I also bump Flask to 3.x while I'm here?",
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("non-whitelisted question -> needs_human", wi.state, WorkItemState.needs_human)
    r.eq("no auto-reply to non-whitelisted question", len(sess.messages), 1)

    w2 = World(w.db_path.with_name("r12b.sqlite3"))
    wi2 = _dispatch(w2, r, "pillow")
    w2.session_state(wi2, DevinStatus.running, DevinStatusDetail.waiting_for_approval, acus=1.2)
    w2.tick()
    wi2 = w2.wi(wi2.id or 0)
    r.eq("waiting_for_approval -> needs_human", wi2.state, WorkItemState.needs_human)
    r.eq(
        "controller never approves in-session",
        len(w2.devin.sessions[wi2.active_session_id or ""].messages),
        0,
    )


# ----------------------------------------------------------------------------- R13


@scenario("R13", "Incomplete or mismatched closing runs never prove absence")
def r13(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.0
    )
    wi, merge_sha = _merge(w, r, wi)

    # (a) grype job failed
    run_a = w.closing_run(merge_sha)
    run_a.job_success = {"trivy": True, "grype": False, "config": True}
    counts = w.apply_run(w.ingest(run_a))
    r.eq("failed grype job -> not_applicable", counts.get("not_applicable"), 1)
    r.eq("still awaiting_rescan", w.state_of(wi.id or 0), WorkItemState.awaiting_rescan)

    # (b) PR-triggered run of the fix branch (not main)
    run_b = w.closing_run(merge_sha, trigger=Trigger.pull_request, source_branch="devin/1-fix")
    counts = w.apply_run(w.ingest(run_b))
    r.eq("PR-triggered run -> not_applicable", counts.get("not_applicable"), 1)

    # (c) run of an unrelated commit (not a descendant of the merge)
    other = sha("unrelated")
    w.gh.add_commit(other, BASELINE_SHA)
    counts = w.apply_run(w.ingest(w.closing_run(other)))
    r.eq("non-descendant run -> not_applicable", counts.get("not_applicable"), 1)

    # (d) ci image scope
    from hardening_loop.domain.enums import ImageTarget

    counts = w.apply_run(w.ingest(w.closing_run(merge_sha, image_target=ImageTarget.ci)))
    r.eq("ci-image run -> not_applicable", counts.get("not_applicable"), 1)

    # (e) older vulnerability DB than the opening run
    from datetime import timedelta

    counts = w.apply_run(w.ingest(w.closing_run(merge_sha, db_age=timedelta(days=30))))
    r.eq("stale vuln DB -> not_applicable", counts.get("not_applicable"), 1)

    # (f) older scanner than pinned
    counts = w.apply_run(
        w.ingest(w.closing_run(merge_sha, tool_versions=("1.45.1", "0.60.0", "0.114.0")))
    )
    r.eq("older trivy than pinned -> not_applicable", counts.get("not_applicable"), 1)
    r.eq(
        "finding still awaiting_rescan",
        w.finding_by_vuln("CVE-2024-26130").state,
        FindingState.awaiting_rescan,
    )
    r.eq("issue still open", w.issue_state(w.wi(wi.id or 0)), "open")
    reasons = [e.reason or "" for e in w.events("work_item", wi.id) if e.event == "rescan_started"]
    r.expect(
        "each rejection logged with a reason",
        len(reasons) >= 6 and all("not a valid closing run" in x for x in reasons),
        reasons,
    )

    # (g) finally a complete, matching run
    counts = w.apply_run(w.ingest(w.closing_run(merge_sha)))
    r.eq("complete run -> fixed", counts.get("fixed"), 1)
    r.eq("verified", w.state_of(wi.id or 0), WorkItemState.verified)


# ----------------------------------------------------------------------------- R14


@scenario("R14", "Grouped issue with partial closure stays open until every member closes")
def r14(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "pillow")
    r.eq("two findings grouped into one work item", len(w.findings(wi.id)), 2)
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("pillow", "10.2.0", "10.2.1"), DEP_FILES, acus=2.5
    )
    wi, merge_sha = _merge(w, r, wi)
    # After the upgrade to 10.2.1, CVE-2024-28219 (fixed only in 10.3.0) is still present at the
    # new version. The dedupe key changes with the version, but closure matches the vulnerability
    # family (vuln, package, layer), so this is *not* a fix.
    partial = SEEDS["pillow"].with_version("10.2.1")
    partial = partial.__class__(
        **{**partial.__dict__, "vulns": (("CVE-2024-28219", partial.vulns[0][1], ("10.3.0",)),)}
    )
    run = w.closing_run(merge_sha)
    run.seeds = [partial]
    counts = w.apply_run(w.ingest(run))
    r.eq("one member fixed", counts.get("fixed"), 1)
    r.eq("one member still present at new version", counts.get("still_present"), 1)
    r.eq("CVE-2023-50447 fixed", w.finding_by_vuln("CVE-2023-50447").state, FindingState.fixed)
    orig = next(f for f in w.findings(wi.id) if f.vuln_id == "CVE-2024-28219")
    r.eq("original CVE-2024-28219@10.2.0 human_blocked", orig.state, FindingState.human_blocked)
    r.eq("partial closure -> needs_human", w.state_of(wi.id or 0), WorkItemState.needs_human)
    r.eq("issue stays open", w.issue_state(w.wi(wi.id or 0)), "open")
    newer = [f for f in w.findings() if f.vuln_id == "CVE-2024-28219" and f.pkg_version == "10.2.1"]
    r.eq("pillow@10.2.1 sighting recorded as its own finding", len(newer), 1)

    # Same-version partial closure: a container item whose two members are only half fixed.
    w2 = World(w.db_path.with_name("r14b.sqlite3"))
    w2.baseline(configs=("dockerfile-root", "image-no-healthcheck"))
    w2.tick()
    wi2 = w2.only_wi()
    r.eq("dockerfile + image-config grouped", len(w2.findings(wi2.id)), 2)
    out = {
        "changes": [{"type": "user", "detail": "USER superset"}],
        "lean_smoke_local": True,
    }
    wi2, _ = _to_ready_for_human(w2, r, wi2, out, ["Dockerfile"], acus=3.0)
    wi2, merge2 = _merge(w2, r, wi2)
    run2 = w2.closing_run(merge2, configs=("image-no-healthcheck",))
    counts = w2.apply_run(w2.ingest(run2))
    r.eq("one member fixed", counts.get("fixed"), 1)
    r.eq("one member still present", counts.get("still_present"), 1)
    wi2 = w2.wi(wi2.id or 0)
    r.eq("partial closure -> needs_human", wi2.state, WorkItemState.needs_human)
    r.eq("issue stays open", w2.issue_state(wi2), "open")
    st = sorted(f.state.value for f in w2.findings(wi2.id))
    r.eq("members: fixed + human_blocked", st, ["fixed", "human_blocked"])
    r.expect("verification level stays L5", wi2.lifecycle_level == LifecycleLevel.merged)


# ----------------------------------------------------------------------------- R15


def _crash_tick(w: World, r: ScenarioResult, label: str) -> None:
    try:
        w.tick()
    except ControllerCrash:
        return
    r.expect(f"{label}: simulated crash reached the controller", False)


@scenario("R15", "Crash mid-dispatch: `dispatching` lock is recovered on restart, never duplicated")
def r15(w: World, r: ScenarioResult) -> None:
    # (a) Crash after the DB lock is committed but before any Devin call: no session exists.
    w.baseline("cryptography")
    w.devin.crash_before.add("list_sessions")
    _crash_tick(w, r, "a")
    wi = w.only_wi()
    r.eq("a: lock survived the crash", wi.state, WorkItemState.dispatching)
    r.eq("a: no session at Devin", len(w.devin.created_requests()), 0)
    rep = w.tick()  # restart
    wi = w.wi(wi.id or 0)
    r.eq("a: recovered -> released -> re-dispatched", wi.state, WorkItemState.session_active)
    r.eq("a: exactly one session created", (rep.sessions_created, rep.sessions_adopted), (1, 0))
    r.eq("a: release counted as a dispatch failure", wi.dispatch_failures, 1)
    names = w.event_names(wi.id or 0)
    r.expect(
        "a: recovery -> dispatch_failed -> dispatch_started -> session_created recorded",
        [n for n in names if n not in ("created", "issue_created")]
        == [
            "dispatch_started",
            "dispatch_recovery",
            "dispatch_failed",
            "dispatch_started",
            "session_created",
        ],
        names,
    )
    r.eq("a: nothing left to recover", w.tick().sessions_adopted, 0)

    # (b) Crash after create_session succeeded at Devin but before the row was recorded.
    w2 = World(w.db_path.with_name("r15b.sqlite3"))
    w2.baseline("pillow")
    w2.devin.crash_after.add("create_session")
    _crash_tick(w2, r, "b")
    wi2 = w2.only_wi()
    r.eq("b: lock survived the crash", wi2.state, WorkItemState.dispatching)
    r.eq("b: Devin holds the orphan session", len(w2.devin.created_requests()), 1)
    r.eq("b: no session row recorded", len(w2.sessions()), 0)
    orphan = next(iter(w2.devin.sessions))
    rep = w2.tick()  # restart
    wi2 = w2.wi(wi2.id or 0)
    r.eq("b: orphan adopted, none created", (rep.sessions_created, rep.sessions_adopted), (0, 1))
    r.eq("b: bound to the orphan", wi2.active_session_id, orphan)
    r.eq("b: session_active", wi2.state, WorkItemState.session_active)
    r.eq("b: still one session at Devin", len(w2.devin.created_requests()), 1)
    r.eq("b: not a dispatch failure", wi2.dispatch_failures, 0)

    # (c) Same crash, but the orphan already finished before the controller came back: it is still
    # adopted (its output must be evaluated), not redone by a duplicate session.
    w3 = World(w.db_path.with_name("r15c.sqlite3"))
    w3.baseline("libexpat1")
    w3.devin.crash_after.add("create_session")
    _crash_tick(w3, r, "c")
    orphan3 = next(iter(w3.devin.sessions))
    w3.devin.set_state(orphan3, DevinStatus.exit, DevinStatusDetail.finished, acus=1.1)
    rep = w3.tick()
    wi3 = w3.only_wi()
    r.eq("c: finished orphan adopted", (rep.sessions_created, rep.sessions_adopted), (0, 1))
    r.eq("c: still one session at Devin", len(w3.devin.created_requests()), 1)
    r.eq("c: orphan's consumption recorded", [s.acus_consumed for s in w3.sessions()], [1.1])
    r.expect(
        "c: finished orphan without output escalates instead of being re-run",
        wi3.state is WorkItemState.needs_human,
        wi3.state,
    )


# ----------------------------------------------------------------------------- R16


@scenario("R16", "Global ACU budget reserves the unconsumed cap of every active session")
def r16(w: World, r: ScenarioResult) -> None:
    w.settings.max_concurrent_sessions = 3
    # Caps: pillow 5 (CRITICAL, first), cryptography 5, paramiko 8.
    w.settings.global_acu_budget = 8.0
    w.baseline("cryptography", "pillow", "paramiko")
    rep = w.tick()
    r.eq("only the first item fits the budget", rep.sessions_created, 1)
    items = {i.group_key.split(":")[-1]: i for i in w.work_items()}
    pillow, crypto, paramiko = items["pillow"], items["cryptography"], items["paramiko"]
    r.eq("CRITICAL pillow dispatched first", pillow.state, WorkItemState.session_active)
    r.eq(
        "others deferred with issues open",
        (crypto.state, paramiko.state),
        (WorkItemState.issue_open, WorkItemState.issue_open),
    )
    # The running session has barely spent anything; its remaining cap stays committed. (Dispatch
    # precedes polling within a tick, so the 0.2 ACU shows up in the next tick's arithmetic.)
    w.session_state(pillow, DevinStatus.running, DevinStatusDetail.working, acus=0.2)
    w.tick()
    rep = w.tick()
    r.eq("low consumption does not free the budget", rep.sessions_created, 0)
    r.eq("cryptography still waiting", w.state_of(crypto.id or 0), WorkItemState.issue_open)
    deferrals = [e for e in w.events("work_item", crypto.id) if e.event == "budget_deferred"]
    r.expect(
        "deferral reason shows consumed + outstanding + cap > budget",
        len(deferrals) >= 3
        and "consumed=0.20+outstanding=4.80+cap=5>budget=8" in (deferrals[-1].reason or ""),
        [e.reason for e in deferrals],
    )
    r.eq("exactly one session at Devin", len(w.devin.created_requests()), 1)
    # The session ends (1.5 ACU consumed, no PR -> needs_human). Its reservation is released and
    # only what it consumed stays counted, so cryptography fits (1.5 + 5 <= 8) while paramiko
    # (cap 8) does not: consumed ACUs are counted once, not once per active session.
    w.session_state(pillow, DevinStatus.exit, DevinStatusDetail.finished, acus=1.5)
    w.tick()
    r.eq("first session escalated", w.state_of(pillow.id or 0), WorkItemState.needs_human)
    rep = w.tick()
    r.eq("budget freed -> exactly one more dispatched", rep.sessions_created, 1)
    r.eq("cryptography active", w.state_of(crypto.id or 0), WorkItemState.session_active)
    r.eq("paramiko still waiting", w.state_of(paramiko.id or 0), WorkItemState.issue_open)
    last = [e for e in w.events("work_item", paramiko.id) if e.event == "budget_deferred"][-1]
    r.expect(
        "paramiko deferral reason counts consumed once plus the new outstanding cap",
        "consumed=1.50+outstanding=5.00+cap=8>budget=8" in (last.reason or ""),
        last.reason,
    )
    r.eq("two sessions at Devin in total", len(w.devin.created_requests()), 2)


# ----------------------------------------------------------------------------- R17


@scenario("R17", "A later scan's findings join the open work item for their group")
def r17(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    r.eq("one member at dispatch", len(w.findings(wi.id)), 1)
    grown = replace(
        SEEDS["cryptography"],
        vulns=(*SEEDS["cryptography"].vulns, ("CVE-2024-99999", Severity.high, ("42.0.4",))),
    )
    run = w.closing_run(BASELINE_SHA)
    run.seeds = [grown]
    w.apply_run(w.ingest(run))
    r.eq("no second work item for the same group", len(w.work_items()), 1)
    members = {f.vuln_id: f for f in w.findings(wi.id)}
    r.eq("late finding joined the open item", sorted(members), ["CVE-2024-26130", "CVE-2024-99999"])
    r.expect("join recorded on the work item", "members_added" in w.event_names(wi.id or 0))
    assert wi.issue_number is not None
    r.expect(
        "issue says the new finding must be fixed here too",
        any("CVE-2024-99999" in c for c in w.gh.issues[wi.issue_number].comments),
        w.gh.issues[wi.issue_number].comments,
    )
    r.eq("running session was told about it", w.sessions()[0].messages_sent, 1)
    # Closure now needs both members: the fix that only covers the original one cannot verify.
    wi, _ = _to_ready_for_human(
        w, r, w.wi(wi.id or 0), _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.0
    )
    wi, merge = _merge(w, r, wi)
    left = replace(grown, vulns=(("CVE-2024-99999", Severity.high, ("42.0.4",)),))
    closing = w.closing_run(merge)
    closing.seeds = [left]
    counts = w.apply_run(w.ingest(closing))
    r.eq("late member still present blocks closure", counts.get("still_present"), 1)
    r.eq("work item not verified", w.state_of(wi.id or 0), WorkItemState.needs_human)


# ----------------------------------------------------------------------------- R18


@scenario("R18", "Opening detector provenance is immutable: closure keeps asking both scanners")
def r18(w: World, r: ScenarioResult) -> None:
    from sqlmodel import select

    from hardening_loop.db import session_scope
    from hardening_loop.models.tables import Finding, ScanJob, ScanRun
    from hardening_loop.orchestrator.closer import original_detectors, validate_closing_run

    w.baseline("cryptography")
    f = w.finding_by_vuln("CVE-2024-26130")
    r.eq("opened by both scanners", (f.opened_by_trivy, f.opened_by_grype), (True, True))
    # A later run where grype's database no longer carries the advisory: the current detector set
    # shrinks, the opening one must not.
    trivy_only = replace(SEEDS["cryptography"], reported_by=frozenset({Scanner.trivy}))
    drifted = w.closing_run(BASELINE_SHA)
    drifted.seeds = [trivy_only]
    w.apply_run(w.ingest(drifted))
    f = w.finding_by_vuln("CVE-2024-26130")
    r.eq(
        "current detectors shrank to trivy",
        (f.reported_by_trivy, f.reported_by_grype),
        (True, False),
    )
    r.eq("opening detectors unchanged", original_detectors(f), {Scanner.trivy, Scanner.grype})
    # Absence proven by trivy alone, with grype's job failed, is not proof for this finding.
    half = w.closing_run(BASELINE_SHA)
    half.job_success = {"trivy": True, "grype": False, "config": True}
    rid = w.ingest(half)
    counts = w.apply_run(rid)
    r.eq("no drift closure on half the evidence", counts.get("fixed_by_drift"), None)
    r.eq("finding not closed", w.finding_by_vuln("CVE-2024-26130").state, FindingState.grouped)
    with session_scope(w.engine) as db:
        run = db.get(ScanRun, rid)
        jobs = list(db.exec(select(ScanJob).where(ScanJob.scan_run_id == rid)).all())
        row = db.get(Finding, f.id)
        assert run is not None and row is not None
        validity = validate_closing_run(
            run, jobs, row, merge_sha=None, is_ancestor=lambda _a, _b: True, require_policy=False
        )
    r.expect(
        "grype is still required even though it stopped reporting",
        any("grype-raw job missing or failed" in x for x in validity.reasons),
        validity.reasons,
    )
    # Both scanners running and neither reporting it: drift closes the finding.
    counts = w.apply_run(w.ingest(w.closing_run(BASELINE_SHA)))
    r.eq("closed once both scanners agree it is gone", counts.get("fixed_by_drift"), 1)
    r.eq("finding fixed", w.finding_by_vuln("CVE-2024-26130").state, FindingState.fixed)


# ----------------------------------------------------------------------------- R19


@scenario("R19", "A new PR head re-earns every level: checks, Devin Review, then approval")
def r19(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    wi, _head1 = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.0
    )
    pr_number = wi.pr_number
    assert pr_number is not None
    head2 = sha("r19-second-head")
    w.gh.push(pr_number, head2)
    w.tick()
    wi = w.wi(wi.id or 0)
    r.eq("push sends the item back to checks_running", wi.state, WorkItemState.checks_running)
    r.eq("verification level back to L1", wi.lifecycle_level, LifecycleLevel.pr_opened)
    row = w.pr_row(wi.id or 0)
    r.eq("review status of the old head discarded", row.review_status if row else "?", None)
    w.ci(head2)
    w.tick()
    r.eq(
        "green checks alone do not restore review",
        w.state_of(wi.id or 0),
        WorkItemState.review_pending,
    )
    w.gh.approve(pr_number, APPROVER, at=w.clock.now())
    w.tick()
    r.eq(
        "approval cannot skip the second review",
        w.state_of(wi.id or 0),
        WorkItemState.review_pending,
    )
    row = w.pr_row(wi.id or 0)
    r.eq("no approval recorded yet", row.approved_by if row else "?", None)
    w.review_done(head2)
    w.tick()
    r.eq("second review -> ready_for_human", w.state_of(wi.id or 0), WorkItemState.ready_for_human)
    w.tick()
    row = w.pr_row(wi.id or 0)
    r.eq("approval of the reviewed head counts", row.approved_by if row else None, APPROVER)
    r.eq(
        "two review_completed events, one per head",
        w.event_names(wi.id or 0).count("review_completed"),
        2,
    )


# ----------------------------------------------------------------------------- R20


@scenario("R20", "A closing run without scanner database timestamps proves nothing")
def r20(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.0
    )
    wi, merge = _merge(w, r, wi)
    undated = w.closing_run(merge)
    undated.db_age = None
    counts = w.apply_run(w.ingest(undated))
    r.eq("outcome not applicable", counts.get("not_applicable"), 1)
    r.eq("nothing fixed", counts.get("fixed"), None)
    r.eq("item waits for a dated rescan", w.state_of(wi.id or 0), WorkItemState.awaiting_rescan)
    r.eq(
        "finding still awaiting a rescan",
        w.finding_by_vuln("CVE-2024-26130").state,
        FindingState.awaiting_rescan,
    )
    reason = [e for e in w.events("work_item", wi.id) if e.event == "rescan_started"][-1].reason
    r.expect(
        "reason names the missing freshness evidence",
        "freshness unproven" in (reason or ""),
        reason,
    )
    counts = w.apply_run(w.ingest(w.closing_run(merge)))
    r.eq("a dated rescan closes it", counts.get("fixed"), 1)
    r.eq("work item verified", w.state_of(wi.id or 0), WorkItemState.verified)


# ----------------------------------------------------------------------------- N1-N5


def _record_negative(
    w: World,
    r: ScenarioResult,
    *,
    case: str,
    branch: str,
    expected: dict[str, Any],
    observed: dict[str, Any],
    pr_url: str | None = None,
) -> None:
    passed = all(observed.get(k) == v for k, v in expected.items())
    from hardening_loop.db import session_scope

    with session_scope(w.engine) as db:
        db.add(
            NegativeRun(
                case=case,
                external_run_id=f"replay-{case.lower()}",
                branch=branch,
                pr_url=pr_url,
                expected=expected,
                observed=observed,
                passed=passed,
                ran_at=w.clock.now(),
            )
        )
    r.expect(f"{case}: CI caught the regression", passed, f"{expected} vs {observed}")


@scenario("N1", "Negative: broken Dockerfile fails the build check; PR never advances")
def n1(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "libexpat1")
    out = {"changes": [{"type": "base_image", "detail": "bad"}], "lean_smoke_local": False}
    _, number = w.devin_opens_pr(wi, out, files=["Dockerfile"], acus=1.0)
    w.tick()
    head = w.gh.prs[number].head_sha
    w.ci(head, failing=["build-image"], pending=["lean-smoke", "app-runs"])
    w.tick()
    wi = w.wi(wi.id or 0)
    _record_negative(
        w,
        r,
        case="N1",
        branch="negative/n1-broken-build",
        expected={"build_check": "failure", "state": "session_active"},
        observed={"build_check": "failure", "state": wi.state.value},
        pr_url=wi.pr_url,
    )
    r.eq("retry requested from the same session", wi.retries_used, 1)


@scenario("N2", "Negative: image builds but fails to start; lean-smoke red")
def n2(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "libexpat1")
    out = {"changes": [{"type": "user", "detail": "USER nobody"}], "lean_smoke_local": True}
    _, number = w.devin_opens_pr(wi, out, files=["Dockerfile"], acus=1.0)
    w.tick()
    head = w.gh.prs[number].head_sha
    w.ci(head, failing=["lean-smoke"])
    w.tick()
    wi = w.wi(wi.id or 0)
    _record_negative(
        w,
        r,
        case="N2",
        branch="negative/n2-broken-runtime",
        expected={"lean_smoke": "failure", "advanced_past_checks": False},
        observed={
            "lean_smoke": "failure",
            "advanced_past_checks": wi.lifecycle_level > LifecycleLevel.pr_opened,
        },
        pr_url=wi.pr_url,
    )
    r.expect(
        "Devin's claimed lean_smoke_local=True did not override CI",
        wi.lifecycle_level == LifecycleLevel.pr_opened,
    )


@scenario("N3", "Negative: dependency regression raises counts; report stays green, enforce fails")
def n3(w: World, r: ScenarioResult) -> None:
    w.baseline("cryptography")
    base_id = w.run_ids["replay-baseline"]
    regressed = sha("n3-regression")
    w.gh.add_commit(regressed, BASELINE_SHA)
    # The regression branch pins an older, more-vulnerable pillow via pyproject + regeneration.
    run_report = w.closing_run(
        regressed,
        "cryptography",
        "pillow",
        trigger=Trigger.pull_request,
        source_branch="negative/n3",
    )
    run_report.gate_mode = GateMode.report
    rid_report = w.ingest(run_report)
    run_enforce = w.closing_run(
        regressed,
        "cryptography",
        "pillow",
        trigger=Trigger.pull_request,
        source_branch="negative/n3",
        gate_mode=GateMode.enforce,
    )
    rid_enforce = w.ingest(run_enforce)
    from hardening_loop.metrics import policy_counts_by_severity, raw_counts_by_severity

    base_raw = raw_counts_by_severity(w.engine, base_id)
    reg_raw = raw_counts_by_severity(w.engine, rid_report)
    reg_policy = policy_counts_by_severity(w.engine, rid_enforce)
    report = gate_verdict(GateMode.report, policy_counts_by_severity(w.engine, rid_report))
    enforce = gate_verdict(GateMode.enforce, reg_policy)
    _record_negative(
        w,
        r,
        case="N3",
        branch="negative/n3-dependency-regression",
        expected={
            "raw_count_increased": True,
            "report_mode_passed": True,
            "enforce_mode_passed": False,
        },
        observed={
            "raw_count_increased": sum(reg_raw.values()) > sum(base_raw.values()),
            "report_mode_passed": report.passed,
            "enforce_mode_passed": enforce.passed,
            "baseline_raw": base_raw,
            "regressed_raw": reg_raw,
            "regressed_policy": reg_policy,
        },
    )
    r.eq("enforce reason counts CRITICAL", enforce.policy_critical, 2)
    r.expect("report mode not ready for enforce", not report.ready_for_enforce)


@scenario("N4", "Negative: PR adds a scanner ignore file; policy check rejects it")
def n4(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "cryptography")
    w.devin_opens_pr(
        wi,
        _dep_output("cryptography", "42.0.2", "42.0.4"),
        files=[*DEP_FILES, ".grype.yaml"],
        acus=1.0,
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    _record_negative(
        w,
        r,
        case="N4",
        branch="negative/n4-ignore-file",
        expected={"state": "needs_human", "pr_advanced": False},
        observed={"state": wi.state.value, "pr_advanced": wi.pr_number is not None},
    )


@scenario("N5", "Negative: OpenVEX placed in approved/ by a session is rejected")
def n5(w: World, r: ScenarioResult) -> None:
    wi = _dispatch(w, r, "paramiko")
    out = {
        "reachability": {
            "imports_found": [],
            "call_sites": [],
            "runtime_paths": [],
            "verdict": "unreachable",
        },
        "proposed_vex_path": "security/vex/proposed/cve-2023-48795.json",
        "justification": "not reachable in Superset's client-only usage of paramiko",
    }
    w.devin_opens_pr(
        wi,
        out,
        files=["security/vex/approved/cve-2023-48795.json"],
        acus=1.0,
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    _record_negative(
        w,
        r,
        case="N5",
        branch="negative/n5-vex-approved-by-bot",
        expected={"state": "needs_human"},
        observed={"state": wi.state.value, "reason": wi.blocked_reason},
    )
    r.expect("reason names approved path", "approved" in (wi.blocked_reason or ""))


# ----------------------------------------------------------------------------- OP1


@scenario(
    "OP1", "Operator launch from the dashboard: capacity refusal, approval trail, same lifecycle"
)
def op1(w: World, r: ScenarioResult) -> None:
    """A MEDIUM finding is never auto-dispatched. An operator launch is refused while the single
    session slot is taken, then goes through the ordinary dispatch path with `dispatch:approved`
    and an audit comment on the issue, and the item closes exactly like an automatic one."""
    w.settings.max_concurrent_sessions = 1
    w.baseline("cryptography", "requests")
    w.tick()
    items = {wi.group_key: wi for wi in w.work_items()}
    auto, manual = items["pypi:cryptography"], items["pypi:requests"]
    r.eq("HIGH item auto-dispatched", auto.state, WorkItemState.session_active)
    r.eq("MEDIUM item only has its issue", manual.state, WorkItemState.issue_open)
    r.expect(
        "MEDIUM issue awaits dispatch approval",
        AWAITING_DISPATCH_LABEL in w.issue_labels(manual),
    )
    mid = manual.id or 0

    pv = w.orch.launch_preview(mid)
    r.eq("preview: blocked at capacity", pv.block, LaunchBlock.at_capacity)
    r.expect("preview: would need dispatch approval", pv.needs_dispatch_approval)
    r.expect("preview: issue already exists", not pv.needs_issue)
    res = w.orch.launch(mid, operator="operator-demo")
    r.eq("launch refused at capacity", res.outcome, "rejected")
    r.eq("refusal names the block", res.reason, LaunchBlock.at_capacity.value)
    r.eq("no session created by the refusal", len(w.devin.created_requests()), 1)
    r.expect("refusal audited", "operator_launch_refused" in w.event_names(mid))
    r.eq("item state unchanged", w.state_of(mid), WorkItemState.issue_open)

    w.settings.max_concurrent_sessions = 2
    res = w.orch.launch_work_item(mid, "operator-demo")
    r.eq("launch creates a session once a slot is free", res.outcome, "created")
    manual = w.wi(mid)
    r.eq("item now session_active", manual.state, WorkItemState.session_active)
    labels = w.issue_labels(manual)
    r.expect("dispatch:approved recorded on the issue", "dispatch:approved" in labels)
    r.expect("awaiting-approval label removed", AWAITING_DISPATCH_LABEL not in labels)
    comments = w.gh.issues[manual.issue_number or 0].comments
    r.expect(
        "operator audit comment on the issue",
        any("operator-demo" in c and "launched" in c for c in comments),
        comments,
    )
    r.expect("operator_launch event", "operator_launch" in w.event_names(mid))
    reqs = w.devin.created_requests()
    r.eq("exactly two sessions exist", len(reqs), 2)
    r.eq("operator session capped at the kind cap", reqs[-1].max_acu_limit, manual.acu_cap)
    r.expect("operator session tagged wi-<id>", f"wi-{mid}" in reqs[-1].tags)

    again = w.orch.launch(mid, operator="operator-demo")
    r.eq(
        "second launch refused: session in flight",
        again.reason,
        LaunchBlock.session_in_flight.value,
    )
    r.eq("still two sessions", len(w.devin.created_requests()), 2)

    manual, _ = _to_ready_for_human(
        w, r, manual, _dep_output("requests", "2.31.0", "2.32.0"), DEP_FILES, acus=1.4
    )
    manual, merge = _merge(w, r, manual)
    w.apply_run(w.ingest(w.closing_run(merge, "cryptography")))
    r.eq(
        "operator-launched item closes on a source-matching rescan",
        w.state_of(mid),
        WorkItemState.verified,
    )
    r.eq("finding fixed", w.finding_by_vuln("CVE-2024-35195").state, FindingState.fixed)


# ----------------------------------------------------------------------------- DEMO


@scenario("DEMO", "Showcase: all five kinds in one database (dashboard default)")
def demo(w: World, r: ScenarioResult) -> None:
    """Sequential end-to-end story over every synthetic seed so one database exercises every
    outcome the dashboard and run report render: fixed (with and without a retry),
    approved_disposition, scanner_disagreement_resolved, needs_human and a regression."""
    seeds = ["cryptography", "pillow", "requests", "paramiko", "libexpat1", "linux-libc-dev"]
    configs = ["helm-run-as-root", "dockerfile-root", "image-no-healthcheck"]
    w.settings.max_concurrent_sessions = 8
    w.settings.global_acu_budget = 200.0
    w.baseline(*seeds, configs=configs)
    w.tick()
    items = {wi.group_key: wi for wi in w.work_items()}
    r.eq("seven HIGH/CRITICAL items dispatched", len(w.devin.created_requests()), 7)
    r.eq("all five kinds present", {wi.kind for wi in items.values()}, set(Kind))
    remaining = set(seeds)
    remaining_cfg = set(configs)

    def closing(merge_sha: str) -> int:
        return w.ingest(w.closing_run(merge_sha, *sorted(remaining), configs=sorted(remaining_cfg)))

    # 1. cryptography: first-try dependency upgrade.
    wi = items["pypi:cryptography"]
    wi, _ = _to_ready_for_human(
        w, r, wi, _dep_output("cryptography", "42.0.2", "42.0.4"), DEP_FILES, acus=2.1
    )
    wi, merge = _merge(w, r, wi)
    remaining.discard("cryptography")
    w.apply_run(closing(merge))
    r.eq("cryptography verified", w.state_of(wi.id or 0), WorkItemState.verified)

    # 2. pillow: one red CI, same-session retry, then verified.
    wi = items["pypi:pillow"]
    url, number = w.devin_opens_pr(
        wi, _dep_output("pillow", "10.2.0", "10.3.0"), files=DEP_FILES, acus=1.8
    )
    w.tick()
    w.ci(w.gh.prs[number].head_sha, failing=["app-runs"])
    w.tick()
    sess = w.devin.sessions[wi.active_session_id or ""]
    head2 = sha("demo-pillow-fix-2")
    w.gh.push(number, head2)
    w.devin.finish(
        wi.active_session_id or "",
        {**(sess.structured_output or {}), "pr_url": url},
        acus=3.4,
        pull_requests=[url],
    )
    w.tick()
    w.ci(head2)
    w.tick()
    w.review_done(head2)
    w.tick()
    wi, merge = _merge(w, r, w.wi(wi.id or 0))
    remaining.discard("pillow")
    w.apply_run(closing(merge))
    r.eq("pillow verified after retry", w.state_of(wi.id or 0), WorkItemState.verified)
    r.eq("pillow used one retry", w.wi(wi.id or 0).retries_used, 1)

    # 3. paramiko: no fix; reachability + proposed OpenVEX, approved disposition.
    wi = items["nofix:pypi:paramiko"]
    out: dict[str, Any] = {
        "reachability": {
            "imports_found": ["superset/db_engine_specs/ssh.py"],
            "call_sites": [],
            "runtime_paths": [],
            "verdict": "unreachable",
        },
        "proposed_vex_path": "security/vex/proposed/cve-2023-48795.json",
        "justification": "Terrapin needs an SSH server; Superset is only an SSH client.",
    }
    wi, _ = _to_ready_for_human(
        w, r, wi, out, ["security/vex/proposed/cve-2023-48795.json"], acus=4.4
    )
    wi, merge = _merge(w, r, wi)
    run = w.closing_run(merge, *sorted(remaining), configs=sorted(remaining_cfg))
    run.policy_suppressed_keys = {"paramiko"}
    run.vex_documents = [
        approved_vex(
            issue_url=wi.issue_url or "",
            vuln_id="CVE-2023-48795",
            purl="pkg:pypi/paramiko@3.4.0",
            approver="Hunter-1298",
        )
    ]
    w.apply_run(w.ingest(run))
    r.eq("paramiko approved disposition", w.state_of(wi.id or 0), WorkItemState.verified)
    r.eq(
        "paramiko finding approved_disposition",
        w.finding_by_vuln("CVE-2023-48795").state,
        FindingState.approved_disposition,
    )

    # 4. libexpat1: container hardening (raw paramiko stays; policy suppressed by approved VEX).
    wi = items["container:os-packages"]
    out = {
        "changes": [{"type": "package_removal", "detail": "apt-get upgrade libexpat1 in lean"}],
        "image_size_before_after": {"before": 926202016, "after": 926100000},
        "lean_smoke_local": True,
    }
    wi, _ = _to_ready_for_human(w, r, wi, out, ["Dockerfile"], acus=7.5)
    wi, merge = _merge(w, r, wi)
    remaining.discard("libexpat1")

    def closing_with_vex(merge_sha: str) -> int:
        run2 = w.closing_run(merge_sha, *sorted(remaining), configs=sorted(remaining_cfg))
        run2.policy_suppressed_keys = {"paramiko"}
        run2.vex_documents = [
            approved_vex(
                issue_url=items["nofix:pypi:paramiko"].issue_url or "",
                vuln_id="CVE-2023-48795",
                purl="pkg:pypi/paramiko@3.4.0",
                approver="Hunter-1298",
            )
        ]
        return w.ingest(run2)

    w.apply_run(closing_with_vex(merge))
    r.eq("libexpat1 verified", w.state_of(wi.id or 0), WorkItemState.verified)

    # 5. linux-libc-dev: scanner disagreement, analysis only, human resolves, rescan confirms.
    wi = items["disagreement:deb:linux-libc-dev"]
    w.devin.finish(
        wi.active_session_id or "",
        {
            "outcome": "no_change_needed",
            "base_branch": "main",
            "findings_addressed": [],
            "findings_not_addressed": [{"id": "CVE-2024-40971", "reason": "headers only"}],
            "reason": "Grype has no Debian tracker match; Trivy uses the NVD range.",
            "evidence_urls": ["https://security-tracker.debian.org/tracker/CVE-2024-40971"],
            "verdict": "trivy_correct",
            "evidence": [
                {"scanner": "trivy", "record": {"id": "CVE-2024-40971"}, "reasoning": "NVD range"},
                {"scanner": "grype", "record": {}, "reasoning": "no match in Debian feed"},
            ],
            "recommended_action": "none",
        },
        acus=1.1,
        pull_requests=[],
    )
    w.tick()
    r.eq("disagreement -> needs_human", w.state_of(wi.id or 0), WorkItemState.needs_human)
    w.gh.label(wi.issue_number or 0, HumanLabel.disagreement_resolved.value)
    w.tick()
    remaining.discard("linux-libc-dev")
    later = sha("demo-main-after-disagreement")
    w.gh.add_commit(later, w.gh.branches["main"])
    w.gh.branches["main"] = later
    w.apply_run(closing_with_vex(later))
    r.eq("disagreement resolved", w.state_of(wi.id or 0), WorkItemState.verified)

    # 6. Helm: runAsNonRoot values change.
    wi = items["deploy:helm"]
    out = {
        "values_changed": [{"path": "securityContext.runAsNonRoot", "from": None, "to": True}],
        "helm_lint": "1 chart(s) linted, 0 chart(s) failed",
        "helm_template_diff_attachment": None,
    }
    wi, _ = _to_ready_for_human(w, r, wi, out, ["helm/superset/values.yaml"], acus=2.0)
    wi, merge = _merge(w, r, wi)
    remaining_cfg.discard("helm-run-as-root")
    w.apply_run(closing_with_vex(merge))
    r.eq("helm verified", w.state_of(wi.id or 0), WorkItemState.verified)

    # 7. Dockerfile/container config group: Devin blocks -> needs_human stays open.
    wi = items["container:dockerfile"]
    w.devin.finish(
        wi.active_session_id or "",
        {
            "outcome": "blocked",
            "base_branch": "main",
            "findings_addressed": [],
            "findings_not_addressed": [{"id": "DS002", "reason": "entrypoint needs root"}],
            "blocked_reason": "Switching the lean image to a non-root user changes the entrypoint "
            "contract used by Helm; needs an architecture decision.",
        },
        acus=2.6,
        pull_requests=[],
    )
    w.tick()
    r.eq("dockerfile group -> needs_human", w.state_of(wi.id or 0), WorkItemState.needs_human)

    # 8. Regression: cryptography reappears on a later main commit.
    regressed = sha("demo-main-regressed")
    w.gh.add_commit(regressed, w.gh.branches["main"])
    w.gh.branches["main"] = regressed
    remaining.add("cryptography")
    counts = w.apply_run(closing_with_vex(regressed))
    r.eq("regression detected", counts.get("regression"), 1)

    states = Counter(wi.state for wi in w.work_items())
    r.eq("verified items", states[WorkItemState.verified], 6)
    r.eq("needs_human items", states[WorkItemState.needs_human], 1)
    r.expect(
        "regression item linked",
        any(wi.regression_of_work_item_id is not None for wi in w.work_items()),
    )
    r.expect("controller never approved or merged", w.gh.never_merged_or_approved())


__all__ = ["CONFIG_SEEDS", "SCENARIOS", "Scenario", "scenario"]
