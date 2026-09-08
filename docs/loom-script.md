# Loom script (under five minutes)

Recorded against `hardening-loop serve --replay --db data/replay/replay.sqlite3` for the
no-spend parts and the live database for the last minute. Times are cumulative.

**0:00 – 0:30 — What this is.**
"Apache Superset 6.1.0 has fifty known CVEs in its production image. This is a loop that finds
them, turns them into bounded Devin sessions, verifies the PRs, and only closes a finding when a
later scan of `main` proves it is gone. Two repos: the Superset fork we scan, and the controller."

**0:30 – 1:15 — Evidence first.** Open the fork's latest `security-scan` run.
"One immutable image digest is built once and carried through SBOM, both scanners, the runtime
smoke test and the full Postgres/Redis app check. Trivy and Grype run separately, each in raw
mode and in policy mode; raw JSON is never filtered, policy mode only applies OpenVEX that a human
approved and the `vex-lint` job checked. The gate is in report mode until policy HIGH/CRITICAL is
genuinely zero." Show the artifact `scan-evidence-<sha>` and `manifest.json` with checksums.

**1:15 – 2:00 — Dashboard overview.** `http://127.0.0.1:8080/`.
"Six numbers: open HIGH/CRITICAL, needs-attention, gate readiness for enforce, first-try rate,
median and p90 hours to remediation, cost per verified issue. Below, the queue of items that need a human." Click into
**CVEs**, open one. "Every CVE page is built from the persisted scanner records: advisory,
CVSS, EPSS, fix version per scanner, scanner agreement, sighting history across runs."

**2:00 – 2:45 — Launch.** From the CVE page click **Launch Devin** (doubles mode).
"Read-only by default; operator mode adds exactly one write. Confirmation, CSRF and same-origin
check, loopback only. The launch opens the GitHub issue, applies `dispatch:approved` for lower
severities, and creates one Normal session with the kind's ACU cap, playbook, knowledge note and
structured-output schema. A second click is refused while the session is active." Show the work
item timeline moving to *Session active*.

**2:45 – 3:30 — Verification, not trust.** Open a work item at *Ready for review*.
"The PR must target fork `main`, touch only dependency inputs and regenerated pins, and pass CI.
The controller triggers Devin Review for the exact head SHA and waits for `completed`. Lifecycle
and verification depth are separate: L0 requirements and pip, L1 import and migrations, L2 unit
tests, L3 the immutable-image app check; anything not run is recorded as unavailable, never
assumed." Show the depth ladder and the ACU / cost row.

**3:30 – 4:10 — Closure and the honest cases.** Open the **Report**.
"Approval and merge stay in GitHub. After the merge, the next complete scan of `main` — same
image scope, both scanners, commit a descendant of the merge — is what closes the finding.
Partial or failed scans never close anything. Regressions reopen the issue; scanner
disagreements, approved dispositions and human-blocked items are distinct outcomes, and
unclassified findings stay visible and are never dispatched."

**4:10 – 4:45 — The live run.** Switch to the live database.
"One real session, one small dependency, five ACU cap, doctor-enforced profile: no auto-dispatch,
one concurrent session, report mode. Here is the issue, the session, the PR, CI, the Review for
that exact commit, and the ACUs it actually spent. It is waiting for Hunter's approval and merge;
the finding stays open until the rescan proves it gone."

**4:45 – 5:00 — Close.**
"Everything is replayable with the network off — `hardening-loop replay` runs R0–R21, the five
negatives, the operator launch and the showcase — so the whole loop can be demonstrated without
spending anything."
