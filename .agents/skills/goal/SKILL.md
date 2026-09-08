---
name: goal
description: Execute a bounded, evidence-driven implementation goal across the Superset CVE hardening repositories. Use when the user invokes @skills:goal to complete multi-step work, open reviewed pull requests, and stop honestly on failed gates or missing access.
argument-hint: "<complete goal contract>"
triggers:
  - user
compatibility: "Devin with access to Hunter-1298/superset and Hunter-1298/superset-hardening-loop, GitHub, Docker, and each repository's test tools."
metadata:
  author: "Hunter-1298"
  project: "superset-hardening-loop"
---

# Goal execution

Treat `$ARGUMENTS` as a durable completion contract, not as permission to claim success after writing code. Continue until every stated acceptance condition is supported by current evidence or a blocked stop condition is reached.

## Project invariants

- Work only in `Hunter-1298/superset` and `Hunter-1298/superset-hardening-loop`. Never create branches, issues, pull requests, comments, or workflows in `apache/superset`.
- Preserve the Superset remediation baseline at tag `6.1.0`, commit `c83fb2bb1dcfac41ac51bcebd82471f4a7180d18`. Keep `main` for remediation and `upstream-master` for comparison.
- Keep the reusable control plane in `superset-hardening-loop` and target-specific scanning, runtime probes, remediation issues, remediation pull requests, and CI in `superset`.
- Never merge or enable auto-merge. Humans approve all merges and all no-fix or risk-acceptance dispositions.
- Never weaken tests, scanners, gates, evidence validation, branch safety, or read-only dashboard behavior merely to make a check pass.
- Raw Trivy and Grype evidence must remain unsuppressed. Policy views may apply only human-approved OpenVEX documents and must retain the raw evidence.
- Do not expose secrets. Never print, log, commit, echo, upload, or request literal credential values in chat or pull-request comments. If a named secret is absent, ask the user to provision it through the approved secret manager or runtime environment and report only presence or absence.
- Do not change repository settings, rulesets, variables, secrets, or protections unless the goal explicitly authorizes it. Preparing exact instructions or scripts is not authorization to apply them.
- Keep live Devin usage within the per-kind ACU caps: dependency upgrade 5, no-fix disposition 8, runtime hardening 20, scanner disagreement 3, deployment configuration 6. Never retry a live launch blindly.

## Operating protocol

1. **Inspect reality first.** Synchronize both repositories, read their current instructions and security documentation, inspect open and merged pull requests, issues, branches, Actions runs, configured variables, and relevant artifacts. Do not rely on an earlier plan or prompt when current code and GitHub state disagree.
2. **Build an acceptance matrix.** Translate the goal into concrete outcomes, evidence, constraints, dependencies, and blockers. Record which requirements already pass, which are missing, and which claims require live evidence.
3. **Work in dependency order.** Repair foundational scan, evidence, and negative gates before live orchestration. Finish replay and contract tests before external API calls. Make the smallest coherent changes and avoid speculative abstractions.
4. **Use reviewable branches.** Create focused branches and as few pull requests as safely possible. Keep target-repository and controller changes in their respective repositories. Document cross-repository dependencies, exact commit SHAs, and required merge order.
5. **Verify each increment.** Run formatting, lint, type checks, focused tests, full tests, replay, Docker/image checks, workflow validation, and browser/accessibility checks as applicable. Inspect generated evidence rather than inferring success from exit status alone.
6. **Exercise failure paths.** Prove fail-closed behavior for incomplete or tampered evidence, missing credentials, duplicate delivery, stale events, invalid signatures, scanner disagreement, unapproved VEX, budget exhaustion, and unsuccessful CI or review states wherever those paths are in scope.
7. **Gate live operations.** Before any real session, require all offline/replay/negative gates to pass, immutable target and controller SHAs to be recorded, required credentials to be present by name, and the intended ACU cap to be explicit. Launch at most the live work authorized by the goal.
8. **Close the review loop.** For every pull request, run the repository checks, trigger Devin Review, inspect every posted and hidden finding, fix valid findings, explain rejected findings with evidence, and rerun affected checks. If Devin Review is unavailable, stop blocked rather than claim review-complete. Leave no unresolved review thread or failing required check.
9. **Audit the final diff.** Confirm no unrelated files, mock behavior, generated secrets, scanner suppressions, auto-merge settings, placeholder code, or undocumented deviations remain. Verify that documentation describes implemented behavior rather than planned behavior.
10. **Stop without merging.** Leave each pull request ready for human review and merge. Provide exact URLs, merge order, commit SHAs, check results, review status, live-spend totals, artifacts, residual risks, and any manual repository-setting steps.

## Evidence standard

A completion claim must be independently auditable. Include, as applicable:

- exact source, controller, image, workflow-run, issue, session, and pull-request identifiers;
- commands executed and concise results, including test counts;
- raw and policy scan manifests with checksums and immutable image digests;
- replay and negative-suite results for all five remediation kinds;
- verification depth reached by each pull request, separate from lifecycle state;
- Devin Review findings and their disposition;
- screenshots or browser checks for dashboard changes;
- ACUs and estimated dollars from real session data, never fabricated values.

Do not describe a partial, skipped, mocked, or proxy result as live or complete.

## Iteration policy

After each failure, identify the earliest violated invariant or acceptance condition, inspect the smallest relevant evidence, fix the root cause, and rerun that gate plus any dependent gates. Do not broaden scope while an earlier dependency is red. If two attempts fail for the same reason, stop retrying and reassess the diagnosis before making another change or spending more ACUs.

## Blocked stop condition

Stop and ask for the minimum required user action when credentials, permissions, product decisions, human approval, external service availability, or a safe implementation path is missing. Report:

1. the unmet acceptance condition;
2. evidence gathered;
3. approaches attempted;
4. why continuing would be unsafe or misleading;
5. the exact input or action needed to resume.

A blocked report is a valid outcome. A fabricated success is not.
