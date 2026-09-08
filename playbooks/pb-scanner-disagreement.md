---
kind: scanner_disagreement
title: Superset hardening: scanner disagreement triage (kind 4)
macro: !hl-scanner-disagreement
---
# Scanner disagreement

Exactly one of Trivy and Grype reports the findings in this session for a package both scanners
saw in the same SBOM. Your job is to decide which scanner is right and say why, with the raw records
as evidence. You do not fix anything in this session; the controller re-classifies the finding from
your verdict and a human decides what happens next.

## Boundaries

- Read-only. Open no PR and change no file in any repository.
- Never touch `apache/superset`.
- Use only the raw records in the findings attachment and the public advisory sources they cite
  (NVD, GHSA, the distro security tracker, the scanner's own database entry).
- Never claim a test you did not run; this playbook normally runs none.

## Procedure

1. For each finding, put the two raw records side by side: package name, purl, installed version,
   the version range each database says is affected, and the fix version each reports.
2. Identify the cause of the disagreement. The common ones are: one database has a wrong affected
   range; one scanner matched by CPE rather than purl and hit a different product; the package was
   backported by the distro and only one database tracks the backport; the advisory was withdrawn
   or rejected; the ecosystem name differs (`pypi` vs `pip`, `deb` vs `debian`).
3. Record a `verdict`: `trivy_correct`, `grype_correct`, `both_partial` or `undetermined`. Provide
   one `evidence` entry per scanner with the raw `record` you relied on and your `reasoning`.
4. Record a `recommended_action`: `upgrade` when a real fix exists, `vex` when the finding is a
   false positive that should be documented as `not_affected`, `none` when the advisory does not
   apply at all. The controller will re-dispatch under the matching playbook if a human agrees.
5. Finish with the structured output as `no_change_needed` and put the advisory URLs you consulted
   in `evidence_urls`. Return `blocked` only when the raw records are missing or contradictory in a
   way you cannot resolve from public sources.
