---
kind: no_fix_reachability
title: Superset hardening: no-fix reachability analysis and proposed OpenVEX (kind 2)
macro: !hl-no-fix-openvex
---
# No-fix finding: reachability analysis and proposed OpenVEX

The findings in this session have no fixed version in any scanner. Your job is analysis, not a
workaround: decide whether the vulnerable code is reachable from Superset's runtime and, if you
believe it is not, propose an OpenVEX statement that a human can approve. You never approve it.

## Boundaries

- Work only in `Hunter-1298/superset`, from `main`. Never touch `apache/superset`.
- The only files you may add are under `security/vex/proposed/`. Never write to
  `security/vex/approved/`; only a human moves a document there after review.
- Never remove, pin down, or replace the vulnerable package to make the finding disappear. If a
  fix version has appeared since the scan, stop and return `blocked` so the controller can
  re-classify the finding as an upgrade.
- Never add scanner ignore files.
- Never claim a test you did not run; reachability conclusions must cite the code paths you read.
- Use the role and capability matrix in `SECURITY.md`: name the principal an attacker would need and
  the matrix row a successful exploit would violate.

## Procedure

1. For every finding, read the advisory and identify the vulnerable symbol(s) or code path.
2. Search the Superset codebase for imports of the package (`imports_found`) and every call site
   that can reach the vulnerable symbol (`call_sites` with file, line, symbol). Include transitive
   use through Superset's own dependencies where you can show the path.
3. Trace each call site to a runtime entry point: an API route, a CLI command, a Celery task or a
   startup path (`runtime_paths`). A path you cannot rule in or out makes the verdict `unknown`.
4. Record a `verdict`: `reachable`, `unreachable` or `unknown`.
5. If and only if the verdict is `unreachable`, write one OpenVEX document at
   `security/vex/proposed/<CVE>.openvex.json` with `status: not_affected`, a `justification`
   from the OpenVEX vocabulary (`vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
   `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`),
   an `impact_statement` that repeats your evidence, and the product identified by the exact
   image digest and package purl from the findings attachment. Reference the tracking issue in
   the statement.
6. Open one PR against `main` containing only the proposed document(s) and a body that lays out the
   reachability evidence. A human decides whether to move it to `approved/` and label the issue
   `disposition:approved`. `reachable` and `unknown` verdicts produce no PR: return
   `no_change_needed` with the evidence, or `blocked` if you could not finish the analysis.
7. Finish with the structured output: `reachability` (the four fields above), `proposed_vex_path`
   and `justification` when a PR was opened.
