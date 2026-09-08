---
name: goal
description: Turn a broad multi-step request into a durable, evidence-checkable goal and execute it until verified or honestly blocked. Use for autonomous work that must survive long runs, iteration, and context changes without weakening constraints.
---

# Goal

Treat the user's request as a completion contract, not a suggestion or a reason to claim success after writing code.

## Define the contract

Before acting, identify six things from the request and current environment:

1. **Outcome** - the concrete end state that must be true.
2. **Verification** - tests, commands, artifacts, screenshots, logs, reviews, or runtime evidence that independently prove it.
3. **Constraints** - behavior, security properties, budgets, compatibility, and user decisions that must remain true.
4. **Boundaries** - allowed repositories, branches, files, tools, services, credentials, and forbidden actions.
5. **Iteration policy** - how to choose the next action after each result and what dependent evidence to rerun.
6. **Blocked stop** - conditions that require stopping for user input rather than guessing, drifting, or fabricating completion.

If a missing decision materially changes this contract, ask before implementation. Otherwise state safe assumptions and proceed.

## Execute

1. Inspect current code, instructions, repository state, open work, and external evidence. Current reality overrides stale plans.
2. Convert the contract into an ordered acceptance checklist. Mark an item complete only when its evidence exists.
3. Work from the earliest unmet dependency. Prefer the smallest coherent change; avoid unrelated cleanup and speculative abstractions.
4. Preserve existing architecture and style unless the goal explicitly requires a change. Never weaken tests, validation, security, or review gates just to pass.
5. After each attempt, inspect the result, identify the earliest failing condition, fix the root cause, and rerun that check plus dependent checks. Do not repeat the same failed approach without new evidence.
6. Test both success and relevant failure paths. Inspect generated artifacts and runtime behavior instead of relying only on exit status.
7. Before finishing, audit the complete diff and working state for unrelated changes, placeholders, disabled checks, leaked secrets, undocumented behavior, and unverified claims.
8. Leave work in the exact delivery state requested. Do not merge, deploy, publish, spend money, modify remote settings, or perform other irreversible actions unless explicitly authorized.

## Evidence and honesty

A completion report must map every acceptance condition to concrete evidence and include changed files, commands and results, review status, artifacts, residual risks, and any manual steps. Separate live results from mocks, simulations, estimates, and unavailable checks. Never claim a command ran, a review passed, or a system works without evidence.

Protect credentials throughout execution. Use secrets only through approved secure channels, never expose values in output or persisted artifacts, and report only presence or absence.

## Blocked stop

Stop when required credentials, permissions, human approval, product decisions, external services, or a defensible implementation path are unavailable. Report:

- the unmet acceptance condition;
- evidence gathered and approaches attempted;
- why continuing would be unsafe or misleading;
- the smallest user action or input needed to resume.

A precise blocked report is a valid result. Partial work presented as complete is not.
