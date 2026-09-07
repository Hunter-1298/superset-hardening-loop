"""Policy gate: the single rule that decides whether a scan run's *policy* results fail CI.

`enforce` fails on every policy HIGH or CRITICAL, fix available or not. `report` never fails; it
exists so the workflow stays green while counts are driven to zero, and it must remain the active
mode until `ready_for_enforce` is true for the latest complete run of `main`."""

from __future__ import annotations

from dataclasses import dataclass

from hardening_loop.domain.enums import GateMode, Severity

GATED_SEVERITIES: frozenset[Severity] = frozenset({Severity.critical, Severity.high})


@dataclass(frozen=True)
class GateVerdict:
    mode: GateMode
    policy_high: int
    policy_critical: int
    passed: bool
    reason: str

    @property
    def gated_count(self) -> int:
        return self.policy_high + self.policy_critical

    @property
    def ready_for_enforce(self) -> bool:
        return self.gated_count == 0


def gate_verdict(mode: GateMode, policy_counts_by_severity: dict[str, int]) -> GateVerdict:
    high = int(policy_counts_by_severity.get(Severity.high.value, 0))
    critical = int(policy_counts_by_severity.get(Severity.critical.value, 0))
    gated = high + critical
    if mode is GateMode.enforce:
        passed = gated == 0
        reason = (
            "no policy HIGH/CRITICAL findings"
            if passed
            else f"{critical} CRITICAL + {high} HIGH policy findings (fix availability ignored)"
        )
    else:
        passed = True
        reason = (
            f"report mode: {critical} CRITICAL + {high} HIGH policy findings recorded, not gated"
        )
    return GateVerdict(
        mode=mode, policy_high=high, policy_critical=critical, passed=passed, reason=reason
    )


__all__ = ["GATED_SEVERITIES", "GateVerdict", "gate_verdict"]
