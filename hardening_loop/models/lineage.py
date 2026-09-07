"""Work-item lineage. A finding that regresses is re-homed on a new `#rN` work item that points
back at the original through `regression_of_work_item_id`; the original keeps its verified
outcome but no longer owns the finding row. Readers that want "everything this item ever
covered" use these helpers instead of `Finding.work_item_id` alone."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from hardening_loop.models.tables import Finding, WorkItem

_REGRESSION_SUFFIX = re.compile(r"#r\d+$")


def package_of_group_key(group_key: str) -> str:
    """`pypi:cryptography#r1` -> `cryptography`."""
    key = _REGRESSION_SUFFIX.sub("", group_key)
    return key.split(":", 1)[1] if ":" in key else key


def regression_descendants(items: Iterable[WorkItem], root_id: int) -> list[int]:
    """Ids of every work item that (transitively) regressed from `root_id`, oldest first."""
    children: dict[int, list[int]] = defaultdict(list)
    for w in items:
        if w.id is not None and w.regression_of_work_item_id is not None:
            children[w.regression_of_work_item_id].append(w.id)
    out: list[int] = []
    queue = list(children.get(root_id, []))
    while queue:
        wi_id = queue.pop(0)
        out.append(wi_id)
        queue.extend(children.get(wi_id, []))
    return sorted(out)


def members_with_lineage(
    items: Iterable[WorkItem], findings: Iterable[Finding]
) -> dict[int, list[Finding]]:
    """Findings per work item, where each item also lists the findings owned by its regression
    descendants (a regressed finding stays visible on the item whose fix it invalidated)."""
    parent: dict[int, int] = {}
    for w in items:
        if w.id is not None and w.regression_of_work_item_id is not None:
            parent[w.id] = w.regression_of_work_item_id
    out: dict[int, list[Finding]] = defaultdict(list)
    for f in findings:
        wi_id = f.work_item_id
        seen: set[int] = set()
        while wi_id is not None and wi_id not in seen:
            out[wi_id].append(f)
            seen.add(wi_id)
            wi_id = parent.get(wi_id)
    return out


__all__ = ["members_with_lineage", "package_of_group_key", "regression_descendants"]
