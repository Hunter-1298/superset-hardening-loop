"""Structured-output JSON Schemas for the five playbooks.

One common core (outcome, PR, findings addressed, tests run, blocked reason) plus a per-kind
extension. `validate_output` returns a list of violations; the orchestrator treats a non-empty list
as `final_output_missing_or_invalid` -> needs_human. Devin's `tests_run` claims are stored but never
trusted for state: only GitHub Checks decide.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from jsonschema import Draft202012Validator

from hardening_loop.domain.enums import Kind

_CORE_PROPERTIES: dict[str, Any] = {
    "outcome": {"type": "string", "enum": ["pr_opened", "blocked", "no_change_needed"]},
    "pr_url": {
        "type": ["string", "null"],
        "pattern": "^https://github.com/[^/]+/[^/]+/pull/[0-9]+$",
    },
    "base_branch": {"type": "string", "const": "main"},
    "findings_addressed": {"type": "array", "items": {"type": "string"}},
    "findings_not_addressed": {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id", "reason"],
            "properties": {"id": {"type": "string"}, "reason": {"type": "string"}},
        },
    },
    "tests_run": {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["command", "exit_code"],
            "properties": {
                "command": {"type": "string"},
                "exit_code": {"type": "integer"},
                "log_attachment": {"type": ["string", "null"]},
            },
        },
    },
    "blocked_reason": {"type": ["string", "null"]},
    "evidence_urls": {"type": "array", "items": {"type": "string"}},
    "reason": {"type": ["string", "null"]},
}

_CORE_RULES: list[dict[str, Any]] = [
    # pr_opened requires a PR URL
    {
        "if": {"properties": {"outcome": {"const": "pr_opened"}}},
        "then": {"required": ["pr_url"], "properties": {"pr_url": {"type": "string"}}},
    },
    # blocked requires a non-empty reason
    {
        "if": {"properties": {"outcome": {"const": "blocked"}}},
        "then": {
            "required": ["blocked_reason"],
            "properties": {"blocked_reason": {"type": "string", "minLength": 10}},
        },
    },
    # no_change_needed requires reason + evidence
    {
        "if": {"properties": {"outcome": {"const": "no_change_needed"}}},
        "then": {
            "required": ["reason", "evidence_urls"],
            "properties": {"reason": {"type": "string", "minLength": 10}},
        },
    },
]

_EXTENSIONS: dict[Kind, dict[str, Any]] = {
    Kind.dependency_upgrade: {
        "packages": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "from", "to"],
                "properties": {
                    "name": {"type": "string"},
                    "from": {"type": "string"},
                    "to": {"type": "string"},
                },
            },
        },
        "regenerated_with": {"type": ["string", "null"]},
        "bound_changes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["package", "old_bound", "new_bound", "justification"],
                "properties": {
                    "package": {"type": "string"},
                    "old_bound": {"type": "string"},
                    "new_bound": {"type": "string"},
                    "justification": {"type": "string"},
                },
            },
        },
    },
    Kind.no_fix_reachability: {
        "reachability": {
            "type": "object",
            "required": ["imports_found", "call_sites", "runtime_paths", "verdict"],
            "properties": {
                "imports_found": {"type": "array", "items": {"type": "string"}},
                "call_sites": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["file", "line", "symbol"],
                        "properties": {
                            "file": {"type": "string"},
                            "line": {"type": "integer"},
                            "symbol": {"type": "string"},
                        },
                    },
                },
                "runtime_paths": {"type": "array", "items": {"type": "string"}},
                "verdict": {"type": "string", "enum": ["reachable", "unreachable", "unknown"]},
            },
        },
        "proposed_vex_path": {"type": ["string", "null"], "pattern": "^security/vex/proposed/"},
        "justification": {"type": ["string", "null"]},
    },
    Kind.container_hardening: {
        "changes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "detail"],
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["base_image", "package_removal", "user", "permissions", "pin"],
                    },
                    "detail": {"type": "string"},
                },
            },
        },
        "image_size_before_after": {
            "type": ["object", "null"],
            "properties": {"before": {"type": "integer"}, "after": {"type": "integer"}},
        },
        "lean_smoke_local": {"type": "boolean"},
    },
    Kind.scanner_disagreement: {
        "verdict": {
            "type": "string",
            "enum": ["trivy_correct", "grype_correct", "both_partial", "undetermined"],
        },
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["scanner", "record", "reasoning"],
                "properties": {
                    "scanner": {"type": "string", "enum": ["trivy", "grype"]},
                    "record": {"type": "object"},
                    "reasoning": {"type": "string"},
                },
            },
        },
        "recommended_action": {"type": "string", "enum": ["upgrade", "vex", "none"]},
    },
    Kind.helm_deploy_config: {
        "values_changed": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["path", "from", "to"],
                "properties": {
                    "path": {"type": "string"},
                    "from": {},
                    "to": {},
                },
            },
        },
        "helm_lint": {"type": ["string", "null"]},
        "helm_template_diff_attachment": {"type": ["string", "null"]},
    },
}

_EXTENSION_REQUIRED: dict[Kind, list[str]] = {
    Kind.dependency_upgrade: [],
    Kind.no_fix_reachability: [],
    Kind.container_hardening: [],
    Kind.scanner_disagreement: ["verdict", "evidence", "recommended_action"],
    Kind.helm_deploy_config: [],
}

# Per-kind conditionals beyond the core.
_EXTENSION_RULES: dict[Kind, list[dict[str, Any]]] = {
    Kind.dependency_upgrade: [
        {
            "if": {"properties": {"outcome": {"const": "pr_opened"}}},
            "then": {
                "required": ["packages", "regenerated_with"],
                "properties": {
                    "packages": {"minItems": 1},
                    "regenerated_with": {"type": "string", "minLength": 1},
                },
            },
        }
    ],
    Kind.no_fix_reachability: [
        {
            "if": {"properties": {"outcome": {"const": "pr_opened"}}},
            "then": {
                "required": ["reachability", "proposed_vex_path", "justification"],
                "properties": {"proposed_vex_path": {"type": "string"}},
            },
        }
    ],
    Kind.container_hardening: [
        {
            "if": {"properties": {"outcome": {"const": "pr_opened"}}},
            "then": {
                "required": ["changes", "lean_smoke_local"],
                "properties": {"changes": {"minItems": 1}},
            },
        }
    ],
    Kind.scanner_disagreement: [
        # Analysis-only playbook: a code PR is never the expected outcome.
        {"properties": {"outcome": {"enum": ["no_change_needed", "blocked"]}}},
    ],
    Kind.helm_deploy_config: [
        {
            "if": {"properties": {"outcome": {"const": "pr_opened"}}},
            "then": {
                "required": ["values_changed", "helm_lint"],
                "properties": {"values_changed": {"minItems": 1}},
            },
        }
    ],
}


def schema_for(kind: Kind) -> dict[str, Any]:
    props = deepcopy(_CORE_PROPERTIES)
    props.update(deepcopy(_EXTENSIONS[kind]))
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://hardening-loop/schemas/{kind.playbook_slug}.json",
        "title": f"{kind.playbook_slug} structured output",
        "type": "object",
        "additionalProperties": False,
        "required": ["outcome", "base_branch", "findings_addressed", "findings_not_addressed"]
        + _EXTENSION_REQUIRED[kind],
        "properties": props,
        "allOf": deepcopy(_CORE_RULES) + deepcopy(_EXTENSION_RULES[kind]),
    }


_VALIDATORS: dict[Kind, Draft202012Validator] = {}


def validate_output(kind: Kind, output: object) -> list[str]:
    """Return schema violations (empty list == valid)."""
    if not isinstance(output, dict):
        return ["structured_output is missing or not an object"]
    validator = _VALIDATORS.get(kind)
    if validator is None:
        schema = schema_for(kind)
        Draft202012Validator.check_schema(schema)
        validator = _VALIDATORS[kind] = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(output), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]
