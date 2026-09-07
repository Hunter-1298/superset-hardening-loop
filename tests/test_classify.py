from __future__ import annotations

import itertools
from typing import Any

import pytest
from packaging.specifiers import SpecifierSet

from hardening_loop.classify.group import group_findings, group_key
from hardening_loop.classify.rules import (
    Classification,
    ClassificationContext,
    classify,
    parse_upper_bounds,
)
from hardening_loop.domain.enums import Ecosystem, Kind, Layer, Risk, Scanner, Severity
from hardening_loop.ingest.normalize import NormalizedFinding, normalize
from hardening_loop.ingest.records import RawConfigFinding, RawVuln, canonical_vuln_id

BOTH_OK = ClassificationContext({Scanner.trivy: True, Scanner.grype: True})
GRYPE_FAILED = ClassificationContext({Scanner.trivy: True, Scanner.grype: False})


def vuln(
    scanner: Scanner,
    vid: str = "CVE-2026-1",
    *,
    pkg: str = "Foo_Bar",
    version: str = "1.0",
    eco: Ecosystem = Ecosystem.pypi,
    fixed: list[str] | None = None,
    fix_state: str | None = None,
    sev: Severity = Severity.high,
    aliases: list[str] | None = None,
) -> RawVuln:
    fixed = fixed if fixed is not None else ["1.1"]
    return RawVuln(
        scanner=scanner,
        primary_id=vid,
        aliases=aliases or [],
        pkg_name=pkg,
        pkg_version=version,
        purl=f"pkg:{eco.value}/{pkg}@{version}",
        ecosystem=eco,
        layer=Layer.python if eco is Ecosystem.pypi else Layer.os,
        severity=sev,
        fixed_versions=fixed,
        fix_state=fix_state or ("fixed" if fixed else "not-fixed"),
        record={"id": vid},
    )


def config(
    layer: Layer, rule: str = "AVD-DS-0002", resource: str = "Dockerfile"
) -> RawConfigFinding:
    return RawConfigFinding(
        scanner=Scanner.trivy,
        rule_id=rule,
        resource=resource,
        layer=layer,
        severity=Severity.high,
        record={"ID": rule},
    )


def one(*raw: Any) -> NormalizedFinding:
    vulns = [r for r in raw if isinstance(r, RawVuln)]
    configs = [r for r in raw if isinstance(r, RawConfigFinding)]
    (f,) = normalize(vulns, configs)
    return f


def test_canonical_id_prefers_cve_then_ghsa() -> None:
    assert canonical_vuln_id("GHSA-x", ["CVE-2026-9"]) == "CVE-2026-9"
    assert canonical_vuln_id("CVE-2026-9", ["GHSA-x"]) == "CVE-2026-9"
    assert canonical_vuln_id("GHSA-x", []) == "GHSA-x"
    assert canonical_vuln_id("PYSEC-1", []) == "PYSEC-1"


def test_normalize_merges_scanners_on_same_finding() -> None:
    f = one(
        vuln(Scanner.trivy, "CVE-2026-1", aliases=["GHSA-a"], sev=Severity.high),
        vuln(Scanner.grype, "GHSA-a", aliases=["CVE-2026-1"], pkg="foo-bar", sev=Severity.critical),
    )
    assert f.vuln_id == "CVE-2026-1"
    assert f.pkg_name == "foo-bar"
    assert f.reported_by == {Scanner.trivy, Scanner.grype}
    assert f.severity is Severity.critical and f.severity_disagreement
    assert set(f.records) == {"trivy", "grype"}


def test_rule1_helm_and_compose_are_kind5() -> None:
    for layer in (Layer.helm, Layer.compose):
        c = classify(one(config(layer, resource="helm/superset/values.yaml")), BOTH_OK)
        assert c.kind is Kind.helm_deploy_config


def test_rule2_one_scanner_only_when_other_succeeded() -> None:
    f = one(vuln(Scanner.trivy))
    assert classify(f, BOTH_OK).kind is Kind.scanner_disagreement
    # Other scanner failed -> not a disagreement; falls through to kind 1 (fixable pypi).
    assert classify(f, GRYPE_FAILED).kind is Kind.dependency_upgrade


def test_rule3_fixable_pypi_and_bound_blocked() -> None:
    f = one(vuln(Scanner.trivy, fixed=["2.0"]), vuln(Scanner.grype, fixed=["2.0"]))
    assert classify(f, BOTH_OK) == Classification(
        Kind.dependency_upgrade, trace=classify(f, BOTH_OK).trace
    )
    ctx = ClassificationContext(BOTH_OK.scanner_job_success, {"foo-bar": SpecifierSet(">=1,<2")})
    c = classify(f, ctx)
    assert c.kind is Kind.dependency_upgrade and c.risk is Risk.high and c.bound_blocked
    ctx2 = ClassificationContext(BOTH_OK.scanner_job_success, {"foo-bar": SpecifierSet(">=1,<3")})
    assert not classify(f, ctx2).bound_blocked


def test_rule4_no_fix_from_every_reporter() -> None:
    f = one(vuln(Scanner.trivy, fixed=[], fix_state="affected"), vuln(Scanner.grype, fixed=[]))
    assert classify(f, BOTH_OK).kind is Kind.no_fix_reachability
    # One scanner knows a fix -> fixable, kind 1, not kind 2.
    g = one(vuln(Scanner.trivy, fixed=[], fix_state="affected"), vuln(Scanner.grype, fixed=["1.2"]))
    assert classify(g, BOTH_OK).kind is Kind.dependency_upgrade


def test_rule4_applies_to_os_packages_before_rule5() -> None:
    f = one(
        vuln(Scanner.trivy, eco=Ecosystem.deb, fixed=[], fix_state="will_not_fix"),
        vuln(Scanner.grype, eco=Ecosystem.deb, fixed=[], fix_state="wont-fix"),
    )
    assert classify(f, BOTH_OK).kind is Kind.no_fix_reachability


def test_rule5_fixable_os_and_dockerfile() -> None:
    f = one(vuln(Scanner.trivy, eco=Ecosystem.deb), vuln(Scanner.grype, eco=Ecosystem.deb))
    assert classify(f, BOTH_OK).kind is Kind.container_hardening
    assert classify(one(config(Layer.dockerfile)), BOTH_OK).kind is Kind.container_hardening


def test_unclassified_is_visible_with_reason() -> None:
    f = one(vuln(Scanner.trivy, eco=Ecosystem.unknown), vuln(Scanner.grype, eco=Ecosystem.unknown))
    c = classify(f, BOTH_OK)
    assert c.kind is None and c.unclassified_reason == "unknown_ecosystem"
    assert "r5:no" in c.trace
    candidates, unclassified = group_findings([(f, c)])
    assert candidates == [] and len(unclassified) == 1


@pytest.mark.parametrize(
    ("eco", "reporters", "fixed", "is_config", "layer"),
    [
        *itertools.product(
            [Ecosystem.pypi, Ecosystem.deb, Ecosystem.binary, Ecosystem.unknown],
            [{Scanner.trivy}, {Scanner.grype}, {Scanner.trivy, Scanner.grype}],
            [[], ["9.9"]],
            [False],
            [None],
        ),
        (Ecosystem.config, {Scanner.trivy}, [], True, Layer.dockerfile),
        (Ecosystem.config, {Scanner.trivy}, [], True, Layer.helm),
        (Ecosystem.config, {Scanner.trivy}, [], True, Layer.compose),
    ],
)
def test_classification_is_total_and_deterministic(
    eco: Ecosystem, reporters: set[Scanner], fixed: list[str], is_config: bool, layer: Layer | None
) -> None:
    if is_config:
        assert layer is not None
        f = one(config(layer))
    else:
        f = one(*[vuln(s, eco=eco, fixed=fixed) for s in sorted(reporters)])
    for ctx in (BOTH_OK, GRYPE_FAILED):
        a, b = classify(f, ctx), classify(f, ctx)
        assert a == b
        assert a.kind is None or isinstance(a.kind, Kind)
        if a.kind is None:
            assert a.unclassified_reason


def test_grouping_keys() -> None:
    f1 = one(vuln(Scanner.trivy, "CVE-1", pkg="pkgA"), vuln(Scanner.grype, "CVE-1", pkg="pkgA"))
    f2 = one(vuln(Scanner.trivy, "CVE-2", pkg="pkgA"), vuln(Scanner.grype, "CVE-2", pkg="pkgA"))
    f3 = one(
        vuln(Scanner.trivy, "CVE-3", pkg="pkgB", sev=Severity.critical),
        vuln(Scanner.grype, "CVE-3", pkg="pkgB"),
    )
    classified = [(f, classify(f, BOTH_OK)) for f in (f1, f2, f3)]
    candidates, unclassified = group_findings(classified)
    assert not unclassified
    assert [c.group_key for c in candidates] == ["pypi:pkga", "pypi:pkgb"]
    assert len(candidates[0].members) == 2
    assert candidates[1].severity is Severity.critical
    assert candidates[0].acu_cap == 5
    cfg = one(config(Layer.helm, resource="helm/superset/templates/deployment.yaml"))
    assert group_key(cfg, classify(cfg, BOTH_OK)) == "deploy:helm"


def test_parse_upper_bounds() -> None:
    text = """
[project]
dependencies = ["cryptography>=42.0.4, <45.0.0", "flask>=2.2.5", "PyJWT>=2.4.0, <3.0"]
[project.optional-dependencies]
postgres = ["psycopg2-binary>=2.9.6, <3.0"]
"""
    bounds = parse_upper_bounds(text)
    assert set(bounds) == {"cryptography", "pyjwt", "psycopg2-binary"}
    assert "flask" not in bounds
    assert not bounds["cryptography"].contains("45.0.0")
    assert bounds["cryptography"].contains("44.0.1")
