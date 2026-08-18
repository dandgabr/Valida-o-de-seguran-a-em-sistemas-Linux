"""Scoring and Metrics Calculation Module for Security Frameworks."""

from typing import List, Dict, Tuple, Any
from sec_audit_linux.core.models import ControlEvaluation, ControlStatus, Severity


def summarize_evaluations(evaluations: List[ControlEvaluation]) -> Dict[str, Any]:
    """Generates counts by status and by severity for a list of control evaluations."""
    total = len(evaluations)
    compliant = sum(1 for e in evaluations if e.status == ControlStatus.COMPLIANT)
    non_compliant = sum(1 for e in evaluations if e.status == ControlStatus.NON_COMPLIANT)
    partial = sum(1 for e in evaluations if e.status == ControlStatus.PARTIAL)
    manual = sum(1 for e in evaluations if e.status == ControlStatus.MANUAL_CHECK)
    not_applicable = sum(1 for e in evaluations if e.status == ControlStatus.NOT_APPLICABLE)
    error = sum(1 for e in evaluations if e.status == ControlStatus.ERROR)

    severity_counts = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0
    }

    # Count failed/partial findings by severity
    for e in evaluations:
        if e.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL]:
            sev_key = e.severity.value if hasattr(e.severity, "value") else str(e.severity)
            if sev_key in severity_counts:
                severity_counts[sev_key] += 1

    return {
        "total_controls": total,
        "compliant_count": compliant,
        "non_compliant_count": non_compliant,
        "partial_count": partial,
        "manual_count": manual,
        "not_applicable_count": not_applicable,
        "error_count": error,
        "summary_by_severity": severity_counts
    }


def calculate_weighted_score(evaluations: List[ControlEvaluation]) -> float:
    """
    Calculates weighted compliance percentage:
    Applicable weight = sum of weights for controls that are not NOT_APPLICABLE.
    Earned weight = Compliant (100% weight) + Partial (50% weight).
    """
    applicable = [e for e in evaluations if e.status != ControlStatus.NOT_APPLICABLE]
    if not applicable:
        return 100.0

    total_weight = sum(e.weight for e in applicable)
    if total_weight <= 0:
        return 100.0

    earned_weight = 0.0
    for e in applicable:
        if e.status == ControlStatus.COMPLIANT:
            earned_weight += e.weight
        elif e.status == ControlStatus.PARTIAL:
            earned_weight += e.weight * 0.5
        elif e.status == ControlStatus.MANUAL_CHECK:
            # Manual check is neutral (assumes baseline until reviewed, or 0.5)
            earned_weight += e.weight * 0.5

    return round((earned_weight / total_weight) * 100.0, 2)


def calculate_pci_dss_score(evaluations: List[ControlEvaluation]) -> float:
    """
    PCI DSS standard adherence calculation:
    Requires all mandatory applicable controls to pass (100% or fails).
    Returns weighted score and flag for full compliance.
    """
    applicable = [e for e in evaluations if e.status != ControlStatus.NOT_APPLICABLE]
    if not applicable:
        return 100.0

    has_non_compliant = any(e.status == ControlStatus.NON_COMPLIANT for e in applicable)
    weighted = calculate_weighted_score(evaluations)
    return weighted if not has_non_compliant else min(weighted, 99.0)
