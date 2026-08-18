"""Base abstract class for all compliance and security frameworks."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from sec_audit_linux.core.models import (
    FrameworkResult,
    ControlEvaluation,
    ControlStatus,
    EvidenceRecord,
    SystemContext,
    Severity
)
from sec_audit_linux.core.scoring import calculate_weighted_score, summarize_evaluations


class BaseFramework(ABC):
    """Abstract base class for security compliance frameworks."""

    framework_id: str = "base_framework"
    name: str = "Base Security Framework"
    version: str = "1.0.0"
    description: str = "Base framework definition"

    @abstractmethod
    def evaluate(
        self,
        evidences: List[EvidenceRecord],
        context: SystemContext
    ) -> FrameworkResult:
        """
        Evaluates gathered evidences against framework-specific controls.
        Returns a populated FrameworkResult.
        """
        pass

    def _find_evidence(self, evidences: List[EvidenceRecord], target_item: str) -> Optional[EvidenceRecord]:
        """Helper to find an evidence record by its target_item identifier."""
        for ev in evidences:
            if ev.target_item == target_item:
                return ev
        return None

    def _create_result(self, evaluations: List[ControlEvaluation]) -> FrameworkResult:
        """Helper to construct FrameworkResult with calculated adherence and summaries."""
        summary = summarize_evaluations(evaluations)
        score = calculate_weighted_score(evaluations)

        return FrameworkResult(
            framework_id=self.framework_id,
            framework_name=self.name,
            version=self.version,
            adherence_percentage=score,
            total_controls=summary["total_controls"],
            compliant_count=summary["compliant_count"],
            non_compliant_count=summary["non_compliant_count"],
            partial_count=summary["partial_count"],
            manual_count=summary["manual_count"],
            not_applicable_count=summary["not_applicable_count"],
            error_count=summary["error_count"],
            evaluations=evaluations,
            summary_by_severity=summary["summary_by_severity"]
        )
