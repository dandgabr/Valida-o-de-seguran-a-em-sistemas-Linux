"""Audit Orchestrator and Assessment Engine."""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from sec_audit_linux.core.models import (
    AssessmentResult,
    SystemContext,
    FrameworkResult,
    EvidenceRecord
)
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.core.evidence_manager import EvidenceStore


class AuditEngine:
    """Orchestrates security collectors, framework compliance evaluators, and report generation."""

    def __init__(self, system_context: Optional[SystemContext] = None):
        self.context: SystemContext = system_context or OSDetector.detect()
        self.evidence_store: EvidenceStore = EvidenceStore()
        self._collectors: Dict[str, Any] = {}
        self._frameworks: Dict[str, Any] = {}

    def register_collector(self, collector_instance: Any) -> None:
        """Registers a collector instance."""
        self._collectors[collector_instance.name] = collector_instance

    def register_framework(self, framework_instance: Any) -> None:
        """Registers a framework evaluation instance."""
        self._frameworks[framework_instance.framework_id] = framework_instance

    def get_registered_collectors(self) -> List[str]:
        """Returns list of registered collector names."""
        return list(self._collectors.keys())

    def get_registered_frameworks(self) -> List[str]:
        """Returns list of registered framework IDs."""
        return list(self._frameworks.keys())

    def run_assessment(
        self,
        framework_ids: Optional[List[str]] = None,
        collector_names: Optional[List[str]] = None
    ) -> AssessmentResult:
        """
        Executes a complete assessment pipeline:
        1. Runs selected or all collectors.
        2. Ingests and hashes evidence records.
        3. Evaluates selected or all frameworks.
        4. Calculates adherence metrics and returns AssessmentResult.
        """
        start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()

        # 1. Determine which collectors to execute
        target_collectors = []
        if collector_names:
            target_collectors = [self._collectors[c] for c in collector_names if c in self._collectors]
        else:
            target_collectors = list(self._collectors.values())

        # 2. Run collectors and populate evidence store
        for collector in target_collectors:
            try:
                records = collector.collect(self.context)
                self.evidence_store.add_records(records)
            except Exception as e:
                # Record collection failure gracefully as an evidence record
                err_record = EvidenceRecord(
                    collector_name=collector.name,
                    target_item="collector_execution",
                    error_message=f"Collector failed with error: {str(e)}"
                )
                self.evidence_store.add_record(err_record)

        all_evidences = self.evidence_store.get_all_records()

        # 3. Determine which frameworks to evaluate
        target_frameworks = []
        if framework_ids:
            target_frameworks = [self._frameworks[f] for f in framework_ids if f in self._frameworks]
        else:
            target_frameworks = list(self._frameworks.values())

        # 4. Evaluate each framework
        framework_results: Dict[str, FrameworkResult] = {}
        for fw in target_frameworks:
            try:
                res = fw.evaluate(all_evidences, self.context)
                framework_results[fw.framework_id] = res
            except Exception as e:
                # Log framework evaluation failure
                from sec_audit_linux.core.models import ControlEvaluation, ControlStatus, Severity
                err_eval = ControlEvaluation(
                    control_id=f"{fw.framework_id}-ERR",
                    framework_name=fw.name,
                    title="Framework Execution Error",
                    description=f"Error evaluating framework: {str(e)}",
                    status=ControlStatus.ERROR,
                    severity=Severity.CRITICAL
                )
                framework_results[fw.framework_id] = FrameworkResult(
                    framework_id=fw.framework_id,
                    framework_name=fw.name,
                    version=getattr(fw, "version", "1.0"),
                    adherence_percentage=0.0,
                    total_controls=1,
                    error_count=1,
                    evaluations=[err_eval]
                )

        # 5. Compute global overall score (average of evaluated frameworks)
        overall_score = 0.0
        if framework_results:
            scores = [f.adherence_percentage for f in framework_results.values()]
            overall_score = round(sum(scores) / len(scores), 2)

        duration = round(time.time() - start_time, 3)
        completed_at = datetime.now(timezone.utc).isoformat()

        return AssessmentResult(
            system_context=self.context,
            overall_score=overall_score,
            frameworks=framework_results,
            total_evidences=len(all_evidences),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration
        )
