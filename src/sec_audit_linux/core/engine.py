"""Audit Orchestrator and Assessment Engine."""

import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from sec_audit_linux.core.models import (
    AssessmentResult,
    SystemContext,
    FrameworkResult,
    EvidenceRecord,
    ToolReport
)
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.core.evidence_manager import EvidenceStore


class AuditEngine:
    """Orchestrates security collectors, open-source tool adapters, compliance evaluators, and reports."""

    def __init__(self, system_context: Optional[SystemContext] = None):
        self.context: SystemContext = system_context or OSDetector.detect()
        self.evidence_store: EvidenceStore = EvidenceStore()
        self._collectors: Dict[str, Any] = {}
        self._frameworks: Dict[str, Any] = {}
        self._tool_adapters: Dict[str, Any] = {}

    def register_collector(self, collector_instance: Any) -> None:
        """Registers a collector instance."""
        self._collectors[collector_instance.name] = collector_instance

    def register_framework(self, framework_instance: Any) -> None:
        """Registers a framework evaluation instance."""
        self._frameworks[framework_instance.framework_id] = framework_instance

    def register_tool_adapter(self, adapter_instance: Any) -> None:
        """Registers an external open-source tool adapter."""
        self._tool_adapters[adapter_instance.tool_name] = adapter_instance

    def get_registered_collectors(self) -> List[str]:
        """Returns list of registered collector names."""
        return list(self._collectors.keys())

    def get_registered_frameworks(self) -> List[str]:
        """Returns list of registered framework IDs."""
        return list(self._frameworks.keys())

    def get_registered_tools(self) -> List[str]:
        """Returns list of registered tool names."""
        return list(self._tool_adapters.keys())

    def run_assessment(
        self,
        framework_ids: Optional[List[str]] = None,
        collector_names: Optional[List[str]] = None,
        tool_names: Optional[List[str]] = None,
        run_tools: bool = True
    ) -> AssessmentResult:
        """
        Executes a complete assessment pipeline:
        1. Runs native collectors and records raw evidence.
        2. Executes external open-source security tools and generates standalone ToolReports.
        3. Ingests tool outputs into the EvidenceStore.
        4. Evaluates compliance frameworks.
        5. Calculates metrics and returns AssessmentResult.
        """
        start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()

        # 1. Run Native Collectors
        target_collectors = []
        if collector_names:
            target_collectors = [self._collectors[c] for c in collector_names if c in self._collectors]
        else:
            target_collectors = list(self._collectors.values())

        for collector in target_collectors:
            try:
                records = collector.collect(self.context)
                self.evidence_store.add_records(records)
            except Exception as e:
                err_record = EvidenceRecord(
                    collector_name=collector.name,
                    target_item="collector_execution",
                    error_message=f"Collector failed with error: {str(e)}"
                )
                self.evidence_store.add_record(err_record)

        # 2. Run Integrated Open-Source Security Tools
        tools_reports: Dict[str, ToolReport] = {}
        if run_tools:
            target_tools = []
            if tool_names:
                target_tools = [self._tool_adapters[t] for t in tool_names if t in self._tool_adapters]
            else:
                target_tools = list(self._tool_adapters.values())

            for tool in target_tools:
                try:
                    report = tool.audit(self.context)
                    tools_reports[tool.tool_name] = report
                    # Ingest tool evidences for framework correlation
                    evs = tool.extract_evidences(report)
                    self.evidence_store.add_records(evs)
                except Exception as e:
                    pass

        all_evidences = self.evidence_store.get_all_records()

        # 3. Evaluate Frameworks
        target_frameworks = []
        if framework_ids:
            target_frameworks = [self._frameworks[f] for f in framework_ids if f in self._frameworks]
        else:
            target_frameworks = list(self._frameworks.values())

        framework_results: Dict[str, FrameworkResult] = {}
        for fw in target_frameworks:
            try:
                res = fw.evaluate(all_evidences, self.context)
                framework_results[fw.framework_id] = res
            except Exception as e:
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

        # 4. Compute Global Overall Score
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
            tools_reports=tools_reports,
            total_evidences=len(all_evidences),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=duration
        )
