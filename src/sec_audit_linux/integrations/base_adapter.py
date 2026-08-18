"""Base abstract class for external open-source security tool adapters."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import time
from sec_audit_linux.core.models import (
    EvidenceRecord,
    SystemContext,
    ToolReport,
    ToolExecutionStatus
)
from sec_audit_linux.core.utils import check_command_available, execute_command


class BaseToolAdapter(ABC):
    """Abstract base class for open-source security auditing and scanning tools."""

    tool_name: str = "base_tool"
    tool_category: str = "General Security"
    binary_name: str = "tool"
    license: str = "Open Source"
    description: str = "External open-source security tool adapter"

    def is_available(self) -> bool:
        """Checks if the required tool binary is installed on the host system."""
        return check_command_available(self.binary_name)

    def get_version(self) -> str:
        """Gets tool version string."""
        if not self.is_available():
            return "not_installed"
        out, _, code = execute_command([self.binary_name, "--version"])
        if code == 0 and out.strip():
            return out.splitlines()[0].strip()
        return "installed"

    @abstractmethod
    def audit(self, context: SystemContext) -> ToolReport:
        """
        Executes deep security analysis using the external tool, parses results into a ToolReport,
        and generates comprehensive findings, metrics, and recommendations.
        """
        pass

    def extract_evidences(self, report: ToolReport) -> List[EvidenceRecord]:
        """Converts ToolReport data and findings into normalized EvidenceRecords for framework correlation."""
        records = [
            EvidenceRecord(
                collector_name=self.tool_name,
                target_item=f"tool_report:{self.tool_name}",
                raw_output=report.raw_output[:5000] if len(report.raw_output) > 5000 else report.raw_output,
                parsed_data={
                    "status": report.status.value,
                    "metrics": report.summary_metrics,
                    "findings_count": len(report.findings),
                    "recommendations_count": len(report.recommendations)
                }
            )
        ]
        return records
