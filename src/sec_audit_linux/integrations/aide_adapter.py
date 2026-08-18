"""AIDE (Advanced Intrusion Detection Environment) Integration Adapter."""

import os
import time
from typing import List, Dict, Any
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import (
    EvidenceRecord,
    SystemContext,
    ToolReport,
    ToolExecutionStatus
)
from sec_audit_linux.core.utils import execute_command, check_command_available


class AIDEAdapter(BaseToolAdapter):
    """Integrates AIDE file integrity scanner."""

    tool_name = "aide_adapter"
    tool_category = "File Integrity Monitoring (FIM)"
    binary_name = "aide"
    license = "GPL-2.0 (Open Source / Free for Corporate Use)"
    description = "AIDE Advanced Intrusion Detection Environment"

    def audit(self, context: SystemContext) -> ToolReport:
        start_time = time.time()
        is_installed = self.is_available()

        if not is_installed:
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                status=ToolExecutionStatus.NOT_INSTALLED,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={"status": "aide_not_installed"},
                recommendations=["Install aide ('apt install aide' or 'dnf install aide') and run aideinit to establish baseline hashes."]
            )

        out, err, code = execute_command(["aide", "--check"], timeout=45)
        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS if code in [0, 4] else ToolExecutionStatus.FAILED,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "exit_code": code,
                "clean_baseline": code == 0,
                "changes_detected": code != 0
            },
            findings=[{"raw_check_summary": out[:1000]}],
            recommendations=["Review modified files in AIDE log if baseline changes are reported."]
        )
