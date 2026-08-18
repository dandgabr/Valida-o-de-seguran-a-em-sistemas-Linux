"""Rootkit Hunter (rkhunter) Malware & Rootkit Scanner Integration Adapter."""

import time
from typing import List, Dict, Any
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import (
    EvidenceRecord,
    SystemContext,
    ToolReport,
    ToolExecutionStatus
)
from sec_audit_linux.core.utils import execute_command


class RKHunterAdapter(BaseToolAdapter):
    """Integrates Rootkit Hunter (rkhunter) for local exploits, rootkits, and trojan detection."""

    tool_name = "rkhunter"
    tool_category = "Rootkit & Malware Detection"
    binary_name = "rkhunter"
    license = "GPL-2.0 (Open Source / Free for Corporate Use)"
    description = "Scans systems for known rootkits, trojans, hidden files, and suspicious kernel changes"

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
                summary_metrics={"status": "rkhunter_not_installed"},
                recommendations=["Install rkhunter ('apt install rkhunter') for rootkit scanning."]
            )

        out, err, code = execute_command(
            ["rkhunter", "--check", "--sk", "--nocolors", "--report-warnings-only", "--quiet"],
            timeout=30
        )

        warnings = [line.strip() for line in (out or "").splitlines() if "[ Warning ]" in line or "Warning:" in line]

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "warnings_count": len(warnings),
                "clean_system": len(warnings) == 0
            },
            findings=[{"type": "rootkit_warning", "description": w} for w in warnings],
            recommendations=["Investigate file hash mismatches and hidden files reported by rkhunter."] if warnings else ["Rootkit Hunter: Baseline clean. No known rootkits detected."],
            raw_output=out or err
        )
