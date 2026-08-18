"""Lynis Security Auditing Tool Integration Adapter."""

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
from sec_audit_linux.core.utils import execute_command, read_system_file, parse_key_value_file


class LynisAdapter(BaseToolAdapter):
    """Integrates CISOfy Lynis open-source system security and compliance auditing tool."""

    tool_name = "lynis"
    tool_category = "System Hardening & Compliance"
    binary_name = "lynis"
    license = "GPL-3.0 (Open Source / Free for Corporate Use)"
    description = "Lynis security auditor for Linux systems, compliance testing, and system hardening"

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
                summary_metrics={"status": "lynis_not_installed"},
                recommendations=["Install lynis ('apt-get install lynis') for deep system audits."]
            )

        report_file = "/tmp/lynis-report.dat"
        # Run lynis with custom report file path
        out, err, code = execute_command(
            ["lynis", "audit", "system", "--quick", "--quiet", "--no-colors", "--report-file", report_file, "--log-file", "/tmp/lynis.log"],
            timeout=45
        )

        if not os.path.exists(report_file):
            if os.path.exists("/var/log/lynis-report.dat"):
                report_file = "/var/log/lynis-report.dat"

        report_data: Dict[str, Any] = {}
        if os.path.exists(report_file):
            content, _ = read_system_file(report_file)
            if content:
                report_data = parse_key_value_file(content, delimiter="=")

        warnings = [v for k, v in report_data.items() if "warning" in k.lower()]
        suggestions = [v for k, v in report_data.items() if "suggestion" in k.lower()]
        hardening_index = report_data.get("hardening_index", "evaluated")

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "hardening_index": hardening_index,
                "warnings_count": len(warnings),
                "suggestions_count": len(suggestions),
                "os_name": report_data.get("os_name", "Linux")
            },
            findings=[{"type": "warning", "description": w} for w in warnings],
            recommendations=suggestions[:25] if suggestions else ["Apply recommended sysctl and PAM hardening measures."],
            raw_output=out or err
        )
