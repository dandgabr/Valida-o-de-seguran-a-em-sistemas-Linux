"""Lynis Security Auditing Tool Integration Adapter."""

import os
from typing import List, Dict, Any
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command, read_system_file, parse_key_value_file


class LynisAdapter(BaseToolAdapter):
    """Integrates CISOps / CISOfy Lynis security assessment tool."""

    tool_name = "lynis"
    binary_name = "lynis"
    description = "Lynis System Security and Compliance Auditor"

    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        if not self.is_available():
            # Check if previous report exists
            report_file = "/var/log/lynis-report.dat"
            if os.path.exists(report_file):
                content, _ = read_system_file(report_file)
                if content:
                    parsed = parse_key_value_file(content, delimiter="=")
                    return [EvidenceRecord(
                        collector_name=self.tool_name,
                        target_item="lynis_cached_report",
                        raw_output=content[:2000] + "... (truncated)",
                        parsed_data={"hardness_index": parsed.get("hardening_index", "unknown"), "tests": parsed}
                    )]
            return [EvidenceRecord(
                collector_name=self.tool_name,
                target_item="lynis_status",
                raw_output="Lynis is not installed on the system. Native collectors used as primary audit source.",
                parsed_data={"installed": False}
            )]

        # Execute quick audit
        out, err, code = execute_command(["lynis", "audit", "system", "--quick", "--quiet", "--no-colors"], timeout=60)
        report_file = "/var/log/lynis-report.dat"
        report_data: Dict[str, Any] = {}
        if os.path.exists(report_file):
            content, _ = read_system_file(report_file)
            if content:
                report_data = parse_key_value_file(content, delimiter="=")

        return [EvidenceRecord(
            collector_name=self.tool_name,
            target_item="lynis_system_audit",
            command_executed="lynis audit system --quick --quiet",
            raw_output=out or err,
            parsed_data={
                "installed": True,
                "exit_code": code,
                "hardening_index": report_data.get("hardening_index", "unknown"),
                "warnings": [k for k in report_data.keys() if "warning" in k.lower()],
                "suggestions": [k for k in report_data.keys() if "suggestion" in k.lower()]
            }
        )]
