"""Trivy Vulnerability & Misconfiguration Scanner Adapter."""

import json
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


class TrivyAdapter(BaseToolAdapter):
    """Integrates Aqua Security Trivy open-source vulnerability scanner."""

    tool_name = "trivy"
    tool_category = "Vulnerability & Misconfiguration Scanner"
    binary_name = "trivy"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "Comprehensive scanner for vulnerabilities (CVEs), secrets, and misconfigurations in filesystems and containers"

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
                summary_metrics={"status": "trivy_not_installed"},
                recommendations=["Install trivy (https://aquasecurity.github.io/trivy/) to enable automated CVE scanning."]
            )

        out, err, code = execute_command(
            ["trivy", "fs", "--skip-db-update", "--severity", "HIGH,CRITICAL", "--format", "json", "-q", "/etc"],
            timeout=30
        )

        parsed_vulns = []
        sev_counts = {"CRITICAL": 0, "HIGH": 0}

        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                results = data.get("Results", [])
                for r in results:
                    vulns = r.get("Vulnerabilities", [])
                    for v in vulns:
                        sev = v.get("Severity", "UNKNOWN")
                        if sev in sev_counts:
                            sev_counts[sev] += 1
                        parsed_vulns.append({
                            "cve_id": v.get("VulnerabilityID"),
                            "package": v.get("PkgName"),
                            "severity": sev,
                            "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion"),
                            "title": v.get("Title", "")
                        })
            except Exception:
                pass

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "total_high_critical_cves": len(parsed_vulns),
                "critical_cves": sev_counts["CRITICAL"],
                "high_cves": sev_counts["HIGH"]
            },
            findings=parsed_vulns[:50],
            recommendations=[f"Upgrade package {v['package']} to version {v['fixed_version']} (Fixes {v['cve_id']})" for v in parsed_vulns if v.get("fixed_version")][:15],
            raw_output=out[:3000] if len(out) > 3000 else out
        )
