"""Anchore Grype Vulnerability Scanner Integration Adapter."""

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


class GrypeAdapter(BaseToolAdapter):
    """Integrates Anchore Grype vulnerability scanner for container images and filesystems."""

    tool_name = "grype"
    tool_category = "Vulnerability Scanner"
    binary_name = "grype"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "Fast vulnerability scanner for container images and Linux filesystems"

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
                summary_metrics={"status": "grype_not_installed"},
                recommendations=["Install grype (https://github.com/anchore/grype) for fast local CVE scanning."]
            )

        out, err, code = execute_command(
            ["grype", "-q", "-o", "json", "--check-for-updates=false", "dir:/etc"],
            timeout=25
        )

        matches = []
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                for item in data.get("matches", []):
                    vuln = item.get("vulnerability", {})
                    pkg = item.get("artifact", {})
                    sev = vuln.get("severity", "Unknown")
                    if sev in sev_counts:
                        sev_counts[sev] += 1
                    matches.append({
                        "id": vuln.get("id"),
                        "severity": sev,
                        "package": pkg.get("name"),
                        "version": pkg.get("version"),
                        "fix_versions": vuln.get("fix", {}).get("versions", [])
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
                "total_vulnerabilities": len(matches),
                "critical": sev_counts["Critical"],
                "high": sev_counts["High"],
                "medium": sev_counts["Medium"]
            },
            findings=matches[:50],
            recommendations=[f"Patch {m['package']} to {m['fix_versions']}" for m in matches if m.get("fix_versions")][:15],
            raw_output=out[:3000] if len(out) > 3000 else out
        )
