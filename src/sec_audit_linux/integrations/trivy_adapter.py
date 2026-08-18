"""Trivy / Grype Vulnerability Scanner Adapter."""

import json
from typing import List
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command


class TrivyAdapter(BaseToolAdapter):
    """Integrates Aqua Security Trivy filesystem vulnerability scanner."""

    tool_name = "trivy"
    binary_name = "trivy"
    description = "Trivy Vulnerability & Misconfiguration Scanner"

    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        if not self.is_available():
            return [EvidenceRecord(
                collector_name=self.tool_name,
                target_item="trivy_status",
                raw_output="Trivy binary is not installed.",
                parsed_data={"installed": False}
            )]

        out, err, code = execute_command(["trivy", "rootfs", "--severity", "HIGH,CRITICAL", "--format", "json", "/"], timeout=45)
        parsed_vulns = []
        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                results = data.get("Results", [])
                for r in results:
                    vulns = r.get("Vulnerabilities", [])
                    for v in vulns:
                        parsed_vulns.append({
                            "cve_id": v.get("VulnerabilityID"),
                            "package": v.get("PkgName"),
                            "severity": v.get("Severity"),
                            "installed_version": v.get("InstalledVersion"),
                            "fixed_version": v.get("FixedVersion")
                        })
            except Exception:
                pass

        return [EvidenceRecord(
            collector_name=self.tool_name,
            target_item="trivy_vulnerability_scan",
            command_executed="trivy rootfs --severity HIGH,CRITICAL --format json /",
            raw_output=out[:2000] if len(out) > 2000 else out,
            parsed_data={
                "installed": True,
                "total_high_critical_vulns": len(parsed_vulns),
                "vulnerabilities": parsed_vulns[:50]
            }
        )]
