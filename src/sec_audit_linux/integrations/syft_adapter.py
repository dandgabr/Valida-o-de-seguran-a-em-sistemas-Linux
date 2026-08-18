"""Anchore Syft SBOM (Software Bill of Materials) Integration Adapter."""

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


class SyftAdapter(BaseToolAdapter):
    """Integrates Anchore Syft for Software Bill of Materials (SBOM) generation."""

    tool_name = "syft"
    tool_category = "Supply Chain & Software Bill of Materials (SBOM)"
    binary_name = "syft"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "CLI tool and library for generating a Software Bill of Materials (SBOM) from container images and filesystems"

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
                summary_metrics={"status": "syft_not_installed"},
                recommendations=["Install syft (https://github.com/anchore/syft) to catalog software supply chain packages."]
            )

        # Run syft scan with quiet JSON output on system configuration directory
        out, err, code = execute_command(
            ["syft", "scan", "-q", "-o", "json", "dir:/etc"],
            timeout=25
        )

        packages = []
        pkg_types = {}

        if code == 0 and out.strip():
            try:
                data = json.loads(out)
                for artifact in data.get("artifacts", []):
                    ptype = artifact.get("type", "unknown")
                    pkg_types[ptype] = pkg_types.get(ptype, 0) + 1
                    packages.append({
                        "name": artifact.get("name"),
                        "version": artifact.get("version"),
                        "type": ptype,
                        "purl": artifact.get("purl", "")
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
                "total_installed_packages": len(packages),
                "package_types_breakdown": pkg_types
            },
            findings=packages[:100],
            recommendations=["Maintain signed SBOM artifacts in corporate artifact repositories for continuous vulnerability tracking."]
        )
