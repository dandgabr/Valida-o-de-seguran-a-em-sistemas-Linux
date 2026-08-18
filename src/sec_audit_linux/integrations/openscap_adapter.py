"""OpenSCAP / SSG Integration Adapter."""

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
from sec_audit_linux.core.utils import execute_command


class OpenSCAPAdapter(BaseToolAdapter):
    """Integrates OpenSCAP (oscap) for SCAP Security Guide compliance evaluation."""

    tool_name = "openscap"
    tool_category = "SCAP & Compliance Automation"
    binary_name = "oscap"
    license = "LGPL-2.1 (Open Source / Free for Corporate Use)"
    description = "NIST-certified SCAP 1.2/1.3 scanner for automated compliance evaluation"

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
                summary_metrics={"status": "openscap_not_installed"},
                recommendations=["Install openscap-scanner and scap-security-guide for SCAP/XCCDF benchmark evaluation."]
            )

        ssg_dir = "/usr/share/xml/scap/ssg/content"
        has_ssg = os.path.exists(ssg_dir)

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "openscap_installed": True,
                "ssg_content_installed": has_ssg,
                "ssg_directory": ssg_dir
            },
            findings=[{"property": "ssg_datastreams", "present": has_ssg}],
            recommendations=["Run targeted XCCDF profiles (e.g. cis, ospp, pci-dss) using oscap xccdf eval."]
        )
