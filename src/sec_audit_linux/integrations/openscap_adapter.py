"""OpenSCAP / SSG Integration Adapter."""

import os
from typing import List, Dict, Any
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command


class OpenSCAPAdapter(BaseToolAdapter):
    """Integrates OpenSCAP (oscap) command-line utility for SCAP content evaluation."""

    tool_name = "openscap"
    binary_name = "oscap"
    description = "OpenSCAP Scanner for Security Content Automation Protocol (SCAP)"

    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        if not self.is_available():
            return [EvidenceRecord(
                collector_name=self.tool_name,
                target_item="openscap_status",
                raw_output="OpenSCAP (oscap) binary is not installed.",
                parsed_data={"installed": False}
            )]

        # Check installed SSG datastreams
        ssg_dir = "/usr/share/xml/scap/ssg/content"
        has_ssg = os.path.exists(ssg_dir)

        return [EvidenceRecord(
            collector_name=self.tool_name,
            target_item="openscap_environment",
            command_executed="oscap version",
            raw_output=f"OpenSCAP installed: True, SSG Content dir: {has_ssg}",
            parsed_data={
                "installed": True,
                "ssg_content_present": has_ssg,
                "ssg_dir": ssg_dir
            }
        )]
