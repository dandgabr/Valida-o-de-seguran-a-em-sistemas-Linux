"""AIDE (Advanced Intrusion Detection Environment) Integration Adapter."""

from typing import List
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command


class AIDEAdapter(BaseToolAdapter):
    """Integrates AIDE integrity scanner."""

    tool_name = "aide_adapter"
    binary_name = "aide"
    description = "AIDE File Integrity Checker"

    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        if not self.is_available():
            return [EvidenceRecord(
                collector_name=self.tool_name,
                target_item="aide_tool_status",
                raw_output="AIDE binary is not available on PATH.",
                parsed_data={"installed": False}
            )]

        out, err, code = execute_command(["aide", "--check"], timeout=30)
        return [EvidenceRecord(
            collector_name=self.tool_name,
            target_item="aide_check_run",
            command_executed="aide --check",
            raw_output=out or err,
            parsed_data={
                "installed": True,
                "exit_code": code,
                "clean_baseline": code == 0
            }
        )]
