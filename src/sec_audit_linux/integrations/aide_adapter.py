"""AIDE (Advanced Intrusion Detection Environment) Integration Adapter."""

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
from sec_audit_linux.core.utils import execute_command, check_command_available


class AIDEAdapter(BaseToolAdapter):
    """Integrates AIDE file integrity scanner."""

    tool_name = "aide_adapter"
    tool_category = "File Integrity Monitoring (FIM)"
    binary_name = "aide"
    license = "GPL-2.0 (Open Source / Free for Corporate Use)"
    description = "AIDE Advanced Intrusion Detection Environment"

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
                summary_metrics={"status": "aide_not_installed"},
                recommendations=["Install aide ('apt install aide') and run aideinit to establish baseline hashes."]
            )

        db_paths = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide/aide.db.new"
        ]
        has_db = any(os.path.exists(p) for p in db_paths)

        if has_db:
            out, err, code = execute_command(["aide", "--check", "--quiet"], timeout=30)
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=True,
                version=self.get_version(),
                status=ToolExecutionStatus.SUCCESS if code in [0, 4] else ToolExecutionStatus.FAILED,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={
                    "database_present": True,
                    "clean_baseline": code == 0,
                    "changes_detected": code != 0
                },
                findings=[{"status": "clean" if code == 0 else "integrity_deviation_detected"}],
                recommendations=["Review modified files in /var/log/aide/aide.log if baseline changes are reported."]
            )
        else:
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=True,
                version=self.get_version(),
                status=ToolExecutionStatus.SUCCESS,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={
                    "database_present": False,
                    "aide_installed": True
                },
                findings=[{"status": "aide_database_uninitialized"}],
                recommendations=["Run 'sudo aideinit' to generate initial baseline database."]
            )
