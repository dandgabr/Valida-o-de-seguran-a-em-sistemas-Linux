"""osquery SQL System Instrumentation Integration Adapter."""

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


class OSQueryAdapter(BaseToolAdapter):
    """Integrates osquery SQL-powered instrumentation framework."""

    tool_name = "osquery"
    tool_category = "System Instrumentation & Live Querying"
    binary_name = "osqueryi"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "Exposes operating system state as a high-performance relational database"

    STANDARD_SECURITY_QUERIES = {
        "listening_ports": "SELECT port, address, protocol, pid FROM listening_ports WHERE port != 0;",
        "crontab_entries": "SELECT command, path FROM crontab;",
        "suid_binaries": "SELECT path, permissions FROM suid_binaries LIMIT 50;",
        "users_without_passwords": "SELECT username, shell FROM users WHERE uid >= 1000;"
    }

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
                summary_metrics={"status": "osquery_not_installed"},
                recommendations=["Install osquery (https://osquery.io) to enable live relational SQL queries for system security state."]
            )

        query_results: Dict[str, Any] = {}
        for q_name, q_sql in self.STANDARD_SECURITY_QUERIES.items():
            out, _, code = execute_command(["osqueryi", "--json", q_sql], timeout=15)
            if code == 0 and out.strip():
                try:
                    query_results[q_name] = json.loads(out)
                except Exception:
                    query_results[q_name] = out.strip()
            else:
                query_results[q_name] = []

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "queries_executed": len(self.STANDARD_SECURITY_QUERIES),
                "listening_ports_count": len(query_results.get("listening_ports", [])),
                "crontabs_count": len(query_results.get("crontab_entries", []))
            },
            findings=[{"query": k, "rows": v} for k, v in query_results.items()],
            recommendations=["Monitor active osquery packs for continuous threat detection."]
        )
