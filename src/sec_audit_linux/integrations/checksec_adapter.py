"""Checksec Binary Protection & Compiler Hardening Adapter."""

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


class ChecksecAdapter(BaseToolAdapter):
    """Integrates checksec for binary hardening audit (RELRO, Stack Canary, NX, PIE, Fortify)."""

    tool_name = "checksec"
    tool_category = "Binary & Executable Hardening"
    binary_name = "checksec"
    license = "BSD-3-Clause (Open Source / Free for Corporate Use)"
    description = "Checks binary security flags (PIE, RELRO, Stack Canary, NX, RPATH, ASLR)"

    CRITICAL_BINARIES = [
        "/usr/bin/sudo",
        "/usr/sbin/sshd",
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/dockerd"
    ]

    def audit(self, context: SystemContext) -> ToolReport:
        start_time = time.time()
        is_installed = self.is_available()

        existing_bins = [b for b in self.CRITICAL_BINARIES if os.path.exists(b)]
        findings = []
        metrics = {"total_audited": len(existing_bins), "full_relro": 0, "canary_enabled": 0, "nx_enabled": 0, "pie_enabled": 0}

        if is_installed:
            for b in existing_bins:
                out, _, code = execute_command(["checksec", "--file=" + b, "--format=json"], timeout=10)
                if code == 0 and out.strip():
                    findings.append({"binary": b, "raw_checksec": out.strip()})
                else:
                    out_txt, _, _ = execute_command(["checksec", "--file=" + b], timeout=10)
                    findings.append({"binary": b, "summary": out_txt.strip()})

            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=True,
                version=self.get_version(),
                status=ToolExecutionStatus.SUCCESS,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={"audited_binaries_count": len(existing_bins)},
                findings=findings,
                recommendations=["Compile custom corporate binaries with flags: -fstack-protector-strong -Wl,-z,relro,-z,now -fPIE -pie"]
            )
        else:
            # Fallback native check using readelf or file
            has_readelf = check_command_available("readelf")
            for b in existing_bins:
                b_info = {"binary": b}
                if has_readelf:
                    relro_out, _, _ = execute_command(["readelf", "-l", b])
                    b_info["has_gnu_relro"] = "GNU_RELRO" in (relro_out or "")
                    b_info["has_gnu_stack_nx"] = "GNU_STACK" in (relro_out or "")
                    if b_info["has_gnu_relro"]:
                        metrics["full_relro"] += 1
                    if b_info["has_gnu_stack_nx"]:
                        metrics["nx_enabled"] += 1
                findings.append(b_info)

            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                status=ToolExecutionStatus.SUCCESS,
                version="native_readelf_fallback",
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics=metrics,
                findings=findings,
                recommendations=["Install checksec (apt install checksec / go install github.com/slimm609/checksec) for full JSON reports."]
            )
