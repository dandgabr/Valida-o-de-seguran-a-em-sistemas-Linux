"""Kube-bench Kubernetes Security Integration Adapter."""

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
from sec_audit_linux.core.utils import execute_command, check_command_available


class KubeBenchAdapter(BaseToolAdapter):
    """Integrates Aqua Security kube-bench (CIS Kubernetes Benchmark)."""

    tool_name = "kube_bench"
    tool_category = "Kubernetes & Cloud Native Security"
    binary_name = "kube-bench"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "Checks whether Kubernetes nodes are deployed securely according to the CIS Kubernetes Benchmark"

    def audit(self, context: SystemContext) -> ToolReport:
        start_time = time.time()
        is_installed = self.is_available()
        k8s_present = check_command_available("kubectl") or check_command_available("kubelet")

        if not k8s_present and not is_installed:
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                status=ToolExecutionStatus.SKIPPED,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={"status": "kubernetes_not_detected"},
                recommendations=["Host does not run Kubernetes node components. Kube-bench skipped."]
            )

        if is_installed:
            out, err, code = execute_command(["kube-bench", "--json"], timeout=90)
            findings = []
            metrics = {"total_pass": 0, "total_fail": 0, "total_warn": 0}
            if code == 0 and out.strip():
                try:
                    data = json.loads(out)
                    controls = data.get("Controls", [])
                    for c in controls:
                        tests = c.get("tests", [])
                        for t in tests:
                            for res in t.get("results", []):
                                status_str = res.get("status", "FAIL")
                                if status_str == "PASS":
                                    metrics["total_pass"] += 1
                                elif status_str == "FAIL":
                                    metrics["total_fail"] += 1
                                else:
                                    metrics["total_warn"] += 1
                                findings.append({
                                    "test_number": res.get("test_number"),
                                    "test_desc": res.get("test_desc"),
                                    "status": status_str,
                                    "remediation": res.get("remediation")
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
                summary_metrics=metrics,
                findings=findings[:50],
                recommendations=[f["remediation"] for f in findings if f.get("remediation")][:15],
                raw_output=out or err
            )
        else:
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                status=ToolExecutionStatus.NOT_INSTALLED,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={"status": "kube_bench_not_installed"},
                recommendations=["Install kube-bench for CIS Kubernetes master/worker benchmark validation."]
            )
