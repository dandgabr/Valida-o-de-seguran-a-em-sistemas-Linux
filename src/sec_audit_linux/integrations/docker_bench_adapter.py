"""Docker Bench Security Integration Adapter."""

import os
import re
import time
from typing import List, Dict, Any
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import (
    EvidenceRecord,
    SystemContext,
    ToolReport,
    ToolExecutionStatus
)
from sec_audit_linux.core.utils import execute_command, check_command_available, read_system_file


class DockerBenchAdapter(BaseToolAdapter):
    """Integrates Docker Bench for Security (CIS Docker Benchmark)."""

    tool_name = "docker_bench"
    tool_category = "Container & Docker Security"
    binary_name = "docker-bench-security"
    license = "Apache-2.0 (Open Source / Free for Corporate Use)"
    description = "Checks common security best practices for deploying Docker containers (CIS Docker Benchmark)"

    def audit(self, context: SystemContext) -> ToolReport:
        start_time = time.time()
        is_installed = self.is_available()
        docker_available = check_command_available("docker")

        if not docker_available:
            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                status=ToolExecutionStatus.NOT_INSTALLED,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={"status": "docker_not_installed"},
                recommendations=["Docker is not installed on this host. No container benchmark necessary."]
            )

        if not is_installed:
            # Native inspection of Docker daemon and container best practices
            daemon_json_path = "/etc/docker/daemon.json"
            daemon_cfg, _ = read_system_file(daemon_json_path)
            socket_path = "/var/run/docker.sock"
            sock_exists = os.path.exists(socket_path)

            findings = [
                {
                    "check": "CIS-Docker-1.1",
                    "title": "Ensure docker daemon configuration file exists",
                    "status": "PASS" if daemon_cfg else "WARN",
                    "details": f"File {daemon_json_path} present: {bool(daemon_cfg)}"
                },
                {
                    "check": "CIS-Docker-2.1",
                    "title": "Ensure network traffic is restricted between containers (icc=false)",
                    "status": "PASS" if daemon_cfg and '"icc": false' in daemon_cfg else "WARN",
                    "details": "Unrestricted inter-container communication"
                },
                {
                    "check": "CIS-Docker-2.14",
                    "title": "Ensure live restore is enabled",
                    "status": "PASS" if daemon_cfg and '"live-restore": true' in daemon_cfg else "WARN",
                    "details": "Keep containers alive during daemon downtime"
                },
                {
                    "check": "CIS-Docker-2.18",
                    "title": "Ensure userland proxy is disabled",
                    "status": "PASS" if daemon_cfg and '"userland-proxy": false' in daemon_cfg else "WARN",
                    "details": "Use hairpin NAT instead of userland proxy"
                }
            ]

            pass_count = sum(1 for f in findings if f["status"] == "PASS")
            warn_count = sum(1 for f in findings if f["status"] == "WARN")

            return ToolReport(
                tool_name=self.tool_name,
                tool_category=self.tool_category,
                license=self.license,
                is_installed=False,
                version="native_docker_eval",
                status=ToolExecutionStatus.SUCCESS,
                execution_time_seconds=round(time.time() - start_time, 3),
                summary_metrics={
                    "total_checks": len(findings),
                    "passed_checks": pass_count,
                    "warnings": warn_count,
                    "compliance_rate": f"{(pass_count / len(findings)) * 100:.1f}%"
                },
                findings=findings,
                recommendations=[
                    "Configure 'no-new-privileges: true' and 'live-restore: true' in /etc/docker/daemon.json",
                    "Install docker-bench-security for full multi-section CIS benchmark execution."
                ]
            )

        # Run docker-bench-security binary
        out, err, code = execute_command(["docker-bench-security", "-b"], timeout=120)
        
        warn_matches = re.findall(r"\[WARN\] (.*)", out)
        pass_matches = re.findall(r"\[PASS\] (.*)", out)
        info_matches = re.findall(r"\[INFO\] (.*)", out)

        findings = []
        for w in warn_matches:
            findings.append({"status": "WARN", "description": w.strip()})
        for p in pass_matches:
            findings.append({"status": "PASS", "description": p.strip()})

        total = len(pass_matches) + len(warn_matches)
        pass_rate = (len(pass_matches) / total * 100) if total > 0 else 100.0

        return ToolReport(
            tool_name=self.tool_name,
            tool_category=self.tool_category,
            license=self.license,
            is_installed=True,
            version=self.get_version(),
            status=ToolExecutionStatus.SUCCESS,
            execution_time_seconds=round(time.time() - start_time, 3),
            summary_metrics={
                "total_checks": total,
                "passed_checks": len(pass_matches),
                "warnings": len(warn_matches),
                "pass_rate": f"{pass_rate:.1f}%"
            },
            findings=findings[:40],
            recommendations=[f"Remediate Docker finding: {w}" for w in warn_matches[:10]],
            raw_output=out or err
        )
