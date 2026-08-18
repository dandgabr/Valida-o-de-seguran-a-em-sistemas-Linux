"""Docker Bench Security Integration Adapter."""

from typing import List
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command, check_command_available


class DockerBenchAdapter(BaseToolAdapter):
    """Integrates Docker Bench for Security container assessment."""

    tool_name = "docker_bench"
    binary_name = "docker-bench-security"
    description = "Docker Bench for Security CIS assessment"

    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        if not self.is_available() and not check_command_available("docker"):
            return [EvidenceRecord(
                collector_name=self.tool_name,
                target_item="docker_bench_status",
                raw_output="Docker or Docker Bench Security not available.",
                parsed_data={"installed": False}
            )]

        out, err, code = execute_command(["docker-bench-security", "-b", "-c", "check_2"], timeout=30)
        return [EvidenceRecord(
            collector_name=self.tool_name,
            target_item="docker_bench_run",
            command_executed="docker-bench-security -b -c check_2",
            raw_output=out or err,
            parsed_data={"installed": True, "exit_code": code}
        )]
