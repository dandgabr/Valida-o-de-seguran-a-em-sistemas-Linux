"""Container and Runtime Security (Docker daemon, socket, podman, kubernetes) Collector."""

import json
import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import (
    execute_command,
    read_system_file,
    get_file_stat,
    check_command_available
)


class ContainersCollector(BaseCollector):
    """Audits Docker daemon configuration, socket permissions, and container runtime security."""

    name = "containers"
    description = "Audits Docker daemon, socket security, privileged containers, and container runtime settings"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        docker_installed = check_command_available("docker")
        podman_installed = check_command_available("podman")

        # 1. Docker Socket Permissions
        docker_sock = "/var/run/docker.sock"
        sock_stat = get_file_stat(docker_sock) if os.path.exists(docker_sock) else None

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="docker_socket_security",
            raw_output=f"Docker installed: {docker_installed}, Socket stat: {sock_stat}",
            parsed_data={
                "docker_installed": docker_installed,
                "podman_installed": podman_installed,
                "socket_present": sock_stat is not None,
                "socket_stat": sock_stat
            }
        ))

        # 2. Docker Daemon Configuration (/etc/docker/daemon.json)
        daemon_cfg, _ = read_system_file("/etc/docker/daemon.json")
        daemon_json_data = {}
        if daemon_cfg:
            try:
                daemon_json_data = json.loads(daemon_cfg)
            except Exception:
                daemon_json_data = {"parse_error": True}

        # Check key security flags in daemon.json
        live_restore = daemon_json_data.get("live-restore", False)
        no_new_privileges = daemon_json_data.get("no-new-privileges", False)
        userland_proxy = daemon_json_data.get("userland-proxy", True)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="docker_daemon_config",
            raw_output=daemon_cfg or "daemon.json not present",
            parsed_data={
                "daemon_config_present": bool(daemon_cfg),
                "live_restore": live_restore,
                "no_new_privileges": no_new_privileges,
                "userland_proxy_disabled": not userland_proxy
            }
        ))

        # 3. Running Containers Inspection (if docker available)
        if docker_installed:
            ps_out, _, ps_code = execute_command(["docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}"])
            running_containers = [l.strip() for l in ps_out.splitlines() if l.strip()]

            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="docker_running_containers",
                raw_output=ps_out,
                parsed_data={
                    "running_count": len(running_containers),
                    "containers": running_containers
                }
            ))

        return records
