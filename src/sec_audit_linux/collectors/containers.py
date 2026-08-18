"""Container, Docker Daemon, and Container Runtime Security Collector."""

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
    description = "Audits Docker daemon, socket security, container privileges, mounts, and runtime parameters"

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
                "socket_stat": sock_stat,
                "is_socket_secure": sock_stat is not None and sock_stat.get("mode_octal") in ["0660", "0600"]
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
        icc = daemon_json_data.get("icc", True)
        userns_remap = daemon_json_data.get("userns-remap", "")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="docker_daemon_config",
            raw_output=daemon_cfg or "daemon.json not present",
            parsed_data={
                "daemon_config_present": bool(daemon_cfg),
                "live_restore": live_restore,
                "no_new_privileges": no_new_privileges,
                "userland_proxy_disabled": not userland_proxy,
                "icc_disabled": not icc,
                "userns_remap": userns_remap,
                "is_daemon_hardened": bool(daemon_cfg) and no_new_privileges and (not icc)
            }
        ))

        # 3. Docker Running & Stopped Containers Deep Inspection
        if docker_installed:
            ps_out, _, ps_code = execute_command(["docker", "ps", "-a", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}"])
            raw_containers = [l.strip() for l in (ps_out or "").splitlines() if l.strip()]

            container_audits = []
            privileged_containers = []
            host_network_containers = []
            sensitive_mount_containers = []
            root_user_containers = []

            for c_line in raw_containers:
                parts = c_line.split("|")
                if len(parts) >= 3:
                    c_id = parts[0]
                    c_image = parts[1]
                    c_name = parts[2]

                    # Run docker inspect for deep security posture
                    inspect_out, _, inspect_code = execute_command(["docker", "inspect", c_id], timeout=10)
                    if inspect_code == 0 and inspect_out.strip():
                        try:
                            c_data = json.loads(inspect_out)[0]
                            host_cfg = c_data.get("HostConfig", {})
                            cfg = c_data.get("Config", {})

                            is_priv = host_cfg.get("Privileged", False)
                            net_mode = host_cfg.get("NetworkMode", "default")
                            pid_mode = host_cfg.get("PidMode", "default")
                            ipc_mode = host_cfg.get("IpcMode", "default")
                            readonly_root = host_cfg.get("ReadonlyRootfs", False)
                            cap_add = host_cfg.get("CapAdd") or []
                            cap_drop = host_cfg.get("CapDrop") or []
                            sec_opts = host_cfg.get("SecurityOpt") or []
                            user = cfg.get("User", "root (default)")

                            # Check sensitive mounts
                            binds = host_cfg.get("Binds") or []
                            mounts = c_data.get("Mounts") or []
                            sensitive_targets = ["/var/run/docker.sock", "/etc", "/proc", "/sys", "/"]
                            has_sensitive_mount = any(
                                any(st in str(m) for st in sensitive_targets)
                                for m in binds + [m.get("Source", "") for m in mounts if isinstance(m, dict)]
                            )

                            if is_priv:
                                privileged_containers.append(c_name)
                            if net_mode == "host":
                                host_network_containers.append(c_name)
                            if has_sensitive_mount:
                                sensitive_mount_containers.append(c_name)
                            if user in ["", "0", "root"]:
                                root_user_containers.append(c_name)

                            container_audits.append({
                                "id": c_id,
                                "name": c_name,
                                "image": c_image,
                                "privileged": is_priv,
                                "network_mode": net_mode,
                                "pid_mode": pid_mode,
                                "ipc_mode": ipc_mode,
                                "readonly_rootfs": readonly_root,
                                "capabilities_added": cap_add,
                                "security_options": sec_opts,
                                "user": user,
                                "has_sensitive_mounts": has_sensitive_mount
                            })
                        except Exception:
                            pass

            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="docker_containers_security_audit",
                raw_output=f"Containers found: {len(container_audits)}\nPrivileged: {privileged_containers}\nHost Net: {host_network_containers}",
                parsed_data={
                    "total_containers": len(container_audits),
                    "privileged_containers": privileged_containers,
                    "host_network_containers": host_network_containers,
                    "sensitive_mount_containers": sensitive_mount_containers,
                    "root_user_containers": root_user_containers,
                    "containers_detail": container_audits,
                    "all_containers_secure": len(privileged_containers) == 0 and len(sensitive_mount_containers) == 0
                }
            ))

            # 4. Docker Images Inventory
            img_out, _, img_code = execute_command(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}"])
            images_list = [l.strip() for l in (img_out or "").splitlines() if l.strip()]
            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="docker_images_inventory",
                raw_output=img_out,
                parsed_data={
                    "total_images": len(images_list),
                    "images": images_list
                }
            ))

        return records
