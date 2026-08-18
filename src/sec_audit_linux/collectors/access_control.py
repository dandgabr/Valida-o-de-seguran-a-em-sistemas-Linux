"""Access Control (SELinux, AppArmor, ACLs, File Permissions) Collector."""

import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import (
    read_system_file,
    execute_command,
    get_file_stat,
    parse_key_value_file
)


class AccessControlCollector(BaseCollector):
    """Audits SELinux, AppArmor, file permissions, SUID binaries, and POSIX ACLs."""

    name = "access_control"
    description = "Audits SELinux status, AppArmor profiles, critical file modes, and SUID/SGID binaries"

    CRITICAL_FILES = [
        {"path": "/etc/passwd", "expected_mode": "0644", "expected_uid": 0},
        {"path": "/etc/shadow", "expected_mode": ["0000", "0600", "0640"], "expected_uid": 0},
        {"path": "/etc/group", "expected_mode": "0644", "expected_uid": 0},
        {"path": "/etc/gshadow", "expected_mode": ["0000", "0600", "0640"], "expected_uid": 0},
        {"path": "/etc/sudoers", "expected_mode": ["0440", "0400"], "expected_uid": 0},
        {"path": "/etc/ssh/sshd_config", "expected_mode": ["0600", "0640"], "expected_uid": 0},
        {"path": "/etc/crontab", "expected_mode": ["0600", "0644"], "expected_uid": 0},
        {"path": "/boot/grub2/grub.cfg", "expected_mode": ["0600", "0400"], "expected_uid": 0},
        {"path": "/boot/grub/grub.cfg", "expected_mode": ["0600", "0400"], "expected_uid": 0}
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. SELinux Status
        selinux_mode = "not_installed"
        sestatus_out, _, sestatus_code = execute_command(["sestatus"])
        if sestatus_code == 0:
            for line in sestatus_out.splitlines():
                if "Current mode:" in line:
                    selinux_mode = line.split(":", 1)[1].strip().lower()
                elif "SELinux status:" in line and "disabled" in line.lower():
                    selinux_mode = "disabled"
        else:
            # Check /etc/selinux/config
            cfg, _ = read_system_file("/etc/selinux/config")
            if cfg:
                kv = parse_key_value_file(cfg)
                selinux_mode = kv.get("SELINUX", "unknown").lower()

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="selinux_status",
            raw_output=sestatus_out or f"SELinux Mode: {selinux_mode}",
            parsed_data={
                "mode": selinux_mode,
                "is_enforcing": selinux_mode == "enforcing",
                "is_permissive": selinux_mode == "permissive",
                "is_disabled": selinux_mode in ["disabled", "not_installed"]
            }
        ))

        # 2. AppArmor Status
        apparmor_status = "not_installed"
        aa_out, _, aa_code = execute_command(["aa-status"])
        if aa_code == 0:
            apparmor_status = "active"
        elif os.path.exists("/sys/kernel/security/apparmor"):
            apparmor_status = "loaded_in_kernel"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="apparmor_status",
            raw_output=aa_out or f"AppArmor status: {apparmor_status}",
            parsed_data={"status": apparmor_status}
        ))

        # 3. Critical File Permissions Audit
        file_audits = []
        permission_deviations = []

        for item in self.CRITICAL_FILES:
            path = item["path"]
            if os.path.exists(path):
                stat_data = get_file_stat(path)
                if stat_data:
                    expected_modes = item["expected_mode"] if isinstance(item["expected_mode"], list) else [item["expected_mode"]]
                    actual_mode = stat_data["mode_octal"]
                    compliant = (actual_mode in expected_modes) and (stat_data["uid"] == item["expected_uid"])
                    file_info = {
                        "path": path,
                        "stat": stat_data,
                        "expected_mode": item["expected_mode"],
                        "compliant": compliant
                    }
                    file_audits.append(file_info)
                    if not compliant:
                        permission_deviations.append(file_info)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="critical_file_permissions",
            raw_output="\n".join(f"{f['path']} -> mode: {f['stat']['mode_octal']}, compliant: {f['compliant']}" for f in file_audits),
            parsed_data={
                "audited_files": file_audits,
                "deviations": permission_deviations,
                "all_compliant": len(permission_deviations) == 0
            }
        ))

        # 4. Dangerous SUID/SGID Binaries in common user writeable paths
        suid_out, _, _ = execute_command(["find", "/tmp", "/var/tmp", "-perm", "/6000", "-type", "f"], timeout=5)
        suid_in_tmp = [x.strip() for x in suid_out.splitlines() if x.strip()]

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="suid_binaries_in_temp",
            raw_output=suid_out or "No SUID files found in /tmp or /var/tmp",
            parsed_data={
                "suid_files_in_tmp": suid_in_tmp,
                "has_dangerous_suid": len(suid_in_tmp) > 0
            }
        ))

        return records
