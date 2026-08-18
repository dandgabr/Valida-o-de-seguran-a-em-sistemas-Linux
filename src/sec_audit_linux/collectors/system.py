"""System, Kernel, Bootloader, Sysctl, and Systemd Collector."""

import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import (
    execute_command,
    read_system_file,
    calculate_sha256,
    get_file_stat
)


class SystemCollector(BaseCollector):
    """Audits OS Kernel parameters, sysctl configurations, bootloader, and services."""

    name = "system"
    description = "Audits Kernel, Sysctl, Bootloader, GRUB, and Systemd parameters"

    # Core security sysctl parameters to evaluate across CIS / NIST benchmarks
    AUDIT_SYSCTLS = [
        "fs.suid_dumpable",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
        "fs.protected_fifos",
        "fs.protected_regular",
        "kernel.randomize_va_space",
        "kernel.dmesg_restrict",
        "kernel.kptr_restrict",
        "kernel.yama.ptrace_scope",
        "kernel.sysrq",
        "kernel.core_uses_pid",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.default.send_redirects",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv4.conf.all.secure_redirects",
        "net.ipv4.conf.default.secure_redirects",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
        "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.default.log_martians",
        "net.ipv4.icmp_echo_ignore_broadcasts",
        "net.ipv4.icmp_ignore_bogus_error_responses",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "net.ipv4.tcp_syncookies",
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.all.accept_ra",
        "net.ipv6.conf.default.accept_ra",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.default.accept_redirects"
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Kernel Runtime Sysctl Parameters
        sysctl_values: Dict[str, str] = {}
        for param in self.AUDIT_SYSCTLS:
            # Try reading from /proc/sys/
            proc_path = "/proc/sys/" + param.replace(".", "/")
            val, err = read_system_file(proc_path)
            if val is not None:
                sysctl_values[param] = val.strip()
            else:
                # Fallback to sysctl command
                out, _, code = execute_command(["sysctl", "-n", param])
                if code == 0 and out.strip():
                    sysctl_values[param] = out.strip()
                else:
                    sysctl_values[param] = "N/A"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="kernel_sysctl_runtime",
            raw_output="\n".join(f"{k}={v}" for k, v in sysctl_values.items()),
            parsed_data=sysctl_values,
            sha256_checksum=calculate_sha256(str(sysctl_values))
        ))

        # 2. Bootloader & GRUB Security
        grub_paths = [
            "/boot/grub2/grub.cfg",
            "/boot/grub/grub.cfg",
            "/boot/efi/EFI/redhat/grub.cfg",
            "/boot/efi/EFI/ubuntu/grub.cfg",
            "/etc/grub.d/40_custom"
        ]
        for gp in grub_paths:
            if os.path.exists(gp):
                stat_info = get_file_stat(gp)
                content, _ = read_system_file(gp, max_bytes=500_000)
                has_password = "password" in (content or "").lower() or "superusers" in (content or "").lower()
                records.append(EvidenceRecord(
                    collector_name=self.name,
                    target_item=f"bootloader_config:{gp}",
                    raw_output=f"Stat: {stat_info}\nPassword protection detected: {has_password}",
                    parsed_data={
                        "path": gp,
                        "stat": stat_info,
                        "password_protected": has_password
                    }
                ))

        # 3. Secure Boot Status
        sb_out, _, sb_code = execute_command(["mokutil", "--sb-state"])
        sb_status = "unknown"
        if sb_code == 0:
            sb_status = "enabled" if "SecureBoot enabled" in sb_out else "disabled"
        else:
            # Check efi sysfs
            if os.path.exists("/sys/firmware/efi"):
                sb_status = "efi_present"
            else:
                sb_status = "legacy_bios"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="secure_boot_status",
            raw_output=sb_out or sb_status,
            parsed_data={"secure_boot": sb_status}
        ))

        # 4. Systemd Units & Dangerous/Unneeded Services
        dangerous_services = [
            "telnet.socket", "telnet.service",
            "rsh.socket", "rsh.service",
            "rlogin.service", "rexec.service",
            "tftp.socket", "tftp.service",
            "vsftpd.service", "proftpd.service", "pure-ftpd.service",
            "nfs-server.service", "rpcbind.service",
            "avahi-daemon.service", "cups.service",
            "dhcpd.service", "slapd.service",
            "smb.service", "nmb.service", "snmpd.service"
        ]

        svc_states: Dict[str, str] = {}
        for svc in dangerous_services:
            out, _, code = execute_command(["systemctl", "is-enabled", svc])
            svc_states[svc] = out.strip() if code == 0 or out.strip() else "disabled_or_not_found"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="unnecessary_services",
            raw_output="\n".join(f"{k}: {v}" for k, v in svc_states.items()),
            parsed_data=svc_states
        ))

        return records
