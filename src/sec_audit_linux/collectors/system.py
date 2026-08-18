"""System, Kernel, Bootloader, Sysctl, Kernel Modules, and Systemd Collector."""

import glob
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
    """Audits OS Kernel parameters, sysctl, disabled kernel modules, bootloader, and services."""

    name = "system"
    description = "Audits Kernel, Sysctl, Kernel Modules, Bootloader, GRUB, and Systemd parameters"

    # Core security sysctl parameters
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

    # Uncommon filesystems and protocols that should be disabled
    UNCOMMON_MODULES = [
        "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "squashfs", "udf",
        "dccp", "sctp", "rds", "tipc"
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Kernel Runtime Sysctl Parameters
        sysctl_values: Dict[str, str] = {}
        for param in self.AUDIT_SYSCTLS:
            proc_path = "/proc/sys/" + param.replace(".", "/")
            val, _ = read_system_file(proc_path)
            if val is not None:
                sysctl_values[param] = val.strip()
            else:
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

        # 2. Kernel Modules Status (Uncommon filesystems & protocols)
        modprobe_files = glob.glob("/etc/modprobe.d/*.conf") + ["/etc/modprobe.conf"]
        mod_contents = ""
        for mf in modprobe_files:
            content, _ = read_system_file(mf)
            if content:
                mod_contents += f"\n{content}"

        disabled_modules = {}
        for mod in self.UNCOMMON_MODULES:
            # Check if install /bin/true or /bin/false or blacklist present
            is_disabled = (
                f"install {mod} /bin/true" in mod_contents
                or f"install {mod} /bin/false" in mod_contents
                or f"blacklist {mod}" in mod_contents
            )
            # Check runtime lsmod
            lsmod_out, _, _ = execute_command(["lsmod"])
            is_loaded = mod in (lsmod_out or "")
            disabled_modules[mod] = {
                "disabled_in_config": is_disabled,
                "loaded_in_kernel": is_loaded,
                "is_secure": is_disabled and not is_loaded
            }

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="kernel_modules_status",
            raw_output=f"Kernel modules audit:\n{disabled_modules}",
            parsed_data=disabled_modules
        ))

        # 3. Bootloader & GRUB Security
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

        # 4. Secure Boot Status
        sb_out, _, sb_code = execute_command(["mokutil", "--sb-state"])
        sb_status = "unknown"
        if sb_code == 0:
            sb_status = "enabled" if "SecureBoot enabled" in sb_out else "disabled"
        else:
            sb_status = "efi_present" if os.path.exists("/sys/firmware/efi") else "legacy_bios"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="secure_boot_status",
            raw_output=sb_out or sb_status,
            parsed_data={"secure_boot": sb_status}
        ))

        # 5. Dangerous / Unnecessary Services
        dangerous_services = [
            "telnet.socket", "telnet.service",
            "rsh.socket", "rsh.service",
            "rlogin.service", "rexec.service",
            "tftp.socket", "tftp.service",
            "vsftpd.service", "proftpd.service", "pure-ftpd.service",
            "nfs-server.service", "rpcbind.service",
            "avahi-daemon.service", "cups.service",
            "dhcpd.service", "slapd.service",
            "smb.service", "nmb.service", "snmpd.service",
            "xinetd.service", "nis.service"
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

        # 6. Session Timeout (TMOUT in /etc/profile & /etc/bash.bashrc)
        profile_files = ["/etc/profile", "/etc/bash.bashrc"] + glob.glob("/etc/profile.d/*.sh")
        tmout_val = None
        for pf in profile_files:
            content, _ = read_system_file(pf)
            if content and "TMOUT=" in content:
                for line in content.splitlines():
                    if "TMOUT=" in line and not line.strip().startswith("#"):
                        tmout_val = line.split("TMOUT=", 1)[1].split(";")[0].strip()

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="shell_session_timeout",
            raw_output=f"TMOUT value found: {tmout_val}",
            parsed_data={
                "tmout_configured": tmout_val is not None,
                "tmout_seconds": int(tmout_val) if tmout_val and tmout_val.isdigit() else -1
            }
        ))

        return records
