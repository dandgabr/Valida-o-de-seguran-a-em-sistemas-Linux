"""OpenSSH Server Hardening and Cryptographic Suite Collector."""

import glob
import re
from typing import List, Dict, Any, Optional
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import read_system_file, execute_command, get_file_stat


class SSHCollector(BaseCollector):
    """Audits OpenSSH configuration, permissions, authentication controls, and crypto algorithms."""

    name = "ssh"
    description = "Audits SSH Server configuration (PermitRootLogin, PasswordAuth, Ciphers, MACs, Kex)"

    # Weak / Deprecated Cryptographic Suites
    WEAK_CIPHERS = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"]
    WEAK_MACS = ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-sha1"]
    WEAK_KEX = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Effective Runtime OpenSSH Settings (via `sshd -T`)
        effective_settings: Dict[str, str] = {}
        sshd_t_out, sshd_t_err, sshd_t_code = execute_command(["sshd", "-T"])
        
        if sshd_t_code == 0:
            for line in sshd_t_out.splitlines():
                if " " in line:
                    key, val = line.split(" ", 1)
                    effective_settings[key.strip().lower()] = val.strip()

        # 2. Configuration files in /etc/ssh/
        config_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf")
        file_stats = []
        raw_configs = []

        for cf in config_files:
            stat_info = get_file_stat(cf)
            if stat_info:
                file_stats.append(stat_info)
            content, _ = read_system_file(cf)
            if content:
                raw_configs.append(f"--- {cf} ---\n{content}")

        # 3. Analyze SSH Parameters against Hardening Best Practices
        ciphers = [c.strip() for c in effective_settings.get("ciphers", "").split(",") if c.strip()]
        macs = [m.strip() for m in effective_settings.get("macs", "").split(",") if m.strip()]
        kex = [k.strip() for k in effective_settings.get("kexalgorithms", "").split(",") if k.strip()]

        has_weak_ciphers = any(wc in ciphers for wc in self.WEAK_CIPHERS)
        has_weak_macs = any(wm in macs for wm in self.WEAK_MACS)
        has_weak_kex = any(wk in kex for wk in self.WEAK_KEX)

        parsed_analysis = {
            "sshd_active": sshd_t_code == 0,
            "permit_root_login": effective_settings.get("permitrootlogin", "unset"),
            "password_authentication": effective_settings.get("passwordauthentication", "unset"),
            "permit_empty_passwords": effective_settings.get("permitemptypasswords", "unset"),
            "x11_forwarding": effective_settings.get("x11forwarding", "unset"),
            "max_auth_tries": effective_settings.get("maxauthtries", "unset"),
            "client_alive_interval": effective_settings.get("clientaliveinterval", "unset"),
            "client_alive_count_max": effective_settings.get("clientalivecountmax", "unset"),
            "use_pam": effective_settings.get("usepam", "unset"),
            "protocol": effective_settings.get("protocol", "2"),
            "ciphers": ciphers,
            "macs": macs,
            "kex_algorithms": kex,
            "has_weak_ciphers": has_weak_ciphers,
            "has_weak_macs": has_weak_macs,
            "has_weak_kex": has_weak_kex,
            "config_file_stats": file_stats
        }

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="ssh_server_configuration",
            command_executed="sshd -T" if sshd_t_code == 0 else "read /etc/ssh/sshd_config",
            raw_output=sshd_t_out if sshd_t_code == 0 else "\n".join(raw_configs),
            parsed_data=parsed_analysis
        ))

        return records
