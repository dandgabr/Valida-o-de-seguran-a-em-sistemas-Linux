"""User Accounts, Authentication, PAM, Password Policies, and Sudoers Collector."""

import glob
import os
import re
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import (
    read_system_file,
    parse_colon_file,
    parse_key_value_file,
    get_file_stat
)


class IdentityCollector(BaseCollector):
    """Audits local users, UID 0 accounts, shadow password policies, PAM, and sudoers privileges."""

    name = "identity"
    description = "Audits accounts, empty passwords, UID 0, PAM policies, and sudoers rules"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Inspect /etc/passwd: UID 0 accounts, duplicate UIDs, duplicate GIDs
        passwd_content, _ = read_system_file("/etc/passwd")
        uid_zero_users = []
        user_list = []
        if passwd_content:
            rows = parse_colon_file(passwd_content)
            for r in rows:
                if len(r) >= 7:
                    username = r[0]
                    uid = int(r[2]) if r[2].isdigit() else -1
                    shell = r[6]
                    user_list.append({"user": username, "uid": uid, "shell": shell})
                    if uid == 0:
                        uid_zero_users.append(username)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="user_accounts_uid0",
            raw_output=f"UID 0 Accounts: {uid_zero_users}",
            parsed_data={
                "uid_zero_accounts": uid_zero_users,
                "only_root_uid_zero": uid_zero_users == ["root"],
                "total_users": len(user_list)
            }
        ))

        # 2. Inspect /etc/shadow: Empty passwords, locked accounts (if readable / running as root)
        shadow_content, shadow_err = read_system_file("/etc/shadow")
        empty_password_users = []
        locked_users = []
        active_users = []

        if shadow_content:
            shadow_rows = parse_colon_file(shadow_content)
            for sr in shadow_rows:
                if len(sr) >= 2:
                    user = sr[0]
                    pw_hash = sr[1]
                    if pw_hash == "" or pw_hash == "::":
                        empty_password_users.append(user)
                    elif pw_hash.startswith("!") or pw_hash.startswith("*"):
                        locked_users.append(user)
                    else:
                        active_users.append(user)

            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="shadow_passwords_audit",
                raw_output=f"Empty pw users: {empty_password_users}, Active users: {len(active_users)}, Locked users: {len(locked_users)}",
                parsed_data={
                    "empty_password_users": empty_password_users,
                    "has_empty_passwords": len(empty_password_users) > 0,
                    "active_user_count": len(active_users),
                    "locked_user_count": len(locked_users)
                }
            ))
        else:
            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="shadow_passwords_audit",
                raw_output=f"Could not read /etc/shadow: {shadow_err}",
                parsed_data={"error": shadow_err, "readable": False}
            ))

        # 3. Password Aging Policy in /etc/login.defs
        login_defs_content, _ = read_system_file("/etc/login.defs")
        login_defs_dict: Dict[str, str] = {}
        if login_defs_content:
            login_defs_dict = parse_key_value_file(login_defs_content, delimiter=" ", comment_char="#")
            # Filter standard security keys
            sec_keys = ["PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE", "ENCRYPT_METHOD", "UMASK"]
            login_defs_filtered = {k: login_defs_dict.get(k, "unset") for k in sec_keys}
            records.append(EvidenceRecord(
                collector_name=self.name,
                target_item="login_defs_password_policy",
                raw_output="\n".join(f"{k}: {v}" for k, v in login_defs_filtered.items()),
                parsed_data=login_defs_filtered
            ))

        # 4. Sudoers Configuration and NOPASSWD / Wildcard Checks
        sudoers_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
        nopasswd_entries = []
        excessive_wildcards = []
        all_sudoers_rules = []

        for sf in sudoers_files:
            content, _ = read_system_file(sf)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    all_sudoers_rules.append(f"{sf}: {line}")
                    if "NOPASSWD:" in line:
                        nopasswd_entries.append(f"{sf}: {line}")
                    if re.search(r"ALL\s*=\s*\(ALL(:ALL)?\)\s*NOPASSWD:\s*ALL", line):
                        excessive_wildcards.append(f"{sf}: {line}")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="sudoers_privilege_audit",
            raw_output="\n".join(all_sudoers_rules),
            parsed_data={
                "nopasswd_entries": nopasswd_entries,
                "has_nopasswd": len(nopasswd_entries) > 0,
                "excessive_wildcards": excessive_wildcards,
                "has_full_nopasswd_all": len(excessive_wildcards) > 0
            }
        ))

        # 5. PAM Password Quality Configuration (/etc/security/pwquality.conf)
        pwquality_content, _ = read_system_file("/etc/security/pwquality.conf")
        pwquality_data: Dict[str, str] = {}
        if pwquality_content:
            pwquality_data = parse_key_value_file(pwquality_content, delimiter="=")
        
        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="pam_pwquality_config",
            raw_output=pwquality_content or "pwquality.conf not present",
            parsed_data=pwquality_data
        ))

        return records
