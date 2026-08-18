"""Auditd, Syslog, and Journald Logging Collector."""

import glob
import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import read_system_file, execute_command, get_file_stat


class LoggingAuditCollector(BaseCollector):
    """Audits auditd daemon, kernel audit rules, syscall monitors, and syslog/journald persistence."""

    name = "logging_audit"
    description = "Audits auditd daemon, kernel audit rules, syscall monitors, and syslog/journald"

    # Critical files that should have auditd file watches
    CRITICAL_AUDIT_FILES = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/pam.d",
        "/var/log/lastlog"
    ]

    # Critical system calls that should have active audit rules
    CRITICAL_SYSCALLS = [
        "chmod", "fchmod", "fchmodat",
        "chown", "fchown", "lchown", "fchownat",
        "setxattr", "lsetxattr", "fsetxattr", "removexattr",
        "unlink", "unlinkat", "rename", "renameat",
        "execve", "mount"
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Auditd Service Status
        audit_svc_out, _, _ = execute_command(["systemctl", "is-active", "auditd"])
        auditd_active = audit_svc_out.strip() == "active"

        # 2. Active Audit Rules (via `auditctl -l`)
        rules_out, _, rules_code = execute_command(["auditctl", "-l"])
        active_rules = [r.strip() for r in rules_out.splitlines() if r.strip() and not r.startswith("No rules")]

        # Check coverage of critical files
        covered_files = []
        for target in self.CRITICAL_AUDIT_FILES:
            if any(target in r for r in active_rules):
                covered_files.append(target)

        # Check coverage of critical syscalls
        covered_syscalls = []
        for sc in self.CRITICAL_SYSCALLS:
            if any(f"-S {sc}" in r or f",{sc}" in r or f"{sc}," in r for r in active_rules):
                covered_syscalls.append(sc)

        # 3. Rule files in /etc/audit/rules.d/
        rule_files = glob.glob("/etc/audit/rules.d/*.rules")
        raw_rule_files = []
        for rf in rule_files:
            content, _ = read_system_file(rf)
            if content:
                raw_rule_files.append(f"--- {rf} ---\n{content}")

        # 4. Auditd Configuration File (/etc/audit/auditd.conf)
        auditd_conf, _ = read_system_file("/etc/audit/auditd.conf")
        max_log_file_action = "unset"
        space_left_action = "unset"
        if auditd_conf:
            for line in auditd_conf.splitlines():
                if "max_log_file_action" in line and "=" in line:
                    max_log_file_action = line.split("=", 1)[1].strip().lower()
                if "space_left_action" in line and "=" in line:
                    space_left_action = line.split("=", 1)[1].strip().lower()

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="auditd_rules_and_status",
            command_executed="auditctl -l",
            raw_output=f"Auditd Active: {auditd_active}\nRules:\n{rules_out}\n\nRule Files:\n" + "\n".join(raw_rule_files),
            parsed_data={
                "auditd_service_active": auditd_active,
                "total_active_rules": len(active_rules),
                "covered_critical_files": covered_files,
                "all_critical_files_covered": len(covered_files) >= 5,
                "covered_syscalls": covered_syscalls,
                "has_syscall_auditing": len(covered_syscalls) > 0,
                "max_log_file_action": max_log_file_action,
                "space_left_action": space_left_action,
                "rule_file_count": len(rule_files)
            }
        ))

        # 5. Journald and Rsyslog Persistence
        journal_conf, _ = read_system_file("/etc/systemd/journald.conf")
        journal_persistent = bool(journal_conf and "Storage=persistent" in journal_conf)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="system_logging_persistence",
            raw_output=journal_conf or "journald.conf not available",
            parsed_data={"journald_storage_persistent": journal_persistent}
        ))

        # 6. /var/log Permissions Audit
        var_log_stat = get_file_stat("/var/log")
        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="var_log_permissions",
            raw_output=f"Stat /var/log: {var_log_stat}",
            parsed_data={"var_log_stat": var_log_stat}
        ))

        return records
