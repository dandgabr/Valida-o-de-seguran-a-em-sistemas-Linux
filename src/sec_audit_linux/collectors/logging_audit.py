"""Auditd, Syslog, and Journald Logging Collector."""

import glob
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import read_system_file, execute_command, get_file_stat


class LoggingAuditCollector(BaseCollector):
    """Audits auditd service, active kernel audit rules, and syslog/journald persistence."""

    name = "logging_audit"
    description = "Audits auditd daemon, kernel audit rules, syscall monitors, and syslog/journald"

    # Critical files and syscalls that should have active auditd rules
    CRITICAL_AUDIT_TARGETS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config"
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Auditd Service Status
        audit_svc_out, _, _ = execute_command(["systemctl", "is-active", "auditd"])
        auditd_active = audit_svc_out.strip() == "active"

        # 2. Active Audit Rules (via `auditctl -l`)
        rules_out, _, rules_code = execute_command(["auditctl", "-l"])
        active_rules = [r.strip() for r in rules_out.splitlines() if r.strip() and not r.startswith("No rules")]

        # Check coverage of critical targets
        covered_targets = []
        for target in self.CRITICAL_AUDIT_TARGETS:
            if any(target in r for r in active_rules):
                covered_targets.append(target)

        # 3. Rule files in /etc/audit/rules.d/
        rule_files = glob.glob("/etc/audit/rules.d/*.rules")
        raw_rule_files = []
        for rf in rule_files:
            content, _ = read_system_file(rf)
            if content:
                raw_rule_files.append(f"--- {rf} ---\n{content}")

        # 4. Auditd Configuration File (/etc/audit/auditd.conf)
        auditd_conf, _ = read_system_file("/etc/audit/auditd.conf")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="auditd_rules_and_status",
            command_executed="auditctl -l",
            raw_output=f"Auditd Service Active: {auditd_active}\n\nRules:\n{rules_out}\n\nRule Files:\n" + "\n".join(raw_rule_files),
            parsed_data={
                "auditd_service_active": auditd_active,
                "total_active_rules": len(active_rules),
                "covered_critical_targets": covered_targets,
                "all_critical_targets_covered": len(covered_targets) == len(self.CRITICAL_AUDIT_TARGETS),
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

        return records
