"""MITRE ATT&CK Framework (Enterprise Linux Matrix) Module."""

from typing import List
from sec_audit_linux.frameworks.base_framework import BaseFramework
from sec_audit_linux.core.models import (
    FrameworkResult,
    ControlEvaluation,
    ControlStatus,
    EvidenceRecord,
    SystemContext,
    Severity
)


class MITREAttackFramework(BaseFramework):
    """MITRE ATT&CK Enterprise Matrix for Linux Techniques and Mitigations."""

    framework_id = "mitre_attack"
    name = "MITRE ATT&CK (Linux)"
    version = "v15.0"
    description = "Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) Matrix for Linux"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        perms_ev = self._find_evidence(evidences, "critical_file_permissions")
        id_ev = self._find_evidence(evidences, "user_accounts_uid0")
        shadow_ev = self._find_evidence(evidences, "shadow_passwords_audit")
        sudo_ev = self._find_evidence(evidences, "sudoers_privilege_audit")
        selinux_ev = self._find_evidence(evidences, "selinux_status")
        apparmor_ev = self._find_evidence(evidences, "apparmor_status")
        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        fw_ev = self._find_evidence(evidences, "firewall_status")

        # T1078: Valid Accounts (Initial Access, Persistence, Privilege Escalation)
        root_0_ok = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        t1078_ok = root_0_ok and no_empty_pw

        evaluations.append(ControlEvaluation(
            control_id="T1078",
            framework_name=self.name,
            title="Valid Accounts Hardening (T1078)",
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            status=ControlStatus.COMPLIANT if t1078_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="No blank passwords and single UID 0 account",
            actual_condition=f"UID0 ok: {root_0_ok}, No blank PW: {no_empty_pw}",
            evidence_refs=[id_ev.evidence_id, shadow_ev.evidence_id] if id_ev and shadow_ev else [],
            remediation_cmd="Lock unauthenticated accounts and enforce strict UID 0 governance",
            rationale="Compromised valid accounts provide seamless persistence and lateral movement.",
            tags=["Initial Access", "Privilege Escalation", "T1078"]
        ))

        # T1548.003: Sudo and Sudoers (Privilege Escalation, Defense Evasion)
        has_nopasswd = sudo_ev.parsed_data.get("has_nopasswd", True) if sudo_ev else False
        evaluations.append(ControlEvaluation(
            control_id="T1548.003",
            framework_name=self.name,
            title="Abuse Elevation Control Mechanism: Sudo and Sudoers (T1548.003)",
            description="Adversaries may abuse sudoers configurations with NOPASSWD or wildcards to execute commands as root.",
            status=ControlStatus.COMPLIANT if not has_nopasswd else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="No unrestricted NOPASSWD in sudoers",
            actual_condition=f"NOPASSWD present: {has_nopasswd}",
            evidence_refs=[sudo_ev.evidence_id] if sudo_ev else [],
            remediation_cmd="Remove NOPASSWD flags from /etc/sudoers",
            rationale="Unrestricted sudo allows instant privilege escalation to root without password challenge.",
            tags=["Privilege Escalation", "T1548.003"]
        ))

        # T1562.001: Impair Defenses: Disable or Modify Tools (Defense Evasion)
        selinux_active = selinux_ev.parsed_data.get("is_enforcing", False) if selinux_ev else False
        apparmor_active = (apparmor_ev.parsed_data.get("status") == "active") if apparmor_ev else False
        auditd_active = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        fw_active = fw_ev.parsed_data.get("any_firewall_active", False) if fw_ev else False

        defenses_ok = (selinux_active or apparmor_active) and auditd_active and fw_active
        evaluations.append(ControlEvaluation(
            control_id="T1562.001",
            framework_name=self.name,
            title="Impair Defenses: Security Services Active (T1562.001)",
            description="Adversaries may disable security tools like SELinux, auditd, and firewall to avoid detection.",
            status=ControlStatus.COMPLIANT if defenses_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="SELinux/AppArmor enforcing, auditd active, firewall active",
            actual_condition=f"MAC active: {selinux_active or apparmor_active}, auditd: {auditd_active}, firewall: {fw_active}",
            evidence_refs=[selinux_ev.evidence_id, audit_ev.evidence_id, fw_ev.evidence_id] if selinux_ev and audit_ev and fw_ev else [],
            remediation_cmd="Enable SELinux enforcing, start auditd, and activate firewall",
            rationale="Disabled defensive mechanisms leave the system unmonitored and vulnerable to exploit execution.",
            tags=["Defense Evasion", "T1562.001"]
        ))

        # T1003.008: OS Credential Dumping: /etc/passwd and /etc/shadow (Credential Access)
        perms_ok = perms_ev.parsed_data.get("all_compliant", False) if perms_ev else False
        evaluations.append(ControlEvaluation(
            control_id="T1003.008",
            framework_name=self.name,
            title="OS Credential Dumping: /etc/passwd and /etc/shadow Permissions (T1003.008)",
            description="Adversaries may attempt to dump credentials by reading /etc/shadow or corrupting /etc/passwd.",
            status=ControlStatus.COMPLIANT if perms_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Strict mode 0000/0600 on /etc/shadow and 0644 on /etc/passwd",
            actual_condition=f"File permissions compliant: {perms_ok}",
            evidence_refs=[perms_ev.evidence_id] if perms_ev else [],
            remediation_cmd="chmod 000 /etc/shadow && chmod 644 /etc/passwd",
            rationale="Leaked shadow hashes allow offline cracking via Hashcat or John the Ripper.",
            tags=["Credential Access", "T1003.008"]
        ))

        # T1021.004: Remote Services: SSH (Lateral Movement)
        root_ssh = ssh_ev.parsed_data.get("permit_root_login", "unset").lower() if ssh_ev else "unset"
        ssh_root_ok = root_ssh in ["no", "prohibit-password"]
        evaluations.append(ControlEvaluation(
            control_id="T1021.004",
            framework_name=self.name,
            title="Remote Services: SSH Lateral Movement & Direct Root Login (T1021.004)",
            description="Adversaries may use SSH with compromised credentials to pivot across systems.",
            status=ControlStatus.COMPLIANT if ssh_root_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="PermitRootLogin prohibit-password or no",
            actual_condition=f"PermitRootLogin = {root_ssh}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/01-hardening.conf",
            rationale="Disabling password root SSH limits brute-force attacks and lateral movement.",
            tags=["Lateral Movement", "T1021.004"]
        ))

        return self._create_result(evaluations)
