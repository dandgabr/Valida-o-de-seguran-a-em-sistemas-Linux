"""CIS Critical Security Controls v8 Framework Module."""

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


class CISControlsFramework(BaseFramework):
    """CIS Critical Security Controls v8 (Implementation Groups IG1, IG2, IG3)."""

    framework_id = "cis_controls"
    name = "CIS Critical Security Controls"
    version = "v8.0"
    description = "Prioritized set of actions that protect organizations and data from cyber attack vectors"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        perms_ev = self._find_evidence(evidences, "critical_file_permissions")
        id_ev = self._find_evidence(evidences, "user_accounts_uid0")
        shadow_ev = self._find_evidence(evidences, "shadow_passwords_audit")
        sudo_ev = self._find_evidence(evidences, "sudoers_privilege_audit")
        fw_ev = self._find_evidence(evidences, "firewall_status")
        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        aide_ev = self._find_evidence(evidences, "aide_fim_status")
        sysctl_ev = self._find_evidence(evidences, "kernel_sysctl_runtime")

        # CIS Safeguard 3.3: Configure Data Access Control Lists (IG1)
        perms_ok = perms_ev.parsed_data.get("all_compliant", False) if perms_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-3.3",
            framework_name=self.name,
            title="Configure Data Access Control Lists (IG1)",
            description="Configure data access control lists for sensitive system and credential files.",
            status=ControlStatus.COMPLIANT if perms_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="Strict POSIX permissions on /etc/passwd, /etc/shadow, /etc/sudoers",
            actual_condition=f"Compliant: {perms_ok}",
            evidence_refs=[perms_ev.evidence_id] if perms_ev else [],
            remediation_cmd="chmod 644 /etc/passwd && chmod 000 /etc/shadow",
            tags=["IG1", "Data Protection"]
        ))

        # CIS Safeguard 4.1: Establish and Maintain a Secure Configuration Process (IG1)
        aslr_ok = (sysctl_ev.parsed_data.get("kernel.randomize_va_space") == "2") if sysctl_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-4.1",
            framework_name=self.name,
            title="Establish and Maintain a Secure Configuration Process (IG1)",
            description="Maintain hardened OS baselines including kernel protections and ASLR.",
            status=ControlStatus.COMPLIANT if aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="Hardened kernel and ASLR enabled",
            actual_condition=f"ASLR enabled: {aslr_ok}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w kernel.randomize_va_space=2",
            tags=["IG1", "Secure Configuration"]
        ))

        # CIS Safeguard 5.2: Use Unique Passwords and Restrict Default Accounts (IG1)
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-5.2",
            framework_name=self.name,
            title="Use Unique Passwords and Restrict Default Accounts (IG1)",
            description="Ensure no accounts exist with blank passwords and default accounts are managed.",
            status=ControlStatus.COMPLIANT if no_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="No blank passwords in /etc/shadow",
            actual_condition=f"Blank passwords absent: {no_empty_pw}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="Lock any empty accounts using passwd -l",
            tags=["IG1", "Account Management"]
        ))

        # CIS Safeguard 5.4: Restrict Administrator Privileges to Dedicated Accounts (IG1)
        only_root_0 = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-5.4",
            framework_name=self.name,
            title="Restrict Administrator Privileges to Dedicated Accounts (IG1)",
            description="Ensure only the primary root account possesses UID 0.",
            status=ControlStatus.COMPLIANT if only_root_0 else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="Only 'root' has UID 0",
            actual_condition=f"UID 0 accounts: {id_ev.parsed_data.get('uid_zero_accounts') if id_ev else 'unknown'}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Remove secondary UID 0 users from /etc/passwd",
            tags=["IG1", "Access Control"]
        ))

        # CIS Safeguard 6.1: Establish an Access Granting Process / Sudo Least Privilege (IG2)
        nopasswd_absent = not (sudo_ev.parsed_data.get("has_nopasswd", True)) if sudo_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-6.1",
            framework_name=self.name,
            title="Establish Access Granting Process and Sudo Least Privilege (IG2)",
            description="Ensure administrative privilege escalation requires re-authentication.",
            status=ControlStatus.COMPLIANT if nopasswd_absent else ControlStatus.PARTIAL,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="Sudo operations require password authentication",
            actual_condition=f"NOPASSWD absent: {nopasswd_absent}",
            evidence_refs=[sudo_ev.evidence_id] if sudo_ev else [],
            remediation_cmd="Enforce password requirement in sudoers rules",
            tags=["IG2", "Access Management"]
        ))

        # CIS Safeguard 8.2: Collect Audit Logs (IG1)
        auditd_active = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-8.2",
            framework_name=self.name,
            title="Collect Audit Logs (IG1)",
            description="Ensure the audit logging daemon is active and collecting system event logs.",
            status=ControlStatus.COMPLIANT if auditd_active else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="auditd service active",
            actual_condition=f"auditd active: {auditd_active}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            tags=["IG1", "Audit Log Management"]
        ))

        # CIS Safeguard 10.1: Deploy and Maintain Host-Based Firewalls (IG1)
        fw_active = fw_ev.parsed_data.get("any_firewall_active", False) if fw_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-10.1",
            framework_name=self.name,
            title="Deploy and Maintain Host-Based Firewalls (IG1)",
            description="Ensure host firewall is active to filter network traffic.",
            status=ControlStatus.COMPLIANT if fw_active else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="Host firewall active",
            actual_condition=f"Firewall active: {fw_active}",
            evidence_refs=[fw_ev.evidence_id] if fw_ev else [],
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["IG1", "Network Defense"]
        ))

        # CIS Safeguard 10.3: Disable Insecure Services (IG2)
        ssh_crypto_ok = not (ssh_ev.parsed_data.get("has_weak_ciphers", True)) if ssh_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-10.3",
            framework_name=self.name,
            title="Disable Insecure Services and Legacy Crypto Protocols (IG2)",
            description="Ensure legacy cryptographic suites on remote management services (SSH) are disabled.",
            status=ControlStatus.COMPLIANT if ssh_crypto_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="No weak ciphers in sshd",
            actual_condition=f"Modern ciphers enforced: {ssh_crypto_ok}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="Update SSH crypto suites in sshd_config",
            tags=["IG2", "Network Defense"]
        ))

        # CIS Safeguard 10.5: Enable Anti-Malware / FIM Software (IG2)
        fim_active = aide_ev.parsed_data.get("aide_installed", False) if aide_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CIS-CSC-10.5",
            framework_name=self.name,
            title="Deploy File Integrity Monitoring / Binary Verification (IG2)",
            description="Deploy software to monitor system files for unauthorized changes.",
            status=ControlStatus.COMPLIANT if fim_active else ControlStatus.NON_COMPLIANT,
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="AIDE or FIM solution installed",
            actual_condition=f"AIDE installed: {fim_active}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="apt install aide || dnf install aide",
            tags=["IG2", "Malware Defense"]
        ))

        return self._create_result(evaluations)
