"""ISO/IEC 27001:2022 Annex A Controls Framework Module."""

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


class ISO27001Framework(BaseFramework):
    """ISO/IEC 27001:2022 Annex A Information Security Controls (Linux Host Scope)."""

    framework_id = "iso_27001"
    name = "ISO/IEC 27001:2022"
    version = "2022"
    description = "Information security, cybersecurity and privacy protection — Information security management systems"

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
        crypto_ev = self._find_evidence(evidences, "system_crypto_policy")

        # A.8.2: Privileged Access Rights
        root_0_ok = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.2",
            framework_name=self.name,
            title="Privileged Access Rights (UID 0 & Administrative Control)",
            description="The allocation and use of privileged access rights shall be restricted and managed.",
            status=ControlStatus.COMPLIANT if root_0_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Only 'root' user possesses UID 0",
            actual_condition=f"UID 0 ok: {root_0_ok}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Ensure only root has UID 0 in /etc/passwd",
            tags=["Annex A.8", "Access Control"]
        ))

        # A.8.5: Secure Authentication
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.5",
            framework_name=self.name,
            title="Secure Authentication (No Empty Passwords)",
            description="Secure authentication technologies and procedures shall be implemented.",
            status=ControlStatus.COMPLIANT if no_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="No blank passwords allowed in /etc/shadow",
            actual_condition=f"Blank passwords absent: {no_empty_pw}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="passwd -l <user>",
            tags=["Annex A.8", "Authentication"]
        ))

        # A.8.7: Protection Against Malware / File Integrity
        aide_ok = aide_ev.parsed_data.get("aide_installed", False) if aide_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.7",
            framework_name=self.name,
            title="Protection Against Malware (Integrity Verification)",
            description="Protection against malware shall be implemented and supported by integrity checking.",
            status=ControlStatus.COMPLIANT if aide_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="AIDE or FIM solution active",
            actual_condition=f"AIDE installed: {aide_ok}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="apt install aide || dnf install aide",
            tags=["Annex A.8", "Malware Defense"]
        ))

        # A.8.9: Configuration Management
        perms_ok = perms_ev.parsed_data.get("all_compliant", False) if perms_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.9",
            framework_name=self.name,
            title="Configuration Management (File Permissions & Hardening)",
            description="Configurations, including security configurations, shall be established and monitored.",
            status=ControlStatus.COMPLIANT if perms_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="Permissions compliant on system configuration files",
            actual_condition=f"Compliant: {perms_ok}",
            evidence_refs=[perms_ev.evidence_id] if perms_ev else [],
            remediation_cmd="chmod 644 /etc/passwd /etc/group && chmod 000 /etc/shadow",
            tags=["Annex A.8", "Configuration"]
        ))

        # A.8.15: Logging (auditd & system logging)
        auditd_ok = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.15",
            framework_name=self.name,
            title="Logging (System Event & Audit Logs)",
            description="Logs that record activities, exceptions, and security events shall be produced and retained.",
            status=ControlStatus.COMPLIANT if auditd_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="auditd daemon active and logging",
            actual_condition=f"auditd active: {auditd_ok}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            tags=["Annex A.8", "Logging"]
        ))

        # A.8.20: Network Security (Firewall Filtering)
        fw_ok = fw_ev.parsed_data.get("any_firewall_active", False) if fw_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.20",
            framework_name=self.name,
            title="Network Security (Host-Based Firewall)",
            description="Networks and network services shall be secured, managed, and controlled.",
            status=ControlStatus.COMPLIANT if fw_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="Host-based firewall enabled",
            actual_condition=f"Firewall active: {fw_ok}",
            evidence_refs=[fw_ev.evidence_id] if fw_ev else [],
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["Annex A.8", "Network"]
        ))

        # A.8.24: Use of Cryptography (System & SSH Crypto Policies)
        crypto_ok = not (ssh_ev.parsed_data.get("has_weak_ciphers", True)) if ssh_ev else False
        evaluations.append(ControlEvaluation(
            control_id="ISO-A.8.24",
            framework_name=self.name,
            title="Use of Cryptography (Approved Algorithms and Ciphers)",
            description="Rules for the effective use of cryptography, including crypto algorithms, shall be defined.",
            status=ControlStatus.COMPLIANT if crypto_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="Modern cryptographic suites enforced",
            actual_condition=f"Modern ciphers enforced: {crypto_ok}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="Update /etc/ssh/sshd_config with modern ciphers",
            tags=["Annex A.8", "Cryptography"]
        ))

        return self._create_result(evaluations)
