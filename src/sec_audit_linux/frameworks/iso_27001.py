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
from sec_audit_linux.core.evidence_manager import EvidenceStore
from sec_audit_linux.core.validators import (
    BaseValidator,
    SysctlValidator,
    FilePermissionValidator,
    SSHSettingValidator,
    ServiceStatusValidator,
    SudoersValidator,
    GenericEvidenceValidator
)


class ISO27001Framework(BaseFramework):
    """ISO/IEC 27001:2022 Annex A Information Security Controls (Linux Host Scope)."""

    framework_id = "iso_27001"
    name = "ISO/IEC 27001:2022"
    version = "2022"
    description = "Information security, cybersecurity and privacy protection — Information security management systems"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # A.8.2: Privileged Access Rights
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.2",
            framework_name=self.name,
            title="Privileged Access Rights (UID 0 & Administrative Control)",
            description="The allocation and use of privileged access rights shall be restricted and managed.",
            target_item="user_accounts_uid0",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' user possesses UID 0",
                f"UID 0 ok: {ev.parsed_data.get('only_root_uid_zero') if ev else False}"
            ),
            remediation_cmd="Ensure only root has UID 0 in /etc/passwd",
            tags=["Annex A.8", "Access Control"]
        ))

        # A.8.5: Secure Authentication
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.5",
            framework_name=self.name,
            title="Secure Authentication (No Empty Passwords)",
            description="Secure authentication technologies and procedures shall be implemented.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "No blank passwords allowed in /etc/shadow",
                f"Blank passwords absent: {not ev.parsed_data.get('has_empty_passwords') if ev else False}"
            ),
            remediation_cmd="passwd -l <user>",
            tags=["Annex A.8", "Authentication"]
        ))

        # A.8.7: Protection Against Malware / File Integrity
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.7",
            framework_name=self.name,
            title="Protection Against Malware (Integrity Verification)",
            description="Protection against malware shall be implemented and supported by integrity checking.",
            target_item="aide_fim_status",
            severity=Severity.MEDIUM,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed")
                else ControlStatus.NON_COMPLIANT,
                "AIDE or FIM solution active",
                f"AIDE installed: {ev.parsed_data.get('aide_installed') if ev else False}"
            ),
            remediation_cmd="apt install aide || dnf install aide",
            tags=["Annex A.8", "Malware Defense"]
        ))

        # A.8.9: Configuration Management
        validators.append(FilePermissionValidator(
            control_id="ISO-A.8.9",
            framework_name=self.name,
            title="Configuration Management (File Permissions & Hardening)",
            description="Configurations, including security configurations, shall be established and monitored.",
            file_path="/etc/passwd",
            expected_modes=["0644"],
            expected_uid=0,
            severity=Severity.HIGH,
            weight=1.2,
            tags=["Annex A.8", "Configuration"]
        ))

        # A.8.15: Logging (auditd & system logging)
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.15",
            framework_name=self.name,
            title="Logging (System Event & Audit Logs)",
            description="Logs that record activities, exceptions, and security events shall be produced and retained.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd daemon active and logging",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["Annex A.8", "Logging"]
        ))

        # A.8.20: Network Security (Firewall Filtering)
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.20",
            framework_name=self.name,
            title="Network Security (Host-Based Firewall)",
            description="Networks and network services shall be secured, managed, and controlled.",
            target_item="firewall_status",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("any_firewall_active")
                else ControlStatus.NON_COMPLIANT,
                "Host-based firewall enabled",
                f"Firewall active: {ev.parsed_data.get('any_firewall_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["Annex A.8", "Network"]
        ))

        # A.8.24: Use of Cryptography
        validators.append(GenericEvidenceValidator(
            control_id="ISO-A.8.24",
            framework_name=self.name,
            title="Use of Cryptography (Approved Algorithms and Ciphers)",
            description="Rules for the effective use of cryptography, including crypto algorithms, shall be defined.",
            target_item="ssh_server_configuration",
            severity=Severity.HIGH,
            weight=1.2,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_weak_ciphers", True)
                else ControlStatus.NON_COMPLIANT,
                "Modern cryptographic suites enforced",
                f"Weak ciphers absent: {not ev.parsed_data.get('has_weak_ciphers') if ev else False}"
            ),
            remediation_cmd="Update /etc/ssh/sshd_config with modern ciphers",
            tags=["Annex A.8", "Cryptography"]
        ))

        return validators

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        store = EvidenceStore()
        store.add_records(evidences)

        evaluations: List[ControlEvaluation] = []
        for validator in self._validators:
            evaluation = validator.evaluate(store, context)
            evaluations.append(evaluation)

        return self._create_result(evaluations)
