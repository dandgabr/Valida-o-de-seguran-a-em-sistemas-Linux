"""PCI DSS v4.0 (Payment Card Industry Data Security Standard) Framework Module."""

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
from sec_audit_linux.core.scoring import calculate_pci_dss_score, summarize_evaluations
from sec_audit_linux.core.validators import (
    BaseValidator,
    SysctlValidator,
    FilePermissionValidator,
    SSHSettingValidator,
    ServiceStatusValidator,
    SudoersValidator,
    GenericEvidenceValidator
)


class PCIDSSFramework(BaseFramework):
    """Payment Card Industry Data Security Standard (PCI DSS) v4.0 for Linux Hosts."""

    framework_id = "pci_dss"
    name = "PCI DSS v4.0"
    version = "v4.0"
    description = "PCI DSS v4.0 Requirements for Cardholder Data Environment (CDE) Linux Systems"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # Req 2.2: System components configured and managed securely
        validators.append(SysctlValidator(
            control_id="PCI-2.2.1",
            framework_name=self.name,
            title="System components are configured and managed securely (Hardening Baseline)",
            description="System components are hardened in accordance with configuration standards.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.5,
            tags=["Requirement 2", "Secure Configuration"]
        ))

        # Req 7.2: Access appropriately restricted
        validators.append(SudoersValidator(
            control_id="PCI-7.2.1",
            framework_name=self.name,
            title="Access to system components is appropriately restricted (Sudo Controls)",
            description="Privileged access is strictly managed and requires re-authentication (no NOPASSWD).",
            check_type="no_nopasswd",
            severity=Severity.HIGH,
            weight=1.5,
            tags=["Requirement 7", "Access Restriction"]
        ))

        # Req 8.2: User identification
        validators.append(GenericEvidenceValidator(
            control_id="PCI-8.2.1",
            framework_name=self.name,
            title="User identification is uniquely assigned (Single UID 0 Account)",
            description="All users are assigned a unique ID before being allowed to access system components.",
            target_item="user_accounts_uid0",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' has UID 0",
                f"UID 0 ok: {ev.parsed_data.get('only_root_uid_zero') if ev else False}"
            ),
            remediation_cmd="Remove secondary UID 0 accounts from /etc/passwd",
            tags=["Requirement 8", "Identification"]
        ))

        # Req 8.3: Strong authentication & no blank passwords
        validators.append(GenericEvidenceValidator(
            control_id="PCI-8.3.1",
            framework_name=self.name,
            title="Strong authentication mechanisms (No Empty Passwords)",
            description="Ensure blank passwords are systematically forbidden across all accounts.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "No blank passwords in /etc/shadow",
                f"Blank passwords absent: {not ev.parsed_data.get('has_empty_passwords') if ev else False}"
            ),
            remediation_cmd="Lock any empty account with passwd -l",
            tags=["Requirement 8", "Authentication"]
        ))

        # Req 10.2: Audit logging active
        validators.append(GenericEvidenceValidator(
            control_id="PCI-10.2.1",
            framework_name=self.name,
            title="Audit logs are generated and recorded (Active auditd Daemon)",
            description="Audit logs are generated for all system components to enable tracking of security events.",
            target_item="auditd_rules_and_status",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd daemon active and collecting events",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["Requirement 10", "Audit Logging"]
        ))

        # Req 11.5: Change-detection mechanism (FIM)
        validators.append(GenericEvidenceValidator(
            control_id="PCI-11.5.1",
            framework_name=self.name,
            title="A change-detection mechanism is deployed (File Integrity Monitoring)",
            description="Deploy a change-detection mechanism (FIM) to alert personnel to unauthorized modification of critical files.",
            target_item="aide_fim_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed")
                else ControlStatus.NON_COMPLIANT,
                "AIDE or FIM daemon installed and active",
                f"AIDE installed: {ev.parsed_data.get('aide_installed') if ev else False}"
            ),
            remediation_cmd="apt install aide || dnf install aide",
            tags=["Requirement 11", "File Integrity Monitoring"]
        ))

        return validators

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        store = EvidenceStore()
        store.add_records(evidences)

        evaluations: List[ControlEvaluation] = []
        for validator in self._validators:
            evaluation = validator.evaluate(store, context)
            evaluations.append(evaluation)

        summary = summarize_evaluations(evaluations)
        score = calculate_pci_dss_score(evaluations)

        return FrameworkResult(
            framework_id=self.framework_id,
            framework_name=self.name,
            version=self.version,
            adherence_percentage=score,
            total_controls=summary["total_controls"],
            compliant_count=summary["compliant_count"],
            non_compliant_count=summary["non_compliant_count"],
            partial_count=summary["partial_count"],
            manual_count=summary["manual_count"],
            not_applicable_count=summary["not_applicable_count"],
            error_count=summary["error_count"],
            evaluations=evaluations,
            summary_by_severity=summary["summary_by_severity"]
        )
