"""NIST Special Publication 800-53 Revision 5 Security Controls Framework Module."""

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


class NIST80053Framework(BaseFramework):
    """NIST SP 800-53 Rev 5 technical security controls for Linux host environments."""

    framework_id = "nist_800_53"
    name = "NIST SP 800-53 Rev 5"
    version = "Rev 5"
    description = "Security and Privacy Controls for Information Systems and Organizations"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # AC-2: Account Management
        validators.append(GenericEvidenceValidator(
            control_id="NIST-AC-2",
            framework_name=self.name,
            title="Account Management (UID 0 & Account Governance)",
            description="Manage system accounts and ensure only the root user possesses UID 0.",
            target_item="user_accounts_uid0",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' has UID 0",
                f"UID 0 Accounts: {ev.parsed_data.get('uid_zero_accounts') if ev else 'N/A'}"
            ),
            remediation_cmd="Remove secondary UID 0 entries from /etc/passwd",
            tags=["AC", "Access Control"]
        ))

        # AC-3: Access Enforcement (MAC)
        validators.append(GenericEvidenceValidator(
            control_id="NIST-AC-3",
            framework_name=self.name,
            title="Access Enforcement (Mandatory Access Control)",
            description="Enforce approved authorizations for logical access to information and system resources.",
            target_item="selinux_status",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("is_enforcing")
                else (ControlStatus.COMPLIANT if ctx.os_family.value == "debian" else ControlStatus.NON_COMPLIANT),
                "SELinux enforcing or AppArmor active",
                f"SELinux: {ev.parsed_data.get('mode') if ev else 'N/A'}"
            ),
            remediation_cmd="setenforce 1",
            tags=["AC", "Access Control"]
        ))

        # AC-6: Least Privilege (Sudo restrictions & NOPASSWD)
        validators.append(SudoersValidator(
            control_id="NIST-AC-6",
            framework_name=self.name,
            title="Least Privilege (Sudo Access & Authorization)",
            description="Employ the principle of least privilege, allowing only authorized accesses for users.",
            check_type="no_nopasswd",
            severity=Severity.HIGH,
            weight=1.5,
            tags=["AC", "Access Control"]
        ))

        # AU-2 / AU-12: Event Logging & Audit Generation
        validators.append(GenericEvidenceValidator(
            control_id="NIST-AU-2",
            framework_name=self.name,
            title="Event Logging and Audit Record Generation",
            description="Identify, collect, and retain audit records for security-relevant system events.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd service active and generating records",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["AU", "Audit and Accountability"]
        ))

        # CM-6: Configuration Settings (Hardening & Sysctl)
        validators.append(SysctlValidator(
            control_id="NIST-CM-6",
            framework_name=self.name,
            title="Configuration Settings (System Hardening Baseline)",
            description="Establish and document mandatory configuration settings for IT products.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.2,
            tags=["CM", "Configuration Management"]
        ))

        # IA-5: Authenticator Management
        validators.append(GenericEvidenceValidator(
            control_id="NIST-IA-5",
            framework_name=self.name,
            title="Authenticator Management (Password Policies & No Blank Passwords)",
            description="Manage information system authenticators by enforcing non-empty hashes and policy parameters.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "All active accounts have non-empty password hashes",
                f"Empty password users: {ev.parsed_data.get('empty_password_users') if ev else 'N/A'}"
            ),
            remediation_cmd="passwd -l <user>",
            tags=["IA", "Identification and Authentication"]
        ))

        # SC-7: Boundary Protection (Host Firewall)
        validators.append(GenericEvidenceValidator(
            control_id="NIST-SC-7",
            framework_name=self.name,
            title="Boundary Protection (Host-Based Packet Filtering)",
            description="Monitor and control communications at external and internal system boundaries.",
            target_item="firewall_status",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("any_firewall_active")
                else ControlStatus.NON_COMPLIANT,
                "Host-based firewall enabled and filtering",
                f"Firewall active: {ev.parsed_data.get('any_firewall_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["SC", "System and Communications Protection"]
        ))

        # SC-13: Cryptographic Protection
        validators.append(GenericEvidenceValidator(
            control_id="NIST-SC-13",
            framework_name=self.name,
            title="Cryptographic Protection (Approved Cryptographic Algorithms)",
            description="Implement approved cryptographic algorithms, ciphers, and key exchange mechanisms.",
            target_item="ssh_server_configuration",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_weak_ciphers", True)
                else ControlStatus.NON_COMPLIANT,
                "Approved crypto policy and modern SSH ciphers",
                f"Weak ciphers absent: {not ev.parsed_data.get('has_weak_ciphers') if ev else False}"
            ),
            remediation_cmd="update-crypto-policies --set DEFAULT",
            tags=["SC", "System and Communications Protection"]
        ))

        # SI-7: Software, Firmware, and Information Integrity (FIM)
        validators.append(GenericEvidenceValidator(
            control_id="NIST-SI-7",
            framework_name=self.name,
            title="Software, Firmware, and Information Integrity (FIM)",
            description="Employ integrity verification tools to detect unauthorized changes to system software.",
            target_item="aide_fim_status",
            severity=Severity.HIGH,
            weight=1.2,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed")
                else ControlStatus.NON_COMPLIANT,
                "AIDE or FIM daemon installed",
                f"AIDE installed: {ev.parsed_data.get('aide_installed') if ev else False}"
            ),
            remediation_cmd="dnf install aide || apt install aide",
            tags=["SI", "System and Information Integrity"]
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
