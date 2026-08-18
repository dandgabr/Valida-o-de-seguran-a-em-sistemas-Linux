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


class CISControlsFramework(BaseFramework):
    """CIS Critical Security Controls v8 (Implementation Groups IG1, IG2, IG3)."""

    framework_id = "cis_controls"
    name = "CIS Critical Security Controls"
    version = "v8.0"
    description = "Prioritized set of actions that protect organizations and data from cyber attack vectors"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # CIS Safeguard 3.3: Configure Data Access Control Lists (IG1)
        validators.append(FilePermissionValidator(
            control_id="CIS-CSC-3.3",
            framework_name=self.name,
            title="Configure Data Access Control Lists (IG1)",
            description="Configure data access control lists on sensitive system files (/etc/passwd, /etc/shadow).",
            file_path="/etc/passwd",
            expected_modes=["0644"],
            expected_uid=0,
            severity=Severity.HIGH,
            weight=1.0,
            tags=["IG1", "Data Protection"]
        ))

        # CIS Safeguard 4.1: Establish and Maintain a Secure Configuration Process (IG1)
        validators.append(SysctlValidator(
            control_id="CIS-CSC-4.1",
            framework_name=self.name,
            title="Establish and Maintain a Secure Configuration Process (IG1)",
            description="Maintain hardened OS baselines including ASLR.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.0,
            tags=["IG1", "Secure Configuration"]
        ))

        # CIS Safeguard 5.2: Use Unique Passwords and Restrict Default Accounts (IG1)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-5.2",
            framework_name=self.name,
            title="Use Unique Passwords and Restrict Default Accounts (IG1)",
            description="Ensure no accounts exist with blank passwords in /etc/shadow.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "No blank passwords in /etc/shadow",
                f"Blank passwords absent: {not ev.parsed_data.get('has_empty_passwords') if ev else False}"
            ),
            remediation_cmd="Lock any empty accounts using passwd -l",
            tags=["IG1", "Account Management"]
        ))

        # CIS Safeguard 5.4: Restrict Administrator Privileges to Dedicated Accounts (IG1)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-5.4",
            framework_name=self.name,
            title="Restrict Administrator Privileges to Dedicated Accounts (IG1)",
            description="Ensure only the primary root account possesses UID 0.",
            target_item="user_accounts_uid0",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' has UID 0",
                f"UID 0 accounts: {ev.parsed_data.get('uid_zero_accounts') if ev else 'N/A'}"
            ),
            remediation_cmd="Remove secondary UID 0 users from /etc/passwd",
            tags=["IG1", "Access Control"]
        ))

        # CIS Safeguard 6.1: Establish an Access Granting Process / Sudo Least Privilege (IG2)
        validators.append(SudoersValidator(
            control_id="CIS-CSC-6.1",
            framework_name=self.name,
            title="Establish Access Granting Process and Sudo Least Privilege (IG2)",
            description="Ensure administrative privilege escalation requires re-authentication (no NOPASSWD).",
            check_type="no_nopasswd",
            severity=Severity.HIGH,
            weight=1.0,
            tags=["IG2", "Access Management"]
        ))

        # CIS Safeguard 8.2: Collect Audit Logs (IG1)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-8.2",
            framework_name=self.name,
            title="Collect Audit Logs (IG1)",
            description="Ensure the audit logging daemon is active and collecting system event logs.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.2,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd service active",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["IG1", "Audit Log Management"]
        ))

        # CIS Safeguard 10.1: Deploy and Maintain Host-Based Firewalls (IG1)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-10.1",
            framework_name=self.name,
            title="Deploy and Maintain Host-Based Firewalls (IG1)",
            description="Ensure host firewall is active to filter network traffic.",
            target_item="firewall_status",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("any_firewall_active")
                else ControlStatus.NON_COMPLIANT,
                "Host firewall active",
                f"Firewall active: {ev.parsed_data.get('any_firewall_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["IG1", "Network Defense"]
        ))

        # CIS Safeguard 10.3: Disable Insecure Services & Legacy Protocols (IG2)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-10.3",
            framework_name=self.name,
            title="Disable Insecure Services and Legacy Crypto Protocols (IG2)",
            description="Ensure legacy cryptographic suites on remote management services (SSH) are disabled.",
            target_item="ssh_server_configuration",
            severity=Severity.HIGH,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_weak_ciphers", True)
                else ControlStatus.NON_COMPLIANT,
                "No weak ciphers in sshd",
                f"Weak ciphers absent: {not ev.parsed_data.get('has_weak_ciphers') if ev else False}"
            ),
            remediation_cmd="Update SSH crypto suites in sshd_config",
            tags=["IG2", "Network Defense"]
        ))

        # CIS Safeguard 10.5: Deploy File Integrity Monitoring (IG2)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-CSC-10.5",
            framework_name=self.name,
            title="Deploy File Integrity Monitoring / Binary Verification (IG2)",
            description="Deploy software to monitor system files for unauthorized changes.",
            target_item="aide_fim_status",
            severity=Severity.MEDIUM,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed")
                else ControlStatus.NON_COMPLIANT,
                "AIDE or FIM solution installed",
                f"AIDE installed: {ev.parsed_data.get('aide_installed') if ev else False}"
            ),
            remediation_cmd="apt install aide || dnf install aide",
            tags=["IG2", "Malware Defense"]
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
