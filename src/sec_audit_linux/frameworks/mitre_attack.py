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


class MITREAttackFramework(BaseFramework):
    """MITRE ATT&CK Enterprise Matrix for Linux Techniques and Mitigations."""

    framework_id = "mitre_attack"
    name = "MITRE ATT&CK (Linux)"
    version = "v15.0"
    description = "Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) Matrix for Linux"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # T1078: Valid Accounts
        validators.append(GenericEvidenceValidator(
            control_id="T1078",
            framework_name=self.name,
            title="Valid Accounts Hardening (T1078)",
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            target_item="user_accounts_uid0",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "No blank passwords and single UID 0 account",
                f"UID 0 ok: {ev.parsed_data.get('only_root_uid_zero') if ev else False}"
            ),
            remediation_cmd="Lock unauthenticated accounts and enforce strict UID 0 governance",
            tags=["Initial Access", "Privilege Escalation", "T1078"]
        ))

        # T1548.003: Sudo and Sudoers
        validators.append(SudoersValidator(
            control_id="T1548.003",
            framework_name=self.name,
            title="Abuse Elevation Control Mechanism: Sudo and Sudoers (T1548.003)",
            description="Adversaries may abuse sudoers configurations with NOPASSWD or wildcards to execute commands as root.",
            check_type="no_nopasswd",
            severity=Severity.HIGH,
            weight=1.5,
            tags=["Privilege Escalation", "T1548.003"]
        ))

        # T1562.001: Impair Defenses
        validators.append(GenericEvidenceValidator(
            control_id="T1562.001",
            framework_name=self.name,
            title="Impair Defenses: Security Services Active (T1562.001)",
            description="Adversaries may disable security tools like SELinux, auditd, and firewall to avoid detection.",
            target_item="auditd_rules_and_status",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd active and logging",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="Enable SELinux enforcing, start auditd, and activate firewall",
            tags=["Defense Evasion", "T1562.001"]
        ))

        # T1003.008: /etc/passwd and /etc/shadow
        validators.append(FilePermissionValidator(
            control_id="T1003.008",
            framework_name=self.name,
            title="OS Credential Dumping: /etc/passwd and /etc/shadow Permissions (T1003.008)",
            description="Adversaries may attempt to dump credentials by reading /etc/shadow or corrupting /etc/passwd.",
            file_path="/etc/shadow",
            expected_modes=["0000", "0600", "0640"],
            expected_uid=0,
            severity=Severity.HIGH,
            weight=1.5,
            tags=["Credential Access", "T1003.008"]
        ))

        # T1021.004: Remote Services SSH
        validators.append(SSHSettingValidator(
            control_id="T1021.004",
            framework_name=self.name,
            title="Remote Services: SSH Lateral Movement & Direct Root Login (T1021.004)",
            description="Adversaries may use SSH with compromised credentials to pivot across systems.",
            setting_key="permitrootlogin",
            expected_values=["no", "prohibit-password"],
            severity=Severity.HIGH,
            weight=1.2,
            tags=["Lateral Movement", "T1021.004"]
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
