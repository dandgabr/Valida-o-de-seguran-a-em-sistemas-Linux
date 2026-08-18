"""NIST Cybersecurity Framework (CSF 2.0) Module."""

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


class NISTCSFFramework(BaseFramework):
    """NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)."""

    framework_id = "nist_csf"
    name = "NIST CSF 2.0"
    version = "2.0"
    description = "National Institute of Standards and Technology Cybersecurity Framework 2.0"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # PR.AC-01: Identities and credentials authenticated
        validators.append(GenericEvidenceValidator(
            control_id="CSF-PR.AC-01",
            framework_name=self.name,
            title="Identities and credentials are authenticated and managed",
            description="Manage authentication mechanisms and prevent blank passwords.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "No accounts with empty passwords",
                f"Empty passwords absent: {not ev.parsed_data.get('has_empty_passwords') if ev else False}"
            ),
            remediation_cmd="passwd -l <user>",
            tags=["Protect", "PR.AC"]
        ))

        # PR.AC-02: Privileged access restricted
        validators.append(GenericEvidenceValidator(
            control_id="CSF-PR.AC-02",
            framework_name=self.name,
            title="Logical access to privileged accounts is restricted",
            description="Enforce least privilege and ensure only root possesses UID 0.",
            target_item="user_accounts_uid0",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' has UID 0",
                f"UID 0 ok: {ev.parsed_data.get('only_root_uid_zero') if ev else False}"
            ),
            remediation_cmd="Remove secondary UID 0 accounts",
            tags=["Protect", "PR.AC"]
        ))

        # PR.DS-01: Data and configs protected
        validators.append(FilePermissionValidator(
            control_id="CSF-PR.DS-01",
            framework_name=self.name,
            title="Configuration files and credential stores are protected",
            description="Ensure strict permissions on sensitive files (/etc/passwd, /etc/shadow).",
            file_path="/etc/passwd",
            expected_modes=["0644"],
            expected_uid=0,
            severity=Severity.HIGH,
            weight=1.2,
            tags=["Protect", "PR.DS"]
        ))

        # PR.PS-01: Platform Security Baselines
        validators.append(SysctlValidator(
            control_id="CSF-PR.PS-01",
            framework_name=self.name,
            title="Configuration baselines and kernel protections are maintained",
            description="Maintain hardened OS baselines with ASLR enabled.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.0,
            tags=["Protect", "PR.PS"]
        ))

        # PR.IR-01: Network Perimeter Security
        validators.append(GenericEvidenceValidator(
            control_id="CSF-PR.IR-01",
            framework_name=self.name,
            title="Network perimeters and host firewall filtering are enforced",
            description="Ensure host firewall is active and filtering unwanted network traffic.",
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
            tags=["Protect", "PR.IR"]
        ))

        # DE.CM-01: System Monitoring Active
        validators.append(GenericEvidenceValidator(
            control_id="CSF-DE.CM-01",
            framework_name=self.name,
            title="System event logging and audit monitoring are active",
            description="Enable auditd to capture and monitor system security events.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd daemon active",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["Detect", "DE.CM"]
        ))

        # DE.AE-01: Integrity Monitoring
        validators.append(GenericEvidenceValidator(
            control_id="CSF-DE.AE-01",
            framework_name=self.name,
            title="Integrity monitoring is deployed to detect unauthorized changes",
            description="Deploy AIDE or FIM software to identify baseline anomalies.",
            target_item="aide_fim_status",
            severity=Severity.MEDIUM,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed")
                else ControlStatus.NON_COMPLIANT,
                "AIDE installed",
                f"AIDE installed: {ev.parsed_data.get('aide_installed') if ev else False}"
            ),
            remediation_cmd="apt install aide || dnf install aide",
            tags=["Detect", "DE.AE"]
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
