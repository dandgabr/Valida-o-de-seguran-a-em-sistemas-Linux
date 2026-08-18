"""SCAP / SSG (Security Content Automation Protocol) Framework Module."""

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


class SCAPFramework(BaseFramework):
    """SCAP / SSG Security Guide Framework mapper."""

    framework_id = "scap"
    name = "SCAP Security Guide"
    version = "1.3"
    description = "Security Content Automation Protocol (SCAP) and SSG Baseline Profiles"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # SCAP: ASLR rule
        validators.append(SysctlValidator(
            control_id="xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space",
            framework_name=self.name,
            title="Enable Randomized Layout of Virtual Address Space",
            description="Ensure sysctl kernel.randomize_va_space is set to 2.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.0,
            tags=["SCAP", "SSG", "Kernel"]
        ))

        # SCAP: SELinux state rule
        validators.append(GenericEvidenceValidator(
            control_id="xccdf_org.ssgproject.content_rule_selinux_state",
            framework_name=self.name,
            title="Ensure SELinux State is Enforcing",
            description="SELinux must be configured to Enforcing in /etc/selinux/config.",
            target_item="selinux_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("is_enforcing")
                else (ControlStatus.NOT_APPLICABLE if ctx.os_family.value == "debian" else ControlStatus.NON_COMPLIANT),
                "SELinux Enforcing",
                f"SELinux: {ev.parsed_data.get('mode') if ev else 'N/A'}"
            ),
            remediation_cmd="setenforce 1",
            tags=["SCAP", "SSG", "SELinux"]
        ))

        # SCAP: auditd service enabled rule
        validators.append(GenericEvidenceValidator(
            control_id="xccdf_org.ssgproject.content_rule_service_auditd_enabled",
            framework_name=self.name,
            title="Enable auditd Service",
            description="The auditd service must be enabled and running.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd running",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            tags=["SCAP", "SSG", "Audit"]
        ))

        # SCAP: sshd disable root login rule
        validators.append(SSHSettingValidator(
            control_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            framework_name=self.name,
            title="Disable SSH Direct Root Login",
            description="The SSH daemon must not allow direct login by root.",
            setting_key="permitrootlogin",
            expected_values=["no", "prohibit-password"],
            severity=Severity.HIGH,
            weight=1.0,
            tags=["SCAP", "SSG", "SSH"]
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
