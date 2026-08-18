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


class SCAPFramework(BaseFramework):
    """SCAP / SSG Security Guide Framework mapper."""

    framework_id = "scap"
    name = "SCAP Security Guide"
    version = "1.3"
    description = "Security Content Automation Protocol (SCAP) and SSG Baseline Profiles"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        sysctl_ev = self._find_evidence(evidences, "kernel_sysctl_runtime")
        selinux_ev = self._find_evidence(evidences, "selinux_status")
        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        perms_ev = self._find_evidence(evidences, "critical_file_permissions")

        # SCAP: sysctl ASLR rule
        aslr_ok = (sysctl_ev.parsed_data.get("kernel.randomize_va_space") == "2") if sysctl_ev else False
        evaluations.append(ControlEvaluation(
            control_id="xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space",
            framework_name=self.name,
            title="Enable Randomized Layout of Virtual Address Space",
            description="Ensure sysctl kernel.randomize_va_space is set to 2.",
            status=ControlStatus.COMPLIANT if aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="kernel.randomize_va_space = 2",
            actual_condition=f"Value: {sysctl_ev.parsed_data.get('kernel.randomize_va_space') if sysctl_ev else 'N/A'}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w kernel.randomize_va_space=2",
            tags=["SCAP", "SSG", "Kernel"]
        ))

        # SCAP: selinux state rule
        selinux_ok = (selinux_ev.parsed_data.get("is_enforcing", False)) if selinux_ev else False
        evaluations.append(ControlEvaluation(
            control_id="xccdf_org.ssgproject.content_rule_selinux_state",
            framework_name=self.name,
            title="Ensure SELinux State is Enforcing",
            description="SELinux must be configured to Enforcing in /etc/selinux/config.",
            status=ControlStatus.COMPLIANT if selinux_ok else (ControlStatus.NOT_APPLICABLE if context.os_family.value == "debian" else ControlStatus.NON_COMPLIANT),
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="SELinux Enforcing",
            actual_condition=f"SELinux mode: {selinux_ev.parsed_data.get('mode') if selinux_ev else 'N/A'}",
            evidence_refs=[selinux_ev.evidence_id] if selinux_ev else [],
            remediation_cmd="setenforce 1",
            tags=["SCAP", "SSG", "SELinux"]
        ))

        # SCAP: auditd service enabled rule
        auditd_ok = (audit_ev.parsed_data.get("auditd_service_active", False)) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="xccdf_org.ssgproject.content_rule_service_auditd_enabled",
            framework_name=self.name,
            title="Enable auditd Service",
            description="The auditd service must be enabled and running.",
            status=ControlStatus.COMPLIANT if auditd_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="auditd running",
            actual_condition=f"auditd active: {auditd_ok}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            tags=["SCAP", "SSG", "Audit"]
        ))

        # SCAP: sshd disable root login rule
        root_ssh = ssh_ev.parsed_data.get("permit_root_login", "unset").lower() if ssh_ev else "unset"
        evaluations.append(ControlEvaluation(
            control_id="xccdf_org.ssgproject.content_rule_sshd_disable_root_login",
            framework_name=self.name,
            title="Disable SSH Direct Root Login",
            description="The SSH daemon must not allow direct login by root.",
            status=ControlStatus.COMPLIANT if root_ssh in ["no", "prohibit-password"] else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="PermitRootLogin prohibit-password or no",
            actual_condition=f"PermitRootLogin: {root_ssh}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/01-ssg.conf",
            tags=["SCAP", "SSG", "SSH"]
        ))

        return self._create_result(evaluations)
