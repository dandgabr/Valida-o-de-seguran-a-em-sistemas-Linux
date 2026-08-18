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
from sec_audit_linux.core.scoring import calculate_pci_dss_score, summarize_evaluations


class PCIDSSFramework(BaseFramework):
    """Payment Card Industry Data Security Standard (PCI DSS) v4.0 for Linux Hosts."""

    framework_id = "pci_dss"
    name = "PCI DSS v4.0"
    version = "v4.0"
    description = "PCI DSS v4.0 Requirements for Cardholder Data Environment (CDE) Linux Systems"

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

        # Req 2.2: System components are configured and managed securely
        aslr_ok = (sysctl_ev.parsed_data.get("kernel.randomize_va_space") == "2") if sysctl_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-2.2.1",
            framework_name=self.name,
            title="System components are configured and managed securely (Hardening Baseline)",
            description="System components are hardened in accordance with industry-accepted configuration standards.",
            status=ControlStatus.COMPLIANT if aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Hardened kernel parameters applied",
            actual_condition=f"Hardening baseline compliant: {aslr_ok}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="Apply CIS/PCI-DSS sysctl baseline",
            rationale="Unsecured system configurations are the primary entry point for CDE breaches.",
            tags=["Requirement 2", "Secure Configuration"]
        ))

        # Req 7.2: Access to system components is restricted based on business need-to-know
        nopasswd_absent = not (sudo_ev.parsed_data.get("has_nopasswd", True)) if sudo_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-7.2.1",
            framework_name=self.name,
            title="Access to system components is appropriately restricted (Sudo Controls)",
            description="Privileged access is strictly managed and requires re-authentication (no unrestricted NOPASSWD).",
            status=ControlStatus.COMPLIANT if nopasswd_absent else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="No unrestricted NOPASSWD in sudoers",
            actual_condition=f"NOPASSWD absent: {nopasswd_absent}",
            evidence_refs=[sudo_ev.evidence_id] if sudo_ev else [],
            remediation_cmd="Remove NOPASSWD directives from /etc/sudoers",
            rationale="NOPASSWD breaks authentication traceability required by PCI DSS.",
            tags=["Requirement 7", "Access Restriction"]
        ))

        # Req 8.2: User identification and management
        root_0_ok = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-8.2.1",
            framework_name=self.name,
            title="User identification is uniquely assigned (Single UID 0 Account)",
            description="All users are assigned a unique ID before being allowed to access system components.",
            status=ControlStatus.COMPLIANT if root_0_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="Only 'root' has UID 0",
            actual_condition=f"UID 0 ok: {root_0_ok}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Remove secondary UID 0 accounts from /etc/passwd",
            rationale="Shared UID 0 prevents non-repudiation and accountability.",
            tags=["Requirement 8", "Identification"]
        ))

        # Req 8.3: Strong authentication & no blank passwords
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-8.3.1",
            framework_name=self.name,
            title="Strong authentication mechanisms (No Empty Passwords)",
            description="Ensure blank passwords are systematically forbidden across all accounts.",
            status=ControlStatus.COMPLIANT if no_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="No blank passwords in /etc/shadow",
            actual_condition=f"Blank passwords absent: {no_empty_pw}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="Lock any empty account with passwd -l",
            rationale="Blank passwords represent a critical compliance violation.",
            tags=["Requirement 8", "Authentication"]
        ))

        # Req 10.2: Audit logging is implemented and active
        auditd_ok = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-10.2.1",
            framework_name=self.name,
            title="Audit logs are generated and recorded (Active auditd Daemon)",
            description="Audit logs are generated for all system components to enable tracking of security events.",
            status=ControlStatus.COMPLIANT if auditd_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="auditd daemon active and collecting events",
            actual_condition=f"auditd active: {auditd_ok}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            rationale="Audit logging is a mandatory requirement under PCI DSS 10.2.",
            tags=["Requirement 10", "Audit Logging"]
        ))

        # Req 11.5: Change-detection mechanism is deployed on critical files (FIM)
        aide_ok = aide_ev.parsed_data.get("aide_installed", False) if aide_ev else False
        evaluations.append(ControlEvaluation(
            control_id="PCI-11.5.1",
            framework_name=self.name,
            title="A change-detection mechanism is deployed (File Integrity Monitoring)",
            description="Deploy a change-detection mechanism (FIM) to alert personnel to unauthorized modification of critical files.",
            status=ControlStatus.COMPLIANT if aide_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="AIDE or FIM daemon installed and active",
            actual_condition=f"AIDE installed: {aide_ok}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="apt install aide || dnf install aide",
            rationale="FIM alerts security teams when critical binaries or configuration files are altered.",
            tags=["Requirement 11", "File Integrity Monitoring"]
        ))

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
