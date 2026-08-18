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


class NISTCSFFramework(BaseFramework):
    """NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond, Recover)."""

    framework_id = "nist_csf"
    name = "NIST CSF 2.0"
    version = "2.0"
    description = "National Institute of Standards and Technology Cybersecurity Framework 2.0"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        perms_ev = self._find_evidence(evidences, "critical_file_permissions")
        id_ev = self._find_evidence(evidences, "user_accounts_uid0")
        shadow_ev = self._find_evidence(evidences, "shadow_passwords_audit")
        fw_ev = self._find_evidence(evidences, "firewall_status")
        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        aide_ev = self._find_evidence(evidences, "aide_fim_status")
        sysctl_ev = self._find_evidence(evidences, "kernel_sysctl_runtime")

        # PR.AC-01: Identities and credentials are authenticated and managed (Protect - Access Control)
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-PR.AC-01",
            framework_name=self.name,
            title="Identities and credentials are authenticated and managed",
            description="Manage authentication mechanisms and prevent blank passwords.",
            status=ControlStatus.COMPLIANT if no_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="No accounts with empty passwords",
            actual_condition=f"Empty passwords absent: {no_empty_pw}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="passwd -l <user>",
            tags=["Protect", "PR.AC"]
        ))

        # PR.AC-02: Physical and logical access to assets is managed and restricted (Protect - Access Control)
        root_0_ok = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-PR.AC-02",
            framework_name=self.name,
            title="Logical access to privileged accounts is restricted",
            description="Enforce least privilege and ensure only root possesses UID 0.",
            status=ControlStatus.COMPLIANT if root_0_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Only 'root' has UID 0",
            actual_condition=f"UID 0 ok: {root_0_ok}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Remove secondary UID 0 accounts",
            tags=["Protect", "PR.AC"]
        ))

        # PR.DS-01: Data-at-rest and configuration files are protected (Protect - Data Security)
        perms_ok = perms_ev.parsed_data.get("all_compliant", False) if perms_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-PR.DS-01",
            framework_name=self.name,
            title="Configuration files and credential stores are protected",
            description="Ensure strict permissions on sensitive files (/etc/passwd, /etc/shadow).",
            status=ControlStatus.COMPLIANT if perms_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="Permissions compliant on sensitive files",
            actual_condition=f"All compliant: {perms_ok}",
            evidence_refs=[perms_ev.evidence_id] if perms_ev else [],
            remediation_cmd="chmod 644 /etc/passwd && chmod 000 /etc/shadow",
            tags=["Protect", "PR.DS"]
        ))

        # PR.PS-01: Configuration baselines are maintained (Protect - Platform Security)
        aslr_ok = (sysctl_ev.parsed_data.get("kernel.randomize_va_space") == "2") if sysctl_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-PR.PS-01",
            framework_name=self.name,
            title="Configuration baselines and kernel protections are maintained",
            description="Maintain hardened OS baselines with ASLR enabled.",
            status=ControlStatus.COMPLIANT if aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="ASLR enabled (kernel.randomize_va_space=2)",
            actual_condition=f"ASLR enabled: {aslr_ok}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w kernel.randomize_va_space=2",
            tags=["Protect", "PR.PS"]
        ))

        # PR.IR-01: Networks and network perimeters are secured (Protect - Infrastructure Resilience)
        fw_ok = fw_ev.parsed_data.get("any_firewall_active", False) if fw_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-PR.IR-01",
            framework_name=self.name,
            title="Network perimeters and host firewall filtering are enforced",
            description="Ensure host firewall is active and filtering unwanted network traffic.",
            status=ControlStatus.COMPLIANT if fw_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="Host firewall active",
            actual_condition=f"Firewall active: {fw_ok}",
            evidence_refs=[fw_ev.evidence_id] if fw_ev else [],
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            tags=["Protect", "PR.IR"]
        ))

        # DE.CM-01: The network and system are monitored to find potentially malicious events (Detect - Monitoring)
        auditd_ok = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-DE.CM-01",
            framework_name=self.name,
            title="System event logging and audit monitoring are active",
            description="Enable auditd to capture and monitor system security events.",
            status=ControlStatus.COMPLIANT if auditd_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="auditd daemon active",
            actual_condition=f"auditd active: {auditd_ok}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            tags=["Detect", "DE.CM"]
        ))

        # DE.AE-01: Anomalous activity is analyzed (Detect - Adverse Events / FIM)
        aide_ok = aide_ev.parsed_data.get("aide_installed", False) if aide_ev else False
        evaluations.append(ControlEvaluation(
            control_id="CSF-DE.AE-01",
            framework_name=self.name,
            title="Integrity monitoring is deployed to detect unauthorized changes",
            description="Deploy AIDE or FIM software to identify baseline anomalies.",
            status=ControlStatus.COMPLIANT if aide_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="AIDE installed",
            actual_condition=f"AIDE installed: {aide_ok}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="apt install aide || dnf install aide",
            tags=["Detect", "DE.AE"]
        ))

        return self._create_result(evaluations)
