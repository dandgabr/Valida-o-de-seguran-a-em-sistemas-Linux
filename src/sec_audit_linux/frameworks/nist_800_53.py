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


class NIST80053Framework(BaseFramework):
    """NIST SP 800-53 Rev 5 technical security controls for Linux host environments."""

    framework_id = "nist_800_53"
    name = "NIST SP 800-53 Rev 5"
    version = "Rev 5"
    description = "Security and Privacy Controls for Information Systems and Organizations"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        id_ev = self._find_evidence(evidences, "user_accounts_uid0")
        shadow_ev = self._find_evidence(evidences, "shadow_passwords_audit")
        sudo_ev = self._find_evidence(evidences, "sudoers_privilege_audit")
        perms_ev = self._find_evidence(evidences, "critical_file_permissions")
        selinux_ev = self._find_evidence(evidences, "selinux_status")
        apparmor_ev = self._find_evidence(evidences, "apparmor_status")
        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        sysctl_ev = self._find_evidence(evidences, "kernel_sysctl_runtime")
        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        fw_ev = self._find_evidence(evidences, "firewall_status")
        aide_ev = self._find_evidence(evidences, "aide_fim_status")
        crypto_ev = self._find_evidence(evidences, "system_crypto_policy")

        # AC-2: Account Management
        uid0_ok = id_ev.parsed_data.get("only_root_uid_zero", False) if id_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-AC-2",
            framework_name=self.name,
            title="Account Management (UID 0 & Account Governance)",
            description="Manage system accounts and ensure only the root user possesses UID 0.",
            status=ControlStatus.COMPLIANT if uid0_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Only 'root' has UID 0",
            actual_condition=f"UID 0 Accounts: {id_ev.parsed_data.get('uid_zero_accounts') if id_ev else 'N/A'}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Remove secondary UID 0 entries from /etc/passwd",
            rationale="Unmanaged administrative accounts complicate access governance and auditability.",
            tags=["AC", "Access Control"]
        ))

        # AC-3: Access Enforcement (SELinux / AppArmor MAC)
        mac_ok = (selinux_ev.parsed_data.get("is_enforcing", False) if selinux_ev else False) or (apparmor_ev.parsed_data.get("status") == "active" if apparmor_ev else False)
        evaluations.append(ControlEvaluation(
            control_id="NIST-AC-3",
            framework_name=self.name,
            title="Access Enforcement (Mandatory Access Control)",
            description="Enforce approved authorizations for logical access to information and system resources.",
            status=ControlStatus.COMPLIANT if mac_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="SELinux enforcing or AppArmor active",
            actual_condition=f"MAC Enforcing: {mac_ok}",
            evidence_refs=[selinux_ev.evidence_id] if selinux_ev else [],
            remediation_cmd="setenforce 1",
            rationale="Discretionary access control alone does not prevent root-level process takeovers.",
            tags=["AC", "Access Control"]
        ))

        # AC-6: Least Privilege (Sudo restrictions & NOPASSWD)
        no_nopasswd = not (sudo_ev.parsed_data.get("has_nopasswd", True)) if sudo_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-AC-6",
            framework_name=self.name,
            title="Least Privilege (Sudo Access & Authorization)",
            description="Employ the principle of least privilege, allowing only authorized accesses for users.",
            status=ControlStatus.COMPLIANT if no_nopasswd else ControlStatus.PARTIAL,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="No unrestricted NOPASSWD sudo entries",
            actual_condition=f"NOPASSWD count: {len(sudo_ev.parsed_data.get('nopasswd_entries', [])) if sudo_ev else 'N/A'}",
            evidence_refs=[sudo_ev.evidence_id] if sudo_ev else [],
            remediation_cmd="Remove NOPASSWD directives from /etc/sudoers",
            rationale="Unrestricted sudo allows processes running under low-privilege accounts to execute root commands without re-authentication.",
            tags=["AC", "Access Control"]
        ))

        # AU-2 / AU-12: Event Logging & Audit Generation
        auditd_ok = audit_ev.parsed_data.get("auditd_service_active", False) if audit_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-AU-2",
            framework_name=self.name,
            title="Event Logging and Audit Record Generation",
            description="Identify, collect, and retain audit records for security-relevant system events.",
            status=ControlStatus.COMPLIANT if auditd_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="auditd service active and generating records",
            actual_condition=f"auditd active: {auditd_ok}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            rationale="Audit generation is mandatory for forensic readiness and compliance.",
            tags=["AU", "Audit and Accountability"]
        ))

        # CM-6: Configuration Settings (Hardening & Sysctl)
        aslr_ok = (sysctl_ev.parsed_data.get("kernel.randomize_va_space") == "2") if sysctl_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-CM-6",
            framework_name=self.name,
            title="Configuration Settings (System Hardening Baseline)",
            description="Establish and document mandatory configuration settings for IT products.",
            status=ControlStatus.COMPLIANT if aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="Hardened kernel parameters applied",
            actual_condition=f"ASLR enabled: {aslr_ok}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="Apply CIS/DISA-STIG sysctl baseline",
            rationale="Default OS configurations are frequently overly permissive.",
            tags=["CM", "Configuration Management"]
        ))

        # IA-2 / IA-5: Identification, Authentication & Authenticator Management
        no_empty_pw = not (shadow_ev.parsed_data.get("has_empty_passwords", True)) if shadow_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-IA-5",
            framework_name=self.name,
            title="Authenticator Management (Password Policies & No Blank Passwords)",
            description="Manage information system authenticators by enforcing non-empty hashes and policy parameters.",
            status=ControlStatus.COMPLIANT if no_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="All active accounts have non-empty password hashes",
            actual_condition=f"Empty password users: {shadow_ev.parsed_data.get('empty_password_users') if shadow_ev else 'N/A'}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="passwd -l <user>",
            rationale="Blank passwords allow unauthenticated access to the operating system.",
            tags=["IA", "Identification and Authentication"]
        ))

        # SC-7: Boundary Protection (Host Firewall)
        fw_ok = fw_ev.parsed_data.get("any_firewall_active", False) if fw_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-SC-7",
            framework_name=self.name,
            title="Boundary Protection (Host-Based Packet Filtering)",
            description="Monitor and control communications at external and internal system boundaries.",
            status=ControlStatus.COMPLIANT if fw_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=1.5,
            expected_condition="Host-based firewall enabled and filtering",
            actual_condition=f"Firewall active: {fw_ok}",
            evidence_refs=[fw_ev.evidence_id] if fw_ev else [],
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw",
            rationale="Protects against network reconnaissance, lateral port scans, and unauthorized ingress.",
            tags=["SC", "System and Communications Protection"]
        ))

        # SC-13: Cryptographic Protection (System Crypto Policy & SSH Ciphers)
        crypto_policy_ok = crypto_ev.parsed_data.get("is_secure", False) if crypto_ev else True
        ssh_crypto_ok = not (ssh_ev.parsed_data.get("has_weak_ciphers", True)) if ssh_ev else False
        sc13_ok = crypto_policy_ok and ssh_crypto_ok
        evaluations.append(ControlEvaluation(
            control_id="NIST-SC-13",
            framework_name=self.name,
            title="Cryptographic Protection (Approved Cryptographic Algorithms)",
            description="Implement approved cryptographic algorithms, ciphers, and key exchange mechanisms.",
            status=ControlStatus.COMPLIANT if sc13_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="Approved FIPS/DEFAULT crypto policy and modern SSH ciphers",
            actual_condition=f"Crypto policy secure: {crypto_policy_ok}, SSH crypto secure: {ssh_crypto_ok}",
            evidence_refs=[crypto_ev.evidence_id, ssh_ev.evidence_id] if crypto_ev and ssh_ev else [],
            remediation_cmd="update-crypto-policies --set DEFAULT",
            rationale="Weak cryptography permits traffic interception and cryptographic downgrade attacks.",
            tags=["SC", "System and Communications Protection"]
        ))

        # SI-7: Software, Firmware, and Information Integrity (FIM / AIDE)
        aide_ok = aide_ev.parsed_data.get("aide_installed", False) if aide_ev else False
        evaluations.append(ControlEvaluation(
            control_id="NIST-SI-7",
            framework_name=self.name,
            title="Software, Firmware, and Information Integrity (FIM)",
            description="Employ integrity verification tools to detect unauthorized changes to system software.",
            status=ControlStatus.COMPLIANT if aide_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.2,
            expected_condition="AIDE or FIM daemon installed and auditing files",
            actual_condition=f"AIDE installed: {aide_ok}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="dnf install aide || apt install aide",
            rationale="File integrity monitoring is critical to identifying persistence and unauthorized binary replacements.",
            tags=["SI", "System and Information Integrity"]
        ))

        return self._create_result(evaluations)
