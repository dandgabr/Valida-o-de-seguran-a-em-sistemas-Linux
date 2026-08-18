"""CIS Linux Benchmark (Distribution Independent & Enterprise Profiles) Framework Module."""

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


class CISBenchmarkFramework(BaseFramework):
    """CIS Linux Benchmark evaluator covering Level 1 and Level 2 recommendations."""

    framework_id = "cis_benchmarks"
    name = "CIS Linux Benchmark"
    version = "v3.0.0"
    description = "Center for Internet Security (CIS) Distribution-Independent Linux Hardening Benchmark"

    def evaluate(self, evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult:
        evaluations: List[ControlEvaluation] = []

        sysctl_ev = self._find_evidence(evidences, "kernel_sysctl_runtime")
        sysctl_data = sysctl_ev.parsed_data if sysctl_ev else {}

        perms_ev = self._find_evidence(evidences, "critical_file_permissions")
        perms_data = perms_ev.parsed_data if perms_ev else {}

        selinux_ev = self._find_evidence(evidences, "selinux_status")
        selinux_data = selinux_ev.parsed_data if selinux_ev else {}

        apparmor_ev = self._find_evidence(evidences, "apparmor_status")
        apparmor_data = apparmor_ev.parsed_data if apparmor_ev else {}

        id_ev = self._find_evidence(evidences, "user_accounts_uid0")
        id_data = id_ev.parsed_data if id_ev else {}

        shadow_ev = self._find_evidence(evidences, "shadow_passwords_audit")
        shadow_data = shadow_ev.parsed_data if shadow_ev else {}

        sudo_ev = self._find_evidence(evidences, "sudoers_privilege_audit")
        sudo_data = sudo_ev.parsed_data if sudo_ev else {}

        ssh_ev = self._find_evidence(evidences, "ssh_server_configuration")
        ssh_data = ssh_ev.parsed_data if ssh_ev else {}

        fw_ev = self._find_evidence(evidences, "firewall_status")
        fw_data = fw_ev.parsed_data if fw_ev else {}

        audit_ev = self._find_evidence(evidences, "auditd_rules_and_status")
        audit_data = audit_ev.parsed_data if audit_ev else {}

        aide_ev = self._find_evidence(evidences, "aide_fim_status")
        aide_data = aide_ev.parsed_data if aide_ev else {}

        # ----------------------------------------------------
        # 1. Initial Setup & System Hardening
        # ----------------------------------------------------
        # CIS 1.1.1: Filesystem Permissions (/etc/passwd, /etc/shadow)
        all_perms_ok = perms_data.get("all_compliant", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-1.1.1",
            framework_name=self.name,
            title="Ensure permissions on sensitive system files are configured",
            description="Checks permissions and ownership of /etc/passwd, /etc/shadow, /etc/group, and /etc/sudoers.",
            status=ControlStatus.COMPLIANT if all_perms_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="/etc/passwd 0644, /etc/shadow 0000/0600 owned by root",
            actual_condition=f"Deviations found: {len(perms_data.get('deviations', []))}",
            evidence_refs=[perms_ev.evidence_id] if perms_ev else [],
            remediation_cmd="chmod 644 /etc/passwd /etc/group && chmod 000 /etc/shadow /etc/gshadow && chmod 440 /etc/sudoers",
            rationale="Improper permissions on sensitive files may permit unauthorized privilege escalation or hash disclosure."
        ))

        # CIS 1.3.1: Mandatory Access Control (SELinux / AppArmor)
        mac_active = selinux_data.get("is_enforcing", False) or apparmor_data.get("status") == "active"
        evaluations.append(ControlEvaluation(
            control_id="CIS-1.3.1",
            framework_name=self.name,
            title="Ensure SELinux or AppArmor is enabled and enforcing",
            description="Mandatory Access Control provides kernel-level sandboxing and least privilege containment.",
            status=ControlStatus.COMPLIANT if mac_active else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="SELinux in enforcing mode OR AppArmor active",
            actual_condition=f"SELinux: {selinux_data.get('mode', 'unknown')}, AppArmor: {apparmor_data.get('status', 'unknown')}",
            evidence_refs=[selinux_ev.evidence_id] if selinux_ev else [],
            remediation_cmd="setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",
            rationale="Disabling MAC leaves the system vulnerable to containment escapes and process hijackings."
        ))

        # CIS 1.5.1: Restrict Core Dumps (fs.suid_dumpable = 0)
        dumpable_val = sysctl_data.get("fs.suid_dumpable", "1")
        is_dumpable_ok = dumpable_val == "0"
        evaluations.append(ControlEvaluation(
            control_id="CIS-1.5.1",
            framework_name=self.name,
            title="Ensure core dumps are restricted (fs.suid_dumpable = 0)",
            description="Restricts SUID binaries from producing memory core dumps.",
            status=ControlStatus.COMPLIANT if is_dumpable_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="fs.suid_dumpable = 0",
            actual_condition=f"fs.suid_dumpable = {dumpable_val}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-security.conf",
            rationale="Core dumps from SUID programs can expose sensitive memory content such as encryption keys."
        ))

        # CIS 1.5.2: Address Space Layout Randomization (ASLR)
        aslr_val = sysctl_data.get("kernel.randomize_va_space", "0")
        is_aslr_ok = aslr_val == "2"
        evaluations.append(ControlEvaluation(
            control_id="CIS-1.5.2",
            framework_name=self.name,
            title="Ensure Address Space Layout Randomization (ASLR) is enabled",
            description="Randomizes memory stack, heap, and library locations.",
            status=ControlStatus.COMPLIANT if is_aslr_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="kernel.randomize_va_space = 2",
            actual_condition=f"kernel.randomize_va_space = {aslr_val}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w kernel.randomize_va_space=2 && echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-security.conf",
            rationale="ASLR mitigates buffer overflow and Return-Oriented Programming (ROP) exploitation."
        ))

        # ----------------------------------------------------
        # 3. Network Configuration & Sysctl
        # ----------------------------------------------------
        # CIS 3.1.1: Disable IP Forwarding
        ip_fwd = sysctl_data.get("net.ipv4.ip_forward", "1")
        evaluations.append(ControlEvaluation(
            control_id="CIS-3.1.1",
            framework_name=self.name,
            title="Ensure IP forwarding is disabled",
            description="Prevents non-router systems from routing packets between network interfaces.",
            status=ControlStatus.COMPLIANT if ip_fwd == "0" else ControlStatus.NON_COMPLIANT,
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="net.ipv4.ip_forward = 0",
            actual_condition=f"net.ipv4.ip_forward = {ip_fwd}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-security.conf",
            rationale="Unintentional packet forwarding can turn a server into an unauthorized network router."
        ))

        # CIS 3.2.4: Enable TCP SYN Cookies
        syn_val = sysctl_data.get("net.ipv4.tcp_syncookies", "0")
        evaluations.append(ControlEvaluation(
            control_id="CIS-3.2.4",
            framework_name=self.name,
            title="Ensure TCP SYN Cookies is enabled",
            description="Mitigates TCP SYN Flood denial-of-service attacks.",
            status=ControlStatus.COMPLIANT if syn_val == "1" else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.0,
            expected_condition="net.ipv4.tcp_syncookies = 1",
            actual_condition=f"net.ipv4.tcp_syncookies = {syn_val}",
            evidence_refs=[sysctl_ev.evidence_id] if sysctl_ev else [],
            remediation_cmd="sysctl -w net.ipv4.tcp_syncookies=1 && echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-security.conf",
            rationale="Protects connection queues during volumetric SYN attacks."
        ))

        # CIS 3.4.1: Firewall Active
        has_fw = fw_data.get("any_firewall_active", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-3.4.1",
            framework_name=self.name,
            title="Ensure a host firewall is installed and active",
            description="Verifies that nftables, iptables, ufw, or firewalld is enforcing network filtering.",
            status=ControlStatus.COMPLIANT if has_fw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="Active firewall daemon / ruleset",
            actual_condition=f"Firewall active: {has_fw}",
            evidence_refs=[fw_ev.evidence_id] if fw_ev else [],
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw || systemctl enable --now nftables",
            rationale="A host firewall blocks unsolicited incoming connections and limits lateral movement."
        ))

        # ----------------------------------------------------
        # 5. Access, Identity, and SSH
        # ----------------------------------------------------
        # CIS 5.1.1: Only root has UID 0
        root_only_uid0 = id_data.get("only_root_uid_zero", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-5.1.1",
            framework_name=self.name,
            title="Ensure root is the only UID 0 account",
            description="Verifies that no secondary administrative accounts possess UID 0.",
            status=ControlStatus.COMPLIANT if root_only_uid0 else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="Only 'root' has UID 0",
            actual_condition=f"UID 0 accounts: {id_data.get('uid_zero_accounts', [])}",
            evidence_refs=[id_ev.evidence_id] if id_ev else [],
            remediation_cmd="Remove or change UID for non-root accounts found with UID 0 in /etc/passwd",
            rationale="Secondary UID 0 accounts bypass user accounting and privilege escalation audits."
        ))

        # CIS 5.1.2: No Empty Passwords
        has_empty_pw = shadow_data.get("has_empty_passwords", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-5.1.2",
            framework_name=self.name,
            title="Ensure password fields are not empty in /etc/shadow",
            description="Ensures all non-locked accounts have a secure password hash.",
            status=ControlStatus.COMPLIANT if not has_empty_pw else ControlStatus.NON_COMPLIANT,
            severity=Severity.CRITICAL,
            weight=2.0,
            expected_condition="0 accounts with empty passwords",
            actual_condition=f"Empty pw users: {shadow_data.get('empty_password_users', [])}",
            evidence_refs=[shadow_ev.evidence_id] if shadow_ev else [],
            remediation_cmd="passwd -l <user> for any empty account",
            rationale="Accounts without passwords allow unauthenticated local and remote access."
        ))

        # CIS 5.1.3: Sudoers NOPASSWD Restriction
        has_nopasswd = sudo_data.get("has_nopasswd", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-5.1.3",
            framework_name=self.name,
            title="Ensure sudo commands require authentication (No unrestricted NOPASSWD)",
            description="Restricts unrestricted NOPASSWD directives in sudoers.",
            status=ControlStatus.COMPLIANT if not has_nopasswd else ControlStatus.PARTIAL,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="All sudo execution requires password verification",
            actual_condition=f"NOPASSWD entries found: {len(sudo_data.get('nopasswd_entries', []))}",
            evidence_refs=[sudo_ev.evidence_id] if sudo_ev else [],
            remediation_cmd="Remove NOPASSWD from /etc/sudoers and /etc/sudoers.d/*",
            rationale="NOPASSWD allows a compromised non-root process to immediately escalate to root."
        ))

        # CIS 5.2.1: SSH PermitRootLogin
        root_ssh = ssh_data.get("permit_root_login", "unset").lower()
        root_ssh_ok = root_ssh in ["no", "prohibit-password"]
        evaluations.append(ControlEvaluation(
            control_id="CIS-5.2.1",
            framework_name=self.name,
            title="Ensure SSH PermitRootLogin is disabled or prohibit-password",
            description="Disallows direct root logins over OpenSSH.",
            status=ControlStatus.COMPLIANT if root_ssh_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="PermitRootLogin no or prohibit-password",
            actual_condition=f"PermitRootLogin = {root_ssh}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="echo 'PermitRootLogin prohibit-password' >> /etc/ssh/sshd_config.d/01-hardening.conf && systemctl reload sshd",
            rationale="Disabling direct root login enforces individual account accountability via sudo."
        ))

        # CIS 5.2.7: SSH Strong Crypto Suites (No weak ciphers/macs/kex)
        weak_ciphers = ssh_data.get("has_weak_ciphers", False)
        weak_macs = ssh_data.get("has_weak_macs", False)
        weak_kex = ssh_data.get("has_weak_kex", False)
        ssh_crypto_ok = not (weak_ciphers or weak_macs or weak_kex)

        evaluations.append(ControlEvaluation(
            control_id="CIS-5.2.7",
            framework_name=self.name,
            title="Ensure SSH weak Ciphers, MACs, and Kex algorithms are disabled",
            description="Enforces modern cryptography (ChaCha20, AES-GCM, SHA-2, Curve25519) on SSH server.",
            status=ControlStatus.COMPLIANT if ssh_crypto_ok else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="No CBC ciphers, MD5/SHA1 MACs, or 1024-bit DH groups",
            actual_condition=f"Weak Ciphers: {weak_ciphers}, Weak MACs: {weak_macs}, Weak Kex: {weak_kex}",
            evidence_refs=[ssh_ev.evidence_id] if ssh_ev else [],
            remediation_cmd="Configure strong Ciphers and KexAlgorithms in /etc/ssh/sshd_config.d/01-crypto.conf",
            rationale="Legacy cryptographic primitives are vulnerable to eavesdropping and downgrade attacks."
        ))

        # ----------------------------------------------------
        # 6. Logging, Auditing, and Integrity
        # ----------------------------------------------------
        # CIS 6.1.1: Auditd Service Active
        audit_active = audit_data.get("auditd_service_active", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-6.1.1",
            framework_name=self.name,
            title="Ensure auditd service is enabled and active",
            description="The Linux Audit Framework records security-relevant system events and system calls.",
            status=ControlStatus.COMPLIANT if audit_active else ControlStatus.NON_COMPLIANT,
            severity=Severity.HIGH,
            weight=1.5,
            expected_condition="auditd daemon active and running",
            actual_condition=f"auditd active: {audit_active}",
            evidence_refs=[audit_ev.evidence_id] if audit_ev else [],
            remediation_cmd="systemctl enable --now auditd",
            rationale="Without auditd, forensic investigation of privilege escalations and file modifications is hindered."
        ))

        # CIS 6.2.1: AIDE Installed & Baseline Initialized
        aide_ok = aide_data.get("aide_installed", False) and aide_data.get("database_present", False)
        evaluations.append(ControlEvaluation(
            control_id="CIS-6.2.1",
            framework_name=self.name,
            title="Ensure AIDE File Integrity Monitoring (FIM) is installed and initialized",
            description="Verifies baseline integrity database for system binaries and configuration files.",
            status=ControlStatus.COMPLIANT if aide_ok else (ControlStatus.PARTIAL if aide_data.get("aide_installed") else ControlStatus.NON_COMPLIANT),
            severity=Severity.MEDIUM,
            weight=1.0,
            expected_condition="AIDE installed and database initialized",
            actual_condition=f"AIDE installed: {aide_data.get('aide_installed')}, DB present: {aide_data.get('database_present')}",
            evidence_refs=[aide_ev.evidence_id] if aide_ev else [],
            remediation_cmd="apt-get install aide || dnf install aide && aideinit",
            rationale="FIM detects unauthorized modifications and rootkits altering core system binaries."
        ))

        return self._create_result(evaluations)
