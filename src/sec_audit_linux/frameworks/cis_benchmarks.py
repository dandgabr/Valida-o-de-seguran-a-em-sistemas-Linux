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


class CISBenchmarkFramework(BaseFramework):
    """CIS Linux Benchmark evaluator covering Level 1 and Level 2 recommendations."""

    framework_id = "cis_benchmarks"
    name = "CIS Linux Benchmark"
    version = "v3.0.0"
    description = "Center for Internet Security (CIS) Distribution-Independent Linux Hardening Benchmark"

    def __init__(self):
        self._validators: List[BaseValidator] = self._build_validators()

    def _build_validators(self) -> List[BaseValidator]:
        validators: List[BaseValidator] = []

        # ----------------------------------------------------
        # 1. Initial Setup & Filesystem Hardening
        # ----------------------------------------------------
        # CIS 1.1.1: Filesystem Permissions (/etc/passwd, /etc/shadow, /etc/group, /etc/sudoers)
        validators.append(FilePermissionValidator(
            control_id="CIS-1.1.1",
            framework_name=self.name,
            title="Ensure permissions on /etc/passwd are configured (0644)",
            description="Checks permissions and ownership of /etc/passwd (mode 0644, owned by root).",
            file_path="/etc/passwd",
            expected_modes=["0644"],
            expected_uid=0,
            severity=Severity.HIGH,
            weight=1.5,
            rationale="World-writable passwd file allows unprivileged users to create unauthorized UID 0 accounts."
        ))

        validators.append(FilePermissionValidator(
            control_id="CIS-1.1.2",
            framework_name=self.name,
            title="Ensure permissions on /etc/shadow are configured (0000/0600/0640)",
            description="Checks permissions and ownership of /etc/shadow (mode 0000/0600/0640, owned by root).",
            file_path="/etc/shadow",
            expected_modes=["0000", "0600", "0640"],
            expected_uid=0,
            severity=Severity.CRITICAL,
            weight=2.0,
            rationale="Improper permissions on /etc/shadow leak password hashes for offline cracking."
        ))

        validators.append(FilePermissionValidator(
            control_id="CIS-1.1.3",
            framework_name=self.name,
            title="Ensure permissions on /etc/sudoers are configured (0440/0400)",
            description="Checks permissions on /etc/sudoers (mode 0440/0400, owned by root).",
            file_path="/etc/sudoers",
            expected_modes=["0440", "0400"],
            expected_uid=0,
            severity=Severity.CRITICAL,
            weight=2.0,
            rationale="Writable sudoers file allows direct root escalation."
        ))

        # CIS 1.1.4: Uncommon Filesystem Modules Disabled
        validators.append(GenericEvidenceValidator(
            control_id="CIS-1.1.4",
            framework_name=self.name,
            title="Ensure unused filesystems (cramfs, freevxfs, jffs2, hfs, udf) are disabled",
            description="Disabling support for unneeded filesystem types reduces the local kernel attack surface.",
            target_item="kernel_modules_status",
            severity=Severity.MEDIUM,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and any(ev.parsed_data.get(m, {}).get("disabled_in_config") for m in ["cramfs", "jffs2", "udf"])
                else ControlStatus.NON_COMPLIANT,
                "Uncommon filesystems blacklisted in /etc/modprobe.d/",
                f"Active status: {list(ev.parsed_data.keys()) if ev else 'N/A'}"
            ),
            remediation_cmd="echo 'install cramfs /bin/true' >> /etc/modprobe.d/cramfs.conf && echo 'install udf /bin/true' >> /etc/modprobe.d/udf.conf",
            rationale="Vulnerabilities in legacy filesystem drivers can be exploited via malicious USB media."
        ))

        # CIS 1.3.1: Mandatory Access Control (SELinux / AppArmor)
        validators.append(GenericEvidenceValidator(
            control_id="CIS-1.3.1",
            framework_name=self.name,
            title="Ensure SELinux or AppArmor is enabled and enforcing",
            description="Mandatory Access Control provides kernel-level sandboxing and containment.",
            target_item="selinux_status",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("is_enforcing")
                else (ControlStatus.COMPLIANT if ctx.os_family.value == "debian" else ControlStatus.NON_COMPLIANT),
                "SELinux in enforcing mode or AppArmor active",
                f"SELinux: {ev.parsed_data.get('mode') if ev else 'N/A'}, OS Family: {ctx.os_family.value}"
            ),
            remediation_cmd="setenforce 1 && sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config",
            rationale="Disabling MAC leaves the system vulnerable to containment escapes."
        ))

        # CIS 1.5.1: Core Dumps Restricted
        validators.append(SysctlValidator(
            control_id="CIS-1.5.1",
            framework_name=self.name,
            title="Ensure core dumps are restricted (fs.suid_dumpable = 0)",
            description="Restricts SUID binaries from producing memory core dumps.",
            param_name="fs.suid_dumpable",
            expected_value="0",
            severity=Severity.MEDIUM,
            weight=1.0,
            rationale="Core dumps from SUID programs can expose sensitive memory content."
        ))

        # CIS 1.5.2: ASLR Enabled
        validators.append(SysctlValidator(
            control_id="CIS-1.5.2",
            framework_name=self.name,
            title="Ensure Address Space Layout Randomization (ASLR) is enabled",
            description="Randomizes memory stack, heap, and library locations.",
            param_name="kernel.randomize_va_space",
            expected_value="2",
            severity=Severity.HIGH,
            weight=1.5,
            rationale="ASLR mitigates buffer overflow and Return-Oriented Programming (ROP) exploitation."
        ))

        # CIS 1.5.3: Restrict Ptrace Scope
        validators.append(SysctlValidator(
            control_id="CIS-1.5.3",
            framework_name=self.name,
            title="Ensure ptrace scope is restricted (kernel.yama.ptrace_scope >= 1)",
            description="Restricts process debugging and memory injection between unprivileged processes.",
            param_name="kernel.yama.ptrace_scope",
            expected_value=["1", "2", "3"],
            operator="in",
            severity=Severity.HIGH,
            weight=1.2,
            rationale="Unrestricted ptrace allows process injection and credential sniffing from running memory."
        ))

        # ----------------------------------------------------
        # 3. Network Hardening & Sysctl
        # ----------------------------------------------------
        validators.append(SysctlValidator(
            control_id="CIS-3.1.1",
            framework_name=self.name,
            title="Ensure IP forwarding is disabled (net.ipv4.ip_forward = 0)",
            description="Prevents non-router systems from routing packets between network interfaces.",
            param_name="net.ipv4.ip_forward",
            expected_value="0",
            severity=Severity.MEDIUM,
            weight=1.0,
            rationale="Unintentional packet forwarding can expose isolated internal networks."
        ))

        validators.append(SysctlValidator(
            control_id="CIS-3.1.2",
            framework_name=self.name,
            title="Ensure packet redirect sending is disabled (net.ipv4.conf.all.send_redirects = 0)",
            description="Disables transmission of ICMP Redirect packets.",
            param_name="net.ipv4.conf.all.send_redirects",
            expected_value="0",
            severity=Severity.LOW,
            weight=1.0,
            rationale="ICMP redirects can be used in man-in-the-middle network spoofing."
        ))

        validators.append(SysctlValidator(
            control_id="CIS-3.2.1",
            framework_name=self.name,
            title="Ensure ICMP echo broadcast ignore is enabled",
            description="Ignores ICMP Echo requests directed to broadcast addresses.",
            param_name="net.ipv4.icmp_echo_ignore_broadcasts",
            expected_value="1",
            severity=Severity.MEDIUM,
            weight=1.0,
            rationale="Prevents the host from participating in network Smurf amplification attacks."
        ))

        validators.append(SysctlValidator(
            control_id="CIS-3.2.3",
            framework_name=self.name,
            title="Ensure Reverse Path Filtering is enabled (net.ipv4.conf.all.rp_filter = 1)",
            description="Enforces strict reverse path filtering to block spoofed packets.",
            param_name="net.ipv4.conf.all.rp_filter",
            expected_value="1",
            severity=Severity.HIGH,
            weight=1.2,
            rationale="Prevents IP address spoofing by verifying source route interfaces."
        ))

        validators.append(SysctlValidator(
            control_id="CIS-3.2.4",
            framework_name=self.name,
            title="Ensure TCP SYN Cookies is enabled (net.ipv4.tcp_syncookies = 1)",
            description="Mitigates TCP SYN Flood denial-of-service attacks.",
            param_name="net.ipv4.tcp_syncookies",
            expected_value="1",
            severity=Severity.HIGH,
            weight=1.2,
            rationale="Protects connection queues during volumetric SYN attacks."
        ))

        # CIS 3.4.1: Host Firewall Active
        validators.append(GenericEvidenceValidator(
            control_id="CIS-3.4.1",
            framework_name=self.name,
            title="Ensure a host firewall is installed and active (nftables, iptables, ufw, firewalld)",
            description="Verifies that host firewall packet filtering is active.",
            target_item="firewall_status",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("any_firewall_active")
                else ControlStatus.NON_COMPLIANT,
                "Active firewall daemon / ruleset",
                f"Firewall active: {ev.parsed_data.get('any_firewall_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now firewalld || systemctl enable --now ufw || systemctl enable --now nftables",
            rationale="A host firewall blocks unsolicited incoming connections and limits lateral movement."
        ))

        # ----------------------------------------------------
        # 4. Services Hardening (Unnecessary Services Disabled)
        # ----------------------------------------------------
        validators.append(ServiceStatusValidator(
            control_id="CIS-4.1.1",
            framework_name=self.name,
            title="Ensure telnet service is disabled",
            description="Telnet transmits authentication and session data in cleartext.",
            service_name="telnet.socket",
            expected_state="disabled",
            severity=Severity.HIGH,
            weight=1.0,
            rationale="Telnet credentials can be easily sniffed over the network."
        ))

        validators.append(ServiceStatusValidator(
            control_id="CIS-4.1.2",
            framework_name=self.name,
            title="Ensure rsh/rlogin/rexec legacy services are disabled",
            description="RSH protocols rely on unauthenticated trust relationships.",
            service_name="rsh.socket",
            expected_state="disabled",
            severity=Severity.HIGH,
            weight=1.0,
            rationale="Legacy R-commands are inherently insecure."
        ))

        # ----------------------------------------------------
        # 5. Access, Identity, PAM, and SSH
        # ----------------------------------------------------
        validators.append(GenericEvidenceValidator(
            control_id="CIS-5.1.1",
            framework_name=self.name,
            title="Ensure root is the only UID 0 account",
            description="Verifies that no secondary administrative accounts possess UID 0.",
            target_item="user_accounts_uid0",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("only_root_uid_zero")
                else ControlStatus.NON_COMPLIANT,
                "Only 'root' has UID 0",
                f"UID 0 accounts: {ev.parsed_data.get('uid_zero_accounts') if ev else 'N/A'}"
            ),
            remediation_cmd="Remove or change UID for non-root accounts found with UID 0 in /etc/passwd",
            rationale="Secondary UID 0 accounts bypass user accounting and privilege escalation audits."
        ))

        validators.append(GenericEvidenceValidator(
            control_id="CIS-5.1.2",
            framework_name=self.name,
            title="Ensure password fields are not empty in /etc/shadow",
            description="Ensures all non-locked accounts have a secure password hash.",
            target_item="shadow_passwords_audit",
            severity=Severity.CRITICAL,
            weight=2.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not ev.parsed_data.get("has_empty_passwords", True)
                else ControlStatus.NON_COMPLIANT,
                "0 accounts with empty passwords",
                f"Empty pw users: {ev.parsed_data.get('empty_password_users') if ev else 'N/A'}"
            ),
            remediation_cmd="passwd -l <user> for any empty account",
            rationale="Accounts without passwords allow unauthenticated local and remote access."
        ))

        validators.append(SudoersValidator(
            control_id="CIS-5.1.3",
            framework_name=self.name,
            title="Ensure sudo commands require authentication (No unrestricted NOPASSWD)",
            description="Restricts unrestricted NOPASSWD directives in sudoers.",
            check_type="no_nopasswd",
            severity=Severity.HIGH,
            weight=1.5,
            rationale="NOPASSWD allows a compromised process to immediately escalate to root."
        ))

        validators.append(SSHSettingValidator(
            control_id="CIS-5.2.1",
            framework_name=self.name,
            title="Ensure SSH PermitRootLogin is disabled or prohibit-password",
            description="Disallows direct root logins over OpenSSH.",
            setting_key="permitrootlogin",
            expected_values=["no", "prohibit-password"],
            severity=Severity.HIGH,
            weight=1.5,
            rationale="Disabling direct root login enforces individual account accountability via sudo."
        ))

        validators.append(SSHSettingValidator(
            control_id="CIS-5.2.3",
            framework_name=self.name,
            title="Ensure SSH PermitEmptyPasswords is disabled",
            description="Prevents logging in through SSH with accounts that have empty passwords.",
            setting_key="permitemptypasswords",
            expected_values=["no"],
            severity=Severity.CRITICAL,
            weight=2.0,
            rationale="PermitEmptyPasswords permits unauthenticated remote logins."
        ))

        validators.append(SSHSettingValidator(
            control_id="CIS-5.2.5",
            framework_name=self.name,
            title="Ensure SSH MaxAuthTries is configured to 4 or less",
            description="Limits the maximum number of authentication attempts per connection.",
            setting_key="maxauthtries",
            expected_values=["1", "2", "3", "4"],
            severity=Severity.MEDIUM,
            weight=1.0,
            rationale="Mitigates brute-force password guessing attacks against OpenSSH."
        ))

        validators.append(GenericEvidenceValidator(
            control_id="CIS-5.2.7",
            framework_name=self.name,
            title="Ensure SSH weak Ciphers, MACs, and Kex algorithms are disabled",
            description="Enforces modern cryptography (ChaCha20, AES-GCM, SHA-2, Curve25519) on SSH server.",
            target_item="ssh_server_configuration",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and not (ev.parsed_data.get("has_weak_ciphers") or ev.parsed_data.get("has_weak_macs") or ev.parsed_data.get("has_weak_kex"))
                else ControlStatus.NON_COMPLIANT,
                "No CBC ciphers, MD5/SHA1 MACs, or weak DH groups",
                f"Weak Ciphers: {ev.parsed_data.get('has_weak_ciphers') if ev else 'N/A'}"
            ),
            remediation_cmd="Configure modern Ciphers and KexAlgorithms in /etc/ssh/sshd_config.d/01-crypto.conf",
            rationale="Legacy cryptographic primitives are vulnerable to eavesdropping and downgrade attacks."
        ))

        # ----------------------------------------------------
        # 6. Logging, Auditing, and Integrity
        # ----------------------------------------------------
        validators.append(GenericEvidenceValidator(
            control_id="CIS-6.1.1",
            framework_name=self.name,
            title="Ensure auditd service is enabled and active",
            description="The Linux Audit Framework records security-relevant system events and system calls.",
            target_item="auditd_rules_and_status",
            severity=Severity.HIGH,
            weight=1.5,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("auditd_service_active")
                else ControlStatus.NON_COMPLIANT,
                "auditd service active and running",
                f"auditd active: {ev.parsed_data.get('auditd_service_active') if ev else False}"
            ),
            remediation_cmd="systemctl enable --now auditd",
            rationale="Without auditd, forensic investigation of privilege escalations is hindered."
        ))

        validators.append(GenericEvidenceValidator(
            control_id="CIS-6.2.1",
            framework_name=self.name,
            title="Ensure AIDE File Integrity Monitoring (FIM) is installed and initialized",
            description="Verifies baseline integrity database for system binaries and configuration files.",
            target_item="aide_fim_status",
            severity=Severity.MEDIUM,
            weight=1.0,
            eval_fn=lambda ev, ctx: (
                ControlStatus.COMPLIANT if ev and ev.parsed_data.get("aide_installed") and ev.parsed_data.get("database_present")
                else (ControlStatus.PARTIAL if ev and ev.parsed_data.get("aide_installed") else ControlStatus.NON_COMPLIANT),
                "AIDE installed and database initialized",
                f"Installed: {ev.parsed_data.get('aide_installed') if ev else False}, DB: {ev.parsed_data.get('database_present') if ev else False}"
            ),
            remediation_cmd="apt-get install aide || dnf install aide && aideinit",
            rationale="FIM detects unauthorized modifications and rootkits altering core system binaries."
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
