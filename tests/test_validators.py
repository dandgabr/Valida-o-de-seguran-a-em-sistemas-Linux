"""Unit tests for specialized Control Validators."""

import unittest
from sec_audit_linux.core.models import SystemContext, EvidenceRecord, ControlStatus, Severity, OSFamily
from sec_audit_linux.core.evidence_manager import EvidenceStore
from sec_audit_linux.core.validators import (
    SysctlValidator,
    FilePermissionValidator,
    SSHSettingValidator,
    ServiceStatusValidator,
    SudoersValidator
)


class TestControlValidators(unittest.TestCase):

    def setUp(self):
        self.context = SystemContext(hostname="test-host", os_family=OSFamily.DEBIAN)
        self.store = EvidenceStore()

        # Add sysctl evidence
        self.store.add_record(EvidenceRecord(
            collector_name="system",
            target_item="kernel_sysctl_runtime",
            parsed_data={
                "kernel.randomize_va_space": "2",
                "net.ipv4.ip_forward": "1"
            }
        ))

        # Add critical file permissions evidence
        self.store.add_record(EvidenceRecord(
            collector_name="access_control",
            target_item="critical_file_permissions",
            parsed_data={
                "audited_files": [
                    {"path": "/etc/passwd", "stat": {"mode_octal": "0644", "uid": 0}},
                    {"path": "/etc/shadow", "stat": {"mode_octal": "0666", "uid": 0}}
                ]
            }
        ))

        # Add SSH evidence
        self.store.add_record(EvidenceRecord(
            collector_name="ssh",
            target_item="ssh_server_configuration",
            parsed_data={
                "permitrootlogin": "no",
                "maxauthtries": "6"
            }
        ))

        # Add unnecessary services evidence
        self.store.add_record(EvidenceRecord(
            collector_name="system",
            target_item="unnecessary_services",
            parsed_data={
                "telnet.socket": "disabled",
                "vsftpd.service": "enabled"
            }
        ))

        # Add sudoers evidence
        self.store.add_record(EvidenceRecord(
            collector_name="identity",
            target_item="sudoers_privilege_audit",
            parsed_data={
                "has_nopasswd": True,
                "nopasswd_entries": ["%admin ALL=(ALL) NOPASSWD: ALL"],
                "has_full_nopasswd_all": True
            }
        ))

    def test_sysctl_validator(self):
        v1 = SysctlValidator(
            control_id="TEST-ASLR",
            framework_name="TEST",
            title="ASLR Test",
            description="Test ASLR",
            param_name="kernel.randomize_va_space",
            expected_value="2"
        )
        res1 = v1.evaluate(self.store, self.context)
        self.assertEqual(res1.status, ControlStatus.COMPLIANT)

        v2 = SysctlValidator(
            control_id="TEST-IP-FWD",
            framework_name="TEST",
            title="IP Forward Test",
            description="Test IP Forward",
            param_name="net.ipv4.ip_forward",
            expected_value="0"
        )
        res2 = v2.evaluate(self.store, self.context)
        self.assertEqual(res2.status, ControlStatus.NON_COMPLIANT)
        self.assertEqual(res2.actual_condition, "net.ipv4.ip_forward = 1")

    def test_file_permission_validator(self):
        v_passwd = FilePermissionValidator(
            control_id="TEST-PASSWD",
            framework_name="TEST",
            title="Passwd Perms",
            description="Test passwd mode",
            file_path="/etc/passwd",
            expected_modes=["0644"],
            expected_uid=0
        )
        res_passwd = v_passwd.evaluate(self.store, self.context)
        self.assertEqual(res_passwd.status, ControlStatus.COMPLIANT)

        v_shadow = FilePermissionValidator(
            control_id="TEST-SHADOW",
            framework_name="TEST",
            title="Shadow Perms",
            description="Test shadow mode",
            file_path="/etc/shadow",
            expected_modes=["0000", "0600", "0640"],
            expected_uid=0
        )
        res_shadow = v_shadow.evaluate(self.store, self.context)
        self.assertEqual(res_shadow.status, ControlStatus.NON_COMPLIANT)

    def test_ssh_setting_validator(self):
        v_root = SSHSettingValidator(
            control_id="TEST-SSH-ROOT",
            framework_name="TEST",
            title="SSH Root",
            description="Test root login",
            setting_key="permitrootlogin",
            expected_values=["no", "prohibit-password"]
        )
        res_root = v_root.evaluate(self.store, self.context)
        self.assertEqual(res_root.status, ControlStatus.COMPLIANT)

        v_tries = SSHSettingValidator(
            control_id="TEST-SSH-TRIES",
            framework_name="TEST",
            title="SSH Auth Tries",
            description="Test auth tries",
            setting_key="maxauthtries",
            expected_values=["1", "2", "3", "4"]
        )
        res_tries = v_tries.evaluate(self.store, self.context)
        self.assertEqual(res_tries.status, ControlStatus.NON_COMPLIANT)

    def test_service_validator(self):
        v_telnet = ServiceStatusValidator(
            control_id="TEST-TELNET",
            framework_name="TEST",
            title="Telnet Disabled",
            description="Test telnet disabled",
            service_name="telnet.socket",
            expected_state="disabled"
        )
        res_telnet = v_telnet.evaluate(self.store, self.context)
        self.assertEqual(res_telnet.status, ControlStatus.COMPLIANT)

        v_ftp = ServiceStatusValidator(
            control_id="TEST-FTP",
            framework_name="TEST",
            title="FTP Disabled",
            description="Test ftp disabled",
            service_name="vsftpd.service",
            expected_state="disabled"
        )
        res_ftp = v_ftp.evaluate(self.store, self.context)
        self.assertEqual(res_ftp.status, ControlStatus.NON_COMPLIANT)

    def test_sudoers_validator(self):
        v_sudo = SudoersValidator(
            control_id="TEST-SUDO",
            framework_name="TEST",
            title="Sudo NOPASSWD",
            description="Test sudo NOPASSWD",
            check_type="no_nopasswd"
        )
        res_sudo = v_sudo.evaluate(self.store, self.context)
        self.assertEqual(res_sudo.status, ControlStatus.PARTIAL)


if __name__ == "__main__":
    unittest.main()
