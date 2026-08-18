"""Control Validators Module.

Defines specialized validator classes that extract evidence from the EvidenceStore,
compare actual system states against expected baselines, and produce normalized ControlEvaluations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Callable
from sec_audit_linux.core.models import (
    ControlEvaluation,
    ControlStatus,
    Severity,
    EvidenceRecord,
    SystemContext
)
from sec_audit_linux.core.evidence_manager import EvidenceStore


class BaseValidator(ABC):
    """Abstract base validator for a specific security control."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        severity: Severity = Severity.MEDIUM,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        self.control_id = control_id
        self.framework_name = framework_name
        self.title = title
        self.description = description
        self.severity = severity
        self.weight = weight
        self.rationale = rationale
        self.remediation_cmd = remediation_cmd
        self.tags = tags or []

    @abstractmethod
    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        """Extracts evidence, compares actual against expected, and returns ControlEvaluation."""
        pass


class SysctlValidator(BaseValidator):
    """Validates kernel runtime sysctl parameters against expected values or allowable sets."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        param_name: str,
        expected_value: Union[str, List[str]],
        operator: str = "eq",  # "eq", "in", "gte", "lte"
        severity: Severity = Severity.MEDIUM,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=remediation_cmd or f"sysctl -w {param_name}={expected_value if isinstance(expected_value, str) else expected_value[0]} && echo '{param_name} = {expected_value if isinstance(expected_value, str) else expected_value[0]}' >> /etc/sysctl.d/99-security.conf",
            tags=tags or ["Kernel", "Sysctl"]
        )
        self.param_name = param_name
        self.expected_value = expected_value
        self.operator = operator

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev = evidence_store.get_by_target("kernel_sysctl_runtime")
        if not ev:
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.ERROR,
                severity=self.severity,
                weight=self.weight,
                expected_condition=f"{self.param_name} = {self.expected_value}",
                actual_condition="Sysctl evidence not available",
                rationale=self.rationale,
                tags=self.tags
            )

        evidence_record = ev[0]
        actual_val = evidence_record.parsed_data.get(self.param_name, "unset")

        # Compare actual vs expected
        is_compliant = False
        if self.operator == "eq":
            is_compliant = str(actual_val) == str(self.expected_value)
        elif self.operator == "in":
            is_compliant = str(actual_val) in [str(x) for x in self.expected_value]
        elif self.operator == "lte":
            try:
                is_compliant = int(actual_val) <= int(self.expected_value)
            except ValueError:
                is_compliant = False
        elif self.operator == "gte":
            try:
                is_compliant = int(actual_val) >= int(self.expected_value)
            except ValueError:
                is_compliant = False

        status = ControlStatus.COMPLIANT if is_compliant else ControlStatus.NON_COMPLIANT

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=status,
            severity=self.severity,
            weight=self.weight,
            expected_condition=f"{self.param_name} = {self.expected_value}",
            actual_condition=f"{self.param_name} = {actual_val}",
            evidence_refs=[evidence_record.evidence_id],
            remediation_cmd=self.remediation_cmd,
            rationale=self.rationale,
            tags=self.tags
        )


class FilePermissionValidator(BaseValidator):
    """Validates file permissions (octal mode) and ownership (UID/GID) for sensitive files."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        file_path: str,
        expected_modes: List[str],
        expected_uid: int = 0,
        severity: Severity = Severity.HIGH,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        fix_cmd = remediation_cmd or f"chmod {expected_modes[0]} {file_path} && chown {expected_uid}:0 {file_path}"
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=fix_cmd,
            tags=tags or ["Permissions", "Filesystem"]
        )
        self.file_path = file_path
        self.expected_modes = expected_modes
        self.expected_uid = expected_uid

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev = evidence_store.get_by_target("critical_file_permissions")
        if not ev:
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.ERROR,
                severity=self.severity,
                weight=self.weight,
                expected_condition=f"{self.file_path} mode in {self.expected_modes} owned by UID {self.expected_uid}",
                actual_condition="File permission evidence not available",
                rationale=self.rationale,
                tags=self.tags
            )

        evidence_record = ev[0]
        audited_files = evidence_record.parsed_data.get("audited_files", [])
        
        target_file_data = next((f for f in audited_files if f["path"] == self.file_path), None)
        if not target_file_data:
            # File does not exist on this distribution
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.NOT_APPLICABLE,
                severity=self.severity,
                weight=self.weight,
                expected_condition=f"{self.file_path} exists and is secured",
                actual_condition=f"File {self.file_path} does not exist on target",
                evidence_refs=[evidence_record.evidence_id],
                rationale=self.rationale,
                tags=self.tags
            )

        stat_info = target_file_data.get("stat", {})
        actual_mode = stat_info.get("mode_octal", "")
        actual_uid = stat_info.get("uid", -1)

        is_mode_ok = actual_mode in self.expected_modes
        is_uid_ok = actual_uid == self.expected_uid
        is_compliant = is_mode_ok and is_uid_ok

        status = ControlStatus.COMPLIANT if is_compliant else ControlStatus.NON_COMPLIANT

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=status,
            severity=self.severity,
            weight=self.weight,
            expected_condition=f"{self.file_path} mode in {self.expected_modes} owned by UID {self.expected_uid}",
            actual_condition=f"{self.file_path} mode={actual_mode}, UID={actual_uid}",
            evidence_refs=[evidence_record.evidence_id],
            remediation_cmd=self.remediation_cmd,
            rationale=self.rationale,
            tags=self.tags
        )


class SSHSettingValidator(BaseValidator):
    """Validates OpenSSH server configurations against security baseline parameters."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        setting_key: str,
        expected_values: List[str],
        severity: Severity = Severity.HIGH,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        fix_cmd = remediation_cmd or f"echo '{setting_key} {expected_values[0]}' >> /etc/ssh/sshd_config.d/01-hardening.conf && systemctl reload sshd"
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=fix_cmd,
            tags=tags or ["SSH", "Access Control"]
        )
        self.setting_key = setting_key.lower()
        self.expected_values = [v.lower() for v in expected_values]

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev = evidence_store.get_by_target("ssh_server_configuration")
        if not ev:
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.ERROR,
                severity=self.severity,
                weight=self.weight,
                expected_condition=f"sshd {self.setting_key} in {self.expected_values}",
                actual_condition="SSH evidence not available",
                rationale=self.rationale,
                tags=self.tags
            )

        evidence_record = ev[0]
        actual_val = str(evidence_record.parsed_data.get(self.setting_key, "unset")).lower()

        is_compliant = actual_val in self.expected_values
        status = ControlStatus.COMPLIANT if is_compliant else ControlStatus.NON_COMPLIANT

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=status,
            severity=self.severity,
            weight=self.weight,
            expected_condition=f"{self.setting_key} in {self.expected_values}",
            actual_condition=f"{self.setting_key} = {actual_val}",
            evidence_refs=[evidence_record.evidence_id],
            remediation_cmd=self.remediation_cmd,
            rationale=self.rationale,
            tags=self.tags
        )


class ServiceStatusValidator(BaseValidator):
    """Validates that unneeded/insecure services are disabled or masked."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        service_name: str,
        expected_state: str = "disabled",  # "disabled", "masked", "active"
        severity: Severity = Severity.HIGH,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        fix_cmd = remediation_cmd or f"systemctl stop {service_name} && systemctl disable {service_name} && systemctl mask {service_name}"
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=fix_cmd,
            tags=tags or ["Services", "Systemd"]
        )
        self.service_name = service_name
        self.expected_state = expected_state

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev = evidence_store.get_by_target("unnecessary_services")
        if not ev:
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.ERROR,
                severity=self.severity,
                weight=self.weight,
                expected_condition=f"{self.service_name} is {self.expected_state}",
                actual_condition="Service evidence not available",
                rationale=self.rationale,
                tags=self.tags
            )

        evidence_record = ev[0]
        actual_state = evidence_record.parsed_data.get(self.service_name, "disabled_or_not_found").lower()

        if self.expected_state in ["disabled", "masked"]:
            is_compliant = (
                "disabled" in actual_state
                or "not_found" in actual_state
                or "not-found" in actual_state
                or "masked" in actual_state
                or "inactive" in actual_state
            )
        else:
            is_compliant = self.expected_state in actual_state

        status = ControlStatus.COMPLIANT if is_compliant else ControlStatus.NON_COMPLIANT

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=status,
            severity=self.severity,
            weight=self.weight,
            expected_condition=f"{self.service_name} should be {self.expected_state}",
            actual_condition=f"{self.service_name} is {actual_state}",
            evidence_refs=[evidence_record.evidence_id],
            remediation_cmd=self.remediation_cmd,
            rationale=self.rationale,
            tags=self.tags
        )


class SudoersValidator(BaseValidator):
    """Validates sudoers configuration for NOPASSWD directives, wildcards, and security flags."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        check_type: str = "no_nopasswd",  # "no_nopasswd", "no_wildcards"
        severity: Severity = Severity.HIGH,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=remediation_cmd or "Remove unrestricted NOPASSWD entries from /etc/sudoers and /etc/sudoers.d/*",
            tags=tags or ["Sudo", "Privilege Escalation"]
        )
        self.check_type = check_type

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev = evidence_store.get_by_target("sudoers_privilege_audit")
        if not ev:
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=ControlStatus.ERROR,
                severity=self.severity,
                weight=self.weight,
                expected_condition="Sudoers rules require re-authentication",
                actual_condition="Sudoers evidence not available",
                rationale=self.rationale,
                tags=self.tags
            )

        evidence_record = ev[0]
        data = evidence_record.parsed_data

        if self.check_type == "no_nopasswd":
            has_nopasswd = data.get("has_nopasswd", False)
            nopasswd_count = len(data.get("nopasswd_entries", []))
            status = ControlStatus.COMPLIANT if not has_nopasswd else ControlStatus.PARTIAL
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=status,
                severity=self.severity,
                weight=self.weight,
                expected_condition="No unrestricted NOPASSWD in sudoers",
                actual_condition=f"NOPASSWD entries found: {nopasswd_count}",
                evidence_refs=[evidence_record.evidence_id],
                remediation_cmd=self.remediation_cmd,
                rationale=self.rationale,
                tags=self.tags
            )
        elif self.check_type == "no_wildcards":
            has_wildcards = data.get("has_full_nopasswd_all", False)
            status = ControlStatus.COMPLIANT if not has_wildcards else ControlStatus.NON_COMPLIANT
            return ControlEvaluation(
                control_id=self.control_id,
                framework_name=self.framework_name,
                title=self.title,
                description=self.description,
                status=status,
                severity=self.severity,
                weight=self.weight,
                expected_condition="No ALL=(ALL) NOPASSWD: ALL entries",
                actual_condition=f"Unrestricted ALL=(ALL) NOPASSWD present: {has_wildcards}",
                evidence_refs=[evidence_record.evidence_id],
                remediation_cmd=self.remediation_cmd,
                rationale=self.rationale,
                tags=self.tags
            )

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=ControlStatus.ERROR,
            severity=self.severity,
            weight=self.weight,
            expected_condition="Valid check type",
            actual_condition=f"Unknown check type: {self.check_type}",
            rationale=self.rationale,
            tags=self.tags
        )


class GenericEvidenceValidator(BaseValidator):
    """Flexible validator executing a custom evaluation callback against an EvidenceRecord."""

    def __init__(
        self,
        control_id: str,
        framework_name: str,
        title: str,
        description: str,
        target_item: str,
        eval_fn: Callable[[Optional[EvidenceRecord], SystemContext], tuple[ControlStatus, str, str]],
        severity: Severity = Severity.MEDIUM,
        weight: float = 1.0,
        rationale: str = "",
        remediation_cmd: Optional[str] = None,
        tags: Optional[List[str]] = None
    ):
        super().__init__(
            control_id=control_id,
            framework_name=framework_name,
            title=title,
            description=description,
            severity=severity,
            weight=weight,
            rationale=rationale,
            remediation_cmd=remediation_cmd,
            tags=tags or []
        )
        self.target_item = target_item
        self.eval_fn = eval_fn

    def evaluate(self, evidence_store: EvidenceStore, context: SystemContext) -> ControlEvaluation:
        ev_list = evidence_store.get_by_target(self.target_item)
        ev_record = ev_list[0] if ev_list else None

        status, expected_cond, actual_cond = self.eval_fn(ev_record, context)

        return ControlEvaluation(
            control_id=self.control_id,
            framework_name=self.framework_name,
            title=self.title,
            description=self.description,
            status=status,
            severity=self.severity,
            weight=self.weight,
            expected_condition=expected_cond,
            actual_condition=actual_cond,
            evidence_refs=[ev_record.evidence_id] if ev_record else [],
            remediation_cmd=self.remediation_cmd,
            rationale=self.rationale,
            tags=self.tags
        )
