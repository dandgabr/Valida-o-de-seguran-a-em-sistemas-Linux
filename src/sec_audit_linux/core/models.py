"""Core data models for security assessment, evidence collection, and compliance scoring."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Any, Optional
import json
import uuid
from datetime import datetime, timezone


class Severity(str, Enum):
    """Severity levels for findings and compliance controls."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ControlStatus(str, Enum):
    """Evaluation status of an audited security control."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    MANUAL_CHECK = "manual_check"
    ERROR = "error"


class OSFamily(str, Enum):
    """Supported Linux operating system families."""
    REDHAT = "redhat"       # RHEL, Rocky, Alma, Oracle, CentOS, Fedora
    DEBIAN = "debian"       # Debian, Ubuntu, Linux Mint
    SUSE = "suse"           # SLES, openSUSE Leap, openSUSE Tumbleweed
    ARCH = "arch"           # Arch Linux, Manjaro
    ALPINE = "alpine"       # Alpine Linux
    UNKNOWN = "unknown"


class ToolExecutionStatus(str, Enum):
    """Execution status of an integrated security tool."""
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class SystemContext:
    """Metadata representing the audited target host and environment."""
    hostname: str
    ip_addresses: List[str] = field(default_factory=list)
    os_family: OSFamily = OSFamily.UNKNOWN
    os_name: str = "Unknown Linux"
    os_version: str = "0.0"
    os_id: str = "linux"
    os_codename: str = ""
    kernel_release: str = ""
    architecture: str = ""
    init_system: str = "systemd"
    is_root: bool = False
    is_container: bool = False
    virtualization: str = "none"
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceRecord:
    """Tamper-evident record of a low-level technical evidence collected from the system."""
    collector_name: str
    target_item: str
    evidence_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    command_executed: Optional[str] = None
    raw_output: str = ""
    parsed_data: Dict[str, Any] = field(default_factory=dict)
    sha256_checksum: str = ""
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ControlEvaluation:
    """Evaluation result of a single security control against gathered evidences."""
    control_id: str
    framework_name: str
    title: str
    description: str
    status: ControlStatus
    severity: Severity = Severity.MEDIUM
    weight: float = 1.0
    expected_condition: str = ""
    actual_condition: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    remediation_cmd: Optional[str] = None
    remediation_guide: str = ""
    rationale: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass
class ToolReport:
    """Individual deep analysis report produced by an integrated open-source security tool."""
    tool_name: str
    tool_category: str
    license: str
    is_installed: bool
    version: str = "unknown"
    status: ToolExecutionStatus = ToolExecutionStatus.INSTALLED
    execution_time_seconds: float = 0.0
    summary_metrics: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    raw_output: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class UnifiedFinding:
    """Deduplicated, correlated security finding merging evidence from tools and manual controls."""
    finding_id: str
    topic: str
    title: str
    severity: Severity
    description: str
    sources: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    actual_value: str = ""
    expected_value: str = ""
    remediation_cmd: Optional[str] = None
    remediation_guide: str = ""
    related_cves: List[str] = field(default_factory=list)
    is_manual_check: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class FrameworkResult:
    """Consolidated assessment outcome for a specific regulatory/security framework."""
    framework_id: str
    framework_name: str
    version: str
    adherence_percentage: float
    total_controls: int = 0
    compliant_count: int = 0
    non_compliant_count: int = 0
    partial_count: int = 0
    manual_count: int = 0
    not_applicable_count: int = 0
    error_count: int = 0
    evaluations: List[ControlEvaluation] = field(default_factory=list)
    summary_by_severity: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evaluations"] = [e.to_dict() for e in self.evaluations]
        return data


@dataclass
class AssessmentResult:
    """Top-level assessment result containing framework results, tool reports, unified findings, and context."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    system_context: Optional[SystemContext] = None
    overall_score: float = 0.0
    frameworks: Dict[str, FrameworkResult] = field(default_factory=dict)
    tools_reports: Dict[str, ToolReport] = field(default_factory=dict)
    unified_findings: List[UnifiedFinding] = field(default_factory=list)
    total_evidences: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "system_context": self.system_context.to_dict() if self.system_context else None,
            "overall_score": self.overall_score,
            "frameworks": {k: v.to_dict() for k, v in self.frameworks.items()},
            "tools_reports": {k: v.to_dict() for k, v in self.tools_reports.items()},
            "unified_findings": [f.to_dict() for f in self.unified_findings],
            "total_evidences": self.total_evidences,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
