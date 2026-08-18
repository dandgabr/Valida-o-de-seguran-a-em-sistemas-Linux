"""Finding Deduplication and Multi-Source Correlation Engine."""

from typing import Dict, List, Any, Optional
from sec_audit_linux.core.models import (
    FrameworkResult,
    ToolReport,
    UnifiedFinding,
    ControlEvaluation,
    ControlStatus,
    Severity
)


class FindingDeduplicator:
    """Consolidates and deduplicates security findings across frameworks and tools."""

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1
    }

    @staticmethod
    def _extract_topic_key(evaluation: ControlEvaluation) -> str:
        """Determines normalization topic key from a control evaluation."""
        cid = evaluation.control_id.upper()
        title = evaluation.title.lower()

        if "suid_dumpable" in title or "suid_dumpable" in cid:
            return "kernel:suid_dumpable"
        if "randomize_va_space" in title or "aslr" in title:
            return "kernel:aslr"
        if "ptrace_scope" in title:
            return "kernel:ptrace_scope"
        if "ip_forward" in title:
            return "network:ip_forward"
        if "rp_filter" in title:
            return "network:rp_filter"
        if "redirect" in title:
            return "network:redirects"
        if "syn" in title and "cookies" in title:
            return "network:syncookies"
        if "firewall" in title or "nftables" in title or "ufw" in title:
            return "network:firewall"
        if "permitrootlogin" in title or "direct root" in title:
            return "ssh:permit_root_login"
        if "permitemptypasswords" in title or "empty passwords" in title:
            return "auth:empty_passwords"
        if "maxauthtries" in title:
            return "ssh:max_auth_tries"
        if "uid 0" in title or "root is the only" in title or "dedicated accounts" in title:
            return "auth:uid_zero_governance"
        if "sudo" in title or "nopasswd" in title:
            return "auth:sudo_privileges"
        if "auditd" in title or "audit" in title:
            return "logging:auditd"
        if "aide" in title or "fim" in title or "integrity" in title:
            return "integrity:fim_aide"
        if "selinux" in title or "apparmor" in title:
            return "access_control:mac"
        if "/etc/passwd" in title:
            return "file_perm:/etc/passwd"
        if "/etc/shadow" in title:
            return "file_perm:/etc/shadow"
        if "/etc/sudoers" in title:
            return "file_perm:/etc/sudoers"
        if "docker" in title or "container" in title:
            return "container:docker_security"

        return f"generic:{evaluation.control_id}"

    @classmethod
    def deduplicate_and_correlate(
        cls,
        frameworks: Dict[str, FrameworkResult],
        tools_reports: Dict[str, ToolReport]
    ) -> List[UnifiedFinding]:
        """
        Deduplicates overlapping findings from frameworks, native evaluators, and external tools,
        merging them into a unified, traceable ledger.
        """
        findings_map: Dict[str, UnifiedFinding] = {}

        # 1. Process Framework Evaluations
        for fw_id, fw in frameworks.items():
            for ev in fw.evaluations:
                if ev.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL, ControlStatus.MANUAL_CHECK]:
                    topic_key = cls._extract_topic_key(ev)
                    source_label = f"{fw.framework_name} ({ev.control_id})"

                    if topic_key not in findings_map:
                        finding_id = f"FIND-{topic_key.replace(':', '-').replace('/', '-').upper()}"
                        findings_map[topic_key] = UnifiedFinding(
                            finding_id=finding_id,
                            topic=topic_key.split(":")[0].replace("_", " ").title(),
                            title=ev.title,
                            severity=ev.severity,
                            description=ev.description,
                            sources=[source_label],
                            affected_components=[ev.framework_name],
                            actual_value=ev.actual_condition,
                            expected_value=ev.expected_condition,
                            remediation_cmd=ev.remediation_cmd,
                            remediation_guide=ev.rationale or ev.description,
                            is_manual_check=ev.status == ControlStatus.MANUAL_CHECK
                        )
                    else:
                        # Merge finding
                        existing = findings_map[topic_key]
                        if source_label not in existing.sources:
                            existing.sources.append(source_label)
                        # Keep highest severity
                        if cls.SEVERITY_WEIGHTS.get(ev.severity, 0) > cls.SEVERITY_WEIGHTS.get(existing.severity, 0):
                            existing.severity = ev.severity
                        if ev.remediation_cmd and not existing.remediation_cmd:
                            existing.remediation_cmd = ev.remediation_cmd

        # 2. Correlate External Tools Findings
        for t_name, t_rep in tools_reports.items():
            if not t_rep.is_installed:
                continue

            for f in t_rep.findings:
                # Docker bench findings
                if t_name == "docker_bench":
                    c_status = f.get("status", "")
                    if c_status in ["WARN", "FAIL"]:
                        t_key = f"docker:{f.get('check', 'runtime')}"
                        src = f"Docker Bench ({f.get('check', 'CIS-Docker')})"
                        if t_key not in findings_map:
                            findings_map[t_key] = UnifiedFinding(
                                finding_id=f"FIND-DOCKER-{f.get('check', 'WARN')}",
                                topic="Container Security",
                                title=f.get("title", f.get("description", "Docker Security Finding")),
                                severity=Severity.HIGH if "WARN" in c_status else Severity.MEDIUM,
                                description=f.get("details", f.get("description", "")),
                                sources=[src],
                                affected_components=["Docker Daemon / Containers"],
                                actual_value="Misconfigured setting detected by Docker Bench",
                                expected_value="CIS Docker Benchmark compliance",
                                remediation_guide="Review docker daemon.json and container runtime options."
                            )
                        else:
                            if src not in findings_map[t_key].sources:
                                findings_map[t_key].sources.append(src)

                # Trivy & Grype CVE findings
                elif t_name in ["trivy", "grype"]:
                    cve_id = f.get("cve_id") or f.get("id")
                    if cve_id:
                        t_key = f"cve:{cve_id}"
                        src = f"{t_name.upper()} ({cve_id})"
                        pkg = f.get("package", "system_package")
                        sev_str = f.get("severity", "MEDIUM").upper()
                        sev = Severity.CRITICAL if sev_str == "CRITICAL" else (Severity.HIGH if sev_str == "HIGH" else Severity.MEDIUM)
                        
                        if t_key not in findings_map:
                            findings_map[t_key] = UnifiedFinding(
                                finding_id=f"FIND-{cve_id}",
                                topic="Software Vulnerability",
                                title=f"Vulnerability {cve_id} in {pkg}",
                                severity=sev,
                                description=f.get("title", f"Known security vulnerability in {pkg}"),
                                sources=[src],
                                affected_components=[pkg],
                                actual_value=f"Installed version: {f.get('installed_version', f.get('version', 'unknown'))}",
                                expected_value=f"Fixed version: {f.get('fixed_version', f.get('fix_versions', 'available'))}",
                                remediation_cmd=f"apt-get install --only-upgrade {pkg} || dnf upgrade {pkg}",
                                related_cves=[cve_id]
                            )
                        else:
                            if src not in findings_map[t_key].sources:
                                findings_map[t_key].sources.append(src)

        # Sort by severity descending
        sorted_findings = sorted(
            list(findings_map.values()),
            key=lambda x: cls.SEVERITY_WEIGHTS.get(x.severity, 0),
            reverse=True
        )

        return sorted_findings
