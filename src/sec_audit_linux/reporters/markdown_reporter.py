"""Markdown Report Generator for Executive and Technical Audiences."""

from typing import Dict, Any, List
from sec_audit_linux.core.models import (
    AssessmentResult,
    FrameworkResult,
    ControlEvaluation,
    ControlStatus,
    Severity,
    ToolReport,
    UnifiedFinding
)


class MarkdownReporter:
    """Generates formatted executive and technical Markdown reports."""

    @staticmethod
    def _render_progress_bar(percentage: float, width: int = 20) -> str:
        """Renders an ASCII progress bar (e.g., [██████████░░░░░░░░░░] 50%)."""
        filled = int(round(width * percentage / 100))
        bar = "█" * filled + "░" * (width - filled)
        return f"`[{bar}] {percentage:.1f}%`"

    @staticmethod
    def generate_executive_report(result: AssessmentResult) -> str:
        """Generates high-level executive report with posture KPI, tool summaries, and deduplicated findings."""
        ctx = result.system_context
        lines = []

        lines.append("# 🛡️ Executive Security & Compliance Assessment Report")
        lines.append("")
        lines.append(f"> **Overall System Compliance Score:** **{result.overall_score:.1f}%**")
        lines.append(f"> Generated at: `{result.completed_at or result.started_at}` | Assessment ID: `{result.assessment_id}`")
        lines.append("")

        # 1. System Metadata
        lines.append("## 🖥️ System Metadata")
        lines.append("")
        lines.append("| Property | Value |")
        lines.append("| :--- | :--- |")
        if ctx:
            lines.append(f"| **Hostname** | `{ctx.hostname}` |")
            lines.append(f"| **Operating System** | `{ctx.os_name} {ctx.os_version}` (`{ctx.os_family.value}`) |")
            lines.append(f"| **Kernel Release** | `{ctx.kernel_release}` (`{ctx.architecture}`) |")
            lines.append(f"| **Init System** | `{ctx.init_system}` |")
            lines.append(f"| **Environment** | `{'Container' if ctx.is_container else 'Bare Metal / VM'} ({ctx.virtualization})` |")
            lines.append(f"| **IP Addresses** | `{', '.join(ctx.ip_addresses)}` |")
        lines.append(f"| **Total Evidences Gathered** | `{result.total_evidences}` |")
        lines.append(f"| **Deduplicated Security Findings** | `{len(result.unified_findings)}` |")
        lines.append(f"| **Assessment Duration** | `{result.duration_seconds}s` |")
        lines.append("")

        # 2. Compliance Scoreboard by Framework
        lines.append("## 📊 Compliance Scoreboard by Framework")
        lines.append("")
        lines.append("| Framework | Version | Adherence Score | Compliant | Non-Compliant | Partial | Total Controls |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

        for fw_id, fw in result.frameworks.items():
            bar = MarkdownReporter._render_progress_bar(fw.adherence_percentage)
            lines.append(
                f"| **{fw.framework_name}** | `{fw.version}` | {bar} | "
                f"`{fw.compliant_count}` | `{fw.non_compliant_count}` | `{fw.partial_count}` | `{fw.total_controls}` |"
            )
        lines.append("")

        # 3. Integrated Open-Source Security Tools Status
        if result.tools_reports:
            lines.append("## 🛠️ Integrated Open-Source Security Tools Status")
            lines.append("")
            lines.append("| Tool | Category | License | Status | Key Metrics |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for t_name, t_rep in result.tools_reports.items():
                metrics_summary = ", ".join(f"{k}: {v}" for k, v in list(t_rep.summary_metrics.items())[:3])
                status_badge = "✅ Active / Evaluated" if t_rep.is_installed else "ℹ️ Evaluated"
                lines.append(f"| **{t_rep.tool_name.upper()}** | {t_rep.tool_category} | `{t_rep.license}` | {status_badge} | `{metrics_summary or 'N/A'}` |")
            lines.append("")

        # 4. Deduplicated Unified Findings Ledger (Merged across Tools and Manual Controls)
        lines.append("## 🔍 Deduplicated Security Findings Ledger (Multi-Source Correlation)")
        lines.append("")
        lines.append("> _Duplicate issues identified across different frameworks (CIS, NIST, ISO, MITRE) and tools (Lynis, Checksec, Docker-Bench, Trivy) have been unified into a single actionable record._")
        lines.append("")

        if result.unified_findings:
            lines.append("| Finding ID | Topic | Title | Severity | Correlated Sources | Suggested Fix |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for f in result.unified_findings:
                sources_str = "<br>• ".join(f.sources[:4])
                if len(f.sources) > 4:
                    sources_str += f"<br>_+{len(f.sources)-4} more_"
                cmd_snip = f"`{f.remediation_cmd}`" if f.remediation_cmd else "_Review guide_"
                lines.append(
                    f"| `{f.finding_id}` | {f.topic} | {f.title} | **{f.severity.value}** | • {sources_str} | {cmd_snip} |"
                )
        else:
            lines.append("✅ **No security findings detected.**")

        lines.append("")
        lines.append("---")
        lines.append("_Generated automatically by Linux Security Assessment & Compliance Platform._")
        return "\n".join(lines)

    @staticmethod
    def generate_technical_report(result: AssessmentResult) -> str:
        """Generates in-depth technical report with complete evidence, tool findings, and remediation guides."""
        lines = []
        lines.append("# 📋 Technical Security Audit & Hardening Report")
        lines.append("")
        lines.append(f"> **Host:** `{result.system_context.hostname if result.system_context else 'Unknown'}` | "
                     f"**Overall Score:** `{result.overall_score}%` | **Evidences:** `{result.total_evidences}` | "
                     f"**Deduplicated Findings:** `{len(result.unified_findings)}`")
        lines.append("")

        # 1. Deduplicated Findings Section
        lines.append("## 🎯 Consolidated & Deduplicated Vulnerability / Hardening Findings")
        lines.append("")
        for f in result.unified_findings:
            sev_icon = "🔴" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "🟡"
            lines.append(f"### {sev_icon} [{f.severity.value}] `{f.finding_id}`: {f.title}")
            lines.append(f"- **Topic Area:** `{f.topic}`")
            lines.append(f"- **Correlated Framework & Tool Sources:** {', '.join(f.sources)}")
            lines.append(f"- **Description:** {f.description}")
            if f.actual_value:
                lines.append(f"- **Observed Condition:** `{f.actual_value}`")
            if f.expected_value:
                lines.append(f"- **Expected Secure Baseline:** `{f.expected_value}`")
            if f.remediation_cmd:
                lines.append(f"- **Remediation Command:**\n```bash\n{f.remediation_cmd}\n```")
            lines.append("")

        # 2. Framework Breakdown
        lines.append("## 🛡️ Regulatory and Standards Framework Breakdown")
        lines.append("")
        for fw_id, fw in result.frameworks.items():
            lines.append(f"### {fw.framework_name} ({fw.version})")
            lines.append(f"- **Adherence:** `{fw.adherence_percentage:.2f}%`")
            lines.append(f"- **Compliant:** `{fw.compliant_count} / {fw.total_controls}` | **Non-Compliant:** `{fw.non_compliant_count}` | **Partial:** `{fw.partial_count}`")
            lines.append("")

        # 3. Open-source tools breakdown
        if result.tools_reports:
            lines.append("## 🛠️ Integrated Open-Source Security Tools Detailed Output")
            lines.append("")
            for t_name, t_rep in result.tools_reports.items():
                lines.append(f"### 📦 {t_rep.tool_name.upper()} ({t_rep.tool_category})")
                lines.append(f"- **License:** `{t_rep.license}` | **Installed:** `{t_rep.is_installed}` | **Execution Time:** `{t_rep.execution_time_seconds}s`")
                lines.append("- **Metrics:** " + ", ".join(f"`{k}: {v}`" for k, v in t_rep.summary_metrics.items()))
                if t_rep.recommendations:
                    lines.append("- **Key Recommendations:**")
                    for rec in t_rep.recommendations[:5]:
                        lines.append(f"  - {rec}")
                lines.append("")

        return "\n".join(lines)
