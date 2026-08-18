"""Dedicated Individual Report Generator for Integrated Security Tools."""

import json
from typing import Dict, Any, List
from sec_audit_linux.core.models import ToolReport, ToolExecutionStatus


class ToolReporter:
    """Generates standalone, in-depth reports for each open-source security tool."""

    @staticmethod
    def generate_tool_report_md(report: ToolReport) -> str:
        """Generates a formatted standalone Markdown report for an individual security tool."""
        lines = []
        lines.append(f"# 🛠️ Individual Security Tool Report: {report.tool_name.upper()}")
        lines.append("")
        lines.append(f"> **Category:** `{report.tool_category}` | **License:** `{report.license}` | **Status:** `{report.status.value.upper()}`")
        lines.append(f"> **Tool Version:** `{report.version}` | **Scan Duration:** `{report.execution_time_seconds}s` | **Generated:** `{report.generated_at}`")
        lines.append("")

        # 1. Summary Metrics
        lines.append("## 📊 Summary Metrics")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| :--- | :--- |")
        for k, v in report.summary_metrics.items():
            lines.append(f"| **{k.replace('_', ' ').title()}** | `{v}` |")
        lines.append("")

        # 2. Detailed Findings
        lines.append("## 🔍 Detailed Findings & Observations")
        lines.append("")
        if report.findings:
            lines.append(f"Total findings registered: **{len(report.findings)}**")
            lines.append("")
            # Render findings as formatted JSON / list
            lines.append("```json")
            lines.append(json.dumps(report.findings[:50], indent=2))
            lines.append("```")
        else:
            lines.append("ℹ️ _No anomalies or specific findings recorded by this tool._")
        lines.append("")

        # 3. Actionable Recommendations
        lines.append("## 💡 Specific Recommendations & Remediation")
        lines.append("")
        if report.recommendations:
            for r in report.recommendations:
                lines.append(f"- {r}")
        else:
            lines.append("✅ _No action required._")
        lines.append("")

        # 4. Raw Execution Sample
        if report.raw_output:
            lines.append("## 📜 Execution Output Snippet")
            lines.append("```text")
            lines.append(report.raw_output[:2500])
            if len(report.raw_output) > 2500:
                lines.append("... [truncated]")
            lines.append("```")
            lines.append("")

        lines.append("---")
        lines.append(f"_Report produced by Linux Security Assessment Engine for {report.tool_name}._")
        return "\n".join(lines)

    @staticmethod
    def generate_tool_report_json(report: ToolReport, indent: int = 2) -> str:
        """Serializes ToolReport to JSON string."""
        return json.dumps(report.to_dict(), indent=indent)
