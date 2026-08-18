"""Command-Line Interface (CLI) for Linux Security Assessment and Compliance Automation."""

import argparse
import os
import sys
from typing import List

from sec_audit_linux.core.engine import AuditEngine
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.collectors import get_default_collectors
from sec_audit_linux.frameworks import get_default_frameworks
from sec_audit_linux.integrations import get_default_adapters
from sec_audit_linux.reporters.markdown_reporter import MarkdownReporter
from sec_audit_linux.reporters.json_reporter import JSONReporter
from sec_audit_linux.reporters.remediation_gen import RemediationGenerator
from sec_audit_linux.reporters.tool_reporter import ToolReporter


def setup_engine() -> AuditEngine:
    """Initializes AuditEngine with all standard collectors, tool adapters, and frameworks."""
    engine = AuditEngine()
    for col in get_default_collectors():
        engine.register_collector(col)
    for adapter in get_default_adapters():
        engine.register_tool_adapter(adapter)
    for fw in get_default_frameworks():
        engine.register_framework(fw)
    return engine


def cmd_system_info(args: argparse.Namespace) -> int:
    """Displays detected host environment and distribution metadata."""
    ctx = OSDetector.detect()
    print("=" * 60)
    print(" 🐧 Linux Security Assessment - System Environment")
    print("=" * 60)
    print(f" Hostname        : {ctx.hostname}")
    print(f" Operating System: {ctx.os_name} {ctx.os_version} ({ctx.os_family.value})")
    print(f" Kernel Release  : {ctx.kernel_release} ({ctx.architecture})")
    print(f" Init System     : {ctx.init_system}")
    print(f" Environment     : {'Container' if ctx.is_container else 'Bare Metal / VM'} ({ctx.virtualization})")
    print(f" Execution User  : {'Root (UID 0)' if ctx.is_root else 'Non-Root'}")
    print(f" IP Addresses    : {', '.join(ctx.ip_addresses)}")
    print("=" * 60)
    return 0


def cmd_list_frameworks(args: argparse.Namespace) -> int:
    """Lists all supported security and compliance frameworks."""
    frameworks = get_default_frameworks()
    print("=" * 75)
    print(" 🛡️  Supported Security & Compliance Frameworks")
    print("=" * 75)
    for fw in frameworks:
        print(f" • ID: {fw.framework_id:<16} | Name: {fw.name:<30} | Ver: {fw.version}")
        print(f"   Description: {fw.description}")
        print("-" * 75)
    return 0


def cmd_list_components(args: argparse.Namespace) -> int:
    """Lists all available audit collectors and Linux components."""
    collectors = get_default_collectors()
    print("=" * 70)
    print(" 📦 Auditable Linux Components & Collectors")
    print("=" * 70)
    for c in collectors:
        print(f" • Name: {c.name:<18} | Description: {c.description}")
    print("=" * 70)
    return 0


def cmd_list_tools(args: argparse.Namespace) -> int:
    """Lists all integrated open-source security audit and scanning tools."""
    adapters = get_default_adapters()
    print("=" * 80)
    print(" 🛠️  Integrated Open-Source Security Tools (Corporate / Commercial Free)")
    print("=" * 80)
    for a in adapters:
        status_str = "Installed" if a.is_available() else "Available via fallback/package"
        print(f" • Tool: {a.tool_name:<16} | Category: {a.tool_category:<35}")
        print(f"   License: {a.license:<25} | Status: {status_str}")
        print(f"   Description: {a.description}")
        print("-" * 80)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Executes full or selective security assessment."""
    engine = setup_engine()

    framework_ids = None
    if args.framework:
        framework_ids = [f.strip() for f in args.framework.split(",") if f.strip()]

    collector_names = None
    if args.component:
        collector_names = [c.strip() for c in args.component.split(",") if c.strip()]

    tool_names = None
    if args.tools:
        tool_names = [t.strip() for t in args.tools.split(",") if t.strip()]

    print("[*] Starting Linux Security Assessment & Open-Source Tool Audits...")
    print(f"[*] Target Host: {engine.context.hostname} ({engine.context.os_name} {engine.context.os_version})")

    result = engine.run_assessment(
        framework_ids=framework_ids,
        collector_names=collector_names,
        tool_names=tool_names,
        run_tools=not args.no_tools
    )

    print(f"[+] Assessment completed in {result.duration_seconds}s. Total evidences: {result.total_evidences}")
    print("=" * 65)
    print(f" 🏆 Overall Compliance Score: {result.overall_score:.1f}%")
    print("=" * 65)

    for fw_id, fw in result.frameworks.items():
        bar = MarkdownReporter._render_progress_bar(fw.adherence_percentage, width=15)
        print(f" • {fw.framework_name:<28}: {bar} ({fw.compliant_count}/{fw.total_controls} controls)")

    if result.tools_reports:
        print("=" * 65)
        print(" 🛠️  Open-Source Security Tools Reports Evaluated:")
        for t_name, t_rep in result.tools_reports.items():
            status_tag = "INSTALLED" if t_rep.is_installed else "EVALUATED"
            print(f" • {t_name.upper():<16} [{status_tag}]: {len(t_rep.findings)} findings, {len(t_rep.recommendations)} recommendations")

    print("=" * 65)

    # Save reports if output-dir is specified
    output_dir = args.output_dir
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

        exec_md = MarkdownReporter.generate_executive_report(result)
        exec_path = os.path.join(output_dir, "executive_report.md")
        with open(exec_path, "w", encoding="utf-8") as f:
            f.write(exec_md)

        tech_md = MarkdownReporter.generate_technical_report(result)
        tech_path = os.path.join(output_dir, "technical_report.md")
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech_md)

        json_path = os.path.join(output_dir, "assessment_result.json")
        JSONReporter.export_to_file(result, json_path)

        remed_script = RemediationGenerator.generate_bash_script(result)
        remed_path = os.path.join(output_dir, "remediation_playbook.sh")
        with open(remed_path, "w", encoding="utf-8") as f:
            f.write(remed_script)
        os.chmod(remed_path, 0o755)

        # Save individual reports for each tool
        if result.tools_reports:
            tools_dir = os.path.join(output_dir, "tools")
            os.makedirs(tools_dir, exist_ok=True)
            for t_name, t_rep in result.tools_reports.items():
                t_md = ToolReporter.generate_tool_report_md(t_rep)
                t_md_path = os.path.join(tools_dir, f"{t_name}_report.md")
                with open(t_md_path, "w", encoding="utf-8") as f:
                    f.write(t_md)

                t_json = ToolReporter.generate_tool_report_json(t_rep)
                t_json_path = os.path.join(tools_dir, f"{t_name}_report.json")
                with open(t_json_path, "w", encoding="utf-8") as f:
                    f.write(t_json)

        print(f"[+] Executive Report saved to : {exec_path}")
        print(f"[+] Technical Report saved to : {tech_path}")
        print(f"[+] JSON Result saved to      : {json_path}")
        print(f"[+] Remediation Script saved  : {remed_path}")
        if result.tools_reports:
            print(f"[+] Individual Tool Reports in: {os.path.join(output_dir, 'tools')}/")

    return 0


def main() -> int:
    """Main CLI entrypoint parser."""
    parser = argparse.ArgumentParser(
        prog="sec-audit-linux",
        description="Linux Security Assessment, Hardening and Compliance Automation Platform"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Run security audit and compliance assessment")
    audit_parser.add_argument("--all", action="store_true", help="Audit all available frameworks, tools, and components")
    audit_parser.add_argument("-f", "--framework", type=str, help="Comma-separated list of frameworks to evaluate")
    audit_parser.add_argument("-c", "--component", type=str, help="Comma-separated list of collectors to run")
    audit_parser.add_argument("-t", "--tools", type=str, help="Comma-separated list of open-source tools to run")
    audit_parser.add_argument("--no-tools", action="store_true", help="Skip external tool executions and run native audit only")
    audit_parser.add_argument("-o", "--output-dir", type=str, default="./audit_reports", help="Directory to save output reports")
    audit_parser.set_defaults(func=cmd_audit)

    # Command: system-info
    sys_parser = subparsers.add_parser("system-info", help="Display detected OS and environment context")
    sys_parser.set_defaults(func=cmd_system_info)

    # Command: list-frameworks
    fw_parser = subparsers.add_parser("list-frameworks", help="List all supported compliance frameworks")
    fw_parser.set_defaults(func=cmd_list_frameworks)

    # Command: list-components
    comp_parser = subparsers.add_parser("list-components", help="List all auditable components and collectors")
    comp_parser.set_defaults(func=cmd_list_components)

    # Command: list-tools
    tools_parser = subparsers.add_parser("list-tools", help="List all integrated open-source security tools")
    tools_parser.set_defaults(func=cmd_list_tools)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
