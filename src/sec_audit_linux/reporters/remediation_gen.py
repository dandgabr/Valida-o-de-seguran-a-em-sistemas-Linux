"""Automated Remediation Script Generator."""

from typing import List, Dict, Any
from sec_audit_linux.core.models import AssessmentResult, ControlStatus


class RemediationGenerator:
    """Generates executable bash remediation scripts based on non-compliant findings."""

    @staticmethod
    def generate_bash_script(result: AssessmentResult) -> str:
        """Generates an idempotent bash remediation script."""
        lines = [
            "#!/usr/bin/env bash",
            "# ===================================================================",
            "# Automated Linux Hardening & Remediation Script",
            f"# Generated for Host: {result.system_context.hostname if result.system_context else 'Target'}",
            f"# Scan Date: {result.completed_at or result.started_at}",
            "# ===================================================================",
            "set -e",
            "",
            "if [ \"$EUID\" -ne 0 ]; then",
            "  echo '[-] This script must be executed as root.' >&2",
            "  exit 1",
            "fi",
            "",
            "echo '[+] Starting Linux security hardening and remediation...'",
            ""
        ]

        known_shell_starts = (
            "sysctl", "chmod", "chown", "echo", "sed", "systemctl", "apt", "dnf",
            "yum", "zypper", "setenforce", "update-crypto-policies", "passwd",
            "usermod", "userdel", "groupdel", "touch", "mkdir", "rm", "cp", "mv"
        )

        seen_cmds = set()
        for fw in result.frameworks.values():
            for e in fw.evaluations:
                if e.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL] and e.remediation_cmd:
                    cmd_str = e.remediation_cmd.strip()
                    if cmd_str not in seen_cmds:
                        seen_cmds.add(cmd_str)
                        lines.append(f"# [{fw.framework_name}] {e.control_id}: {e.title}")
                        
                        # Check if command is directly executable in bash
                        first_token = cmd_str.split()[0].lower() if cmd_str.split() else ""
                        if first_token in known_shell_starts or first_token.startswith("/"):
                            lines.append(f"echo '[*] Applying fix for {e.control_id}...'")
                            lines.append(cmd_str)
                        else:
                            # Instruction / manual step
                            lines.append(f"# MANUAL ACTION REQUIRED: {cmd_str}")
                        lines.append("")

        lines.append("echo '[+] All automated remediation steps executed successfully.'")
        return "\n".join(lines)
