"""Package Management, Repositories, and Update Policy Collector."""

import glob
import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext, OSFamily
from sec_audit_linux.core.utils import read_system_file, execute_command, parse_key_value_file


class PackagesCollector(BaseCollector):
    """Audits configured repositories, GPG signature verification, and update status."""

    name = "packages"
    description = "Audits package repositories, GPG verification, and pending updates"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        if context.os_family == OSFamily.REDHAT:
            records.extend(self._collect_redhat())
        elif context.os_family == OSFamily.DEBIAN:
            records.extend(self._collect_debian())
        elif context.os_family == OSFamily.SUSE:
            records.extend(self._collect_suse())
        else:
            records.extend(self._collect_generic())

        return records

    def _collect_redhat(self) -> List[EvidenceRecord]:
        records = []
        # 1. GPG check in yum/dnf repos
        repo_files = glob.glob("/etc/yum.repos.d/*.repo")
        repo_configs: Dict[str, Dict[str, Any]] = {}
        gpgcheck_disabled = []

        for rf in repo_files:
            content, _ = read_system_file(rf)
            if content:
                for line in content.splitlines():
                    if line.strip().startswith("gpgcheck"):
                        k, v = line.split("=", 1)
                        if v.strip() == "0":
                            gpgcheck_disabled.append(rf)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="yum_repos_gpgcheck",
            raw_output=f"Total repos: {len(repo_files)}, Repos with gpgcheck=0: {gpgcheck_disabled}",
            parsed_data={
                "total_repos": len(repo_files),
                "repos_with_gpgcheck_disabled": gpgcheck_disabled,
                "all_gpgcheck_enabled": len(gpgcheck_disabled) == 0
            }
        ))

        # 2. Check pending security updates via dnf/yum
        out, err, code = execute_command(["dnf", "check-update", "--security"], timeout=20)
        if code == 127: # dnf not found, try yum
            out, err, code = execute_command(["yum", "check-update", "--security"], timeout=20)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="security_updates_status",
            raw_output=out or err,
            parsed_data={"security_updates_available": code == 100} # code 100 means updates available
        ))

        return records

    def _collect_debian(self) -> List[EvidenceRecord]:
        records = []
        # 1. Check APT repositories & sources
        sources_files = ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*.list") + glob.glob("/etc/apt/sources.list.d/*.sources")
        insecure_repos = []
        for sf in sources_files:
            content, _ = read_system_file(sf)
            if content:
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("deb ") and "trusted=yes" in line:
                        insecure_repos.append(f"{sf}: {line}")
                    if line.startswith("deb http://"):
                        insecure_repos.append(f"{sf}: unencrypted http repo")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="apt_sources_security",
            raw_output="\n".join(insecure_repos) if insecure_repos else "All sources use HTTPS/trusted defaults",
            parsed_data={
                "insecure_repo_entries": insecure_repos,
                "is_secure": len(insecure_repos) == 0
            }
        ))

        # 2. Check automatic security updates (unattended-upgrades)
        auto_upgrades_file = "/etc/apt/apt.conf.d/20auto-upgrades"
        content, _ = read_system_file(auto_upgrades_file)
        auto_enabled = bool(content and 'Update-Package-Lists "1"' in content and 'Unattended-Upgrade "1"' in content)

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="unattended_upgrades_status",
            raw_output=content or "Not configured",
            parsed_data={"unattended_upgrades_enabled": auto_enabled}
        ))

        return records

    def _collect_suse(self) -> List[EvidenceRecord]:
        records = []
        out, _, code = execute_command(["zypper", "list-patches", "--category", "security"], timeout=20)
        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="zypper_security_patches",
            raw_output=out,
            parsed_data={"raw_patches": out}
        ))
        return records

    def _collect_generic(self) -> List[EvidenceRecord]:
        return [
            EvidenceRecord(
                collector_name=self.name,
                target_item="generic_package_audit",
                raw_output="Generic OS package audit",
                parsed_data={"status": "generic"}
            )
        ]
