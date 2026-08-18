"""File Integrity Monitoring (AIDE, osquery, baseline checksums) Collector."""

import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import (
    execute_command,
    read_system_file,
    calculate_sha256,
    check_command_available
)


class IntegrityCollector(BaseCollector):
    """Audits AIDE file integrity database, osquery presence, and core binary integrity."""

    name = "integrity"
    description = "Audits AIDE database, File Integrity Monitoring (FIM), and binary checksums"

    CRITICAL_BINARIES = [
        "/usr/bin/sudo",
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/sbin/sshd",
        "/usr/sbin/useradd"
    ]

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. AIDE Configuration and Database
        aide_db_paths = [
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide/aide.db",
            "/var/log/aide/aide.db.gz"
        ]
        aide_db_found = [p for p in aide_db_paths if os.path.exists(p)]
        aide_installed = check_command_available("aide") or os.path.exists("/etc/aide.conf")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="aide_fim_status",
            raw_output=f"AIDE installed: {aide_installed}, Database found: {aide_db_found}",
            parsed_data={
                "aide_installed": aide_installed,
                "database_present": len(aide_db_found) > 0,
                "database_paths": aide_db_found
            }
        ))

        # 2. osquery Status
        osquery_installed = check_command_available("osqueryi")
        osquery_svc_active = False
        if osquery_installed:
            out, _, _ = execute_command(["systemctl", "is-active", "osqueryd"])
            osquery_svc_active = out.strip() == "active"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="osquery_status",
            raw_output=f"osquery installed: {osquery_installed}, active daemon: {osquery_svc_active}",
            parsed_data={
                "osquery_installed": osquery_installed,
                "osquery_active": osquery_svc_active
            }
        ))

        # 3. Critical Binary Checksums Baseline
        binary_hashes: Dict[str, str] = {}
        for b in self.CRITICAL_BINARIES:
            if os.path.exists(b):
                try:
                    with open(b, "rb") as f:
                        binary_hashes[b] = calculate_sha256(f.read())
                except Exception:
                    binary_hashes[b] = "error_reading"

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="critical_binary_checksums",
            raw_output="\n".join(f"{k}: {v}" for k, v in binary_hashes.items()),
            parsed_data=binary_hashes
        ))

        return records
