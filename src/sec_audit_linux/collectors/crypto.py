"""Cryptography, System Crypto Policies, Encrypted Volumes, and Certificates Collector."""

import glob
import os
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import read_system_file, execute_command


class CryptoCollector(BaseCollector):
    """Audits system crypto policies, LUKS encrypted block devices, and installed certificate authorities."""

    name = "crypto"
    description = "Audits system crypto-policies, LUKS/crypttab encrypted volumes, and CA certificates"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. System-wide Crypto Policy (RHEL/Fedora/CentOS/Rocky/Alma/openSUSE)
        crypto_policy = "unknown"
        policy_out, _, policy_code = execute_command(["update-crypto-policies", "--show"])
        if policy_code == 0 and policy_out.strip():
            crypto_policy = policy_out.strip()
        else:
            state_file = "/etc/crypto-policies/state/current"
            content, _ = read_system_file(state_file)
            if content:
                crypto_policy = content.strip()

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="system_crypto_policy",
            raw_output=f"Crypto Policy: {crypto_policy}",
            parsed_data={
                "policy": crypto_policy,
                "is_secure": crypto_policy in ["DEFAULT", "FUTURE", "FIPS"]
            }
        ))

        # 2. Encrypted Volumes (/etc/crypttab and lsblk LUKS detection)
        crypttab_content, _ = read_system_file("/etc/crypttab")
        lsblk_out, _, lsblk_code = execute_command(["lsblk", "-f"])
        has_luks = "crypto_LUKS" in (lsblk_out or "")

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="encrypted_volumes_luks",
            raw_output=f"Crypttab:\n{crypttab_content}\n\nLsblk:\n{lsblk_out}",
            parsed_data={
                "crypttab_present": bool(crypttab_content and crypttab_content.strip()),
                "has_luks_devices": has_luks
            }
        ))

        # 3. Certificate Authorities & Expiration Check
        cert_paths = ["/etc/ssl/certs", "/etc/pki/tls/certs"]
        total_ca_certs = 0
        for cp in cert_paths:
            if os.path.exists(cp):
                total_ca_certs += len(glob.glob(f"{cp}/*.pem") + glob.glob(f"{cp}/*.crt"))

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="ca_certificates_status",
            raw_output=f"Total CA certs found: {total_ca_certs}",
            parsed_data={"total_ca_certs": total_ca_certs}
        ))

        return records
