"""Network, Listening Ports, Firewall, and Protocol Hardening Collector."""

import re
from typing import List, Dict, Any
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import execute_command, read_system_file


class NetworkCollector(BaseCollector):
    """Audits firewall status, active listening sockets, and DNS resolver configuration."""

    name = "network"
    description = "Audits firewalls (nftables, iptables, ufw, firewalld), listening ports, and DNS settings"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        records: List[EvidenceRecord] = []

        # 1. Firewall Technology Detection & Rule Status
        firewall_info: Dict[str, Any] = {
            "nftables_active": False,
            "iptables_active": False,
            "ufw_active": False,
            "firewalld_active": False,
            "any_firewall_active": False
        }

        # Check nftables
        nft_out, _, nft_code = execute_command(["nft", "list", "ruleset"])
        if nft_code == 0 and "table" in nft_out:
            firewall_info["nftables_active"] = True

        # Check iptables
        ipt_out, _, ipt_code = execute_command(["iptables-save"])
        if ipt_code == 0 and "-A " in ipt_out:
            firewall_info["iptables_active"] = True

        # Check ufw
        ufw_out, _, ufw_code = execute_command(["ufw", "status"])
        if ufw_code == 0 and "Status: active" in ufw_out:
            firewall_info["ufw_active"] = True

        # Check firewalld
        fwd_out, _, fwd_code = execute_command(["firewall-cmd", "--state"])
        if fwd_code == 0 and "running" in fwd_out:
            firewall_info["firewalld_active"] = True

        firewall_info["any_firewall_active"] = any([
            firewall_info["nftables_active"],
            firewall_info["iptables_active"],
            firewall_info["ufw_active"],
            firewall_info["firewalld_active"]
        ])

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="firewall_status",
            raw_output=f"Firewall state: {firewall_info}",
            parsed_data=firewall_info
        ))

        # 2. Listening TCP/UDP Ports & Sockets
        ss_out, _, ss_code = execute_command(["ss", "-tulnp"])
        listening_ports = []
        if ss_code == 0:
            for line in ss_out.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    state = parts[1]
                    local_addr = parts[4]
                    process_info = parts[6] if len(parts) >= 7 else "unknown"
                    listening_ports.append({
                        "proto": proto,
                        "state": state,
                        "local_addr": local_addr,
                        "process": process_info
                    })

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="listening_network_sockets",
            raw_output=ss_out,
            parsed_data={
                "total_listening": len(listening_ports),
                "ports": listening_ports
            }
        ))

        # 3. DNS Configuration (/etc/resolv.conf)
        resolv_content, _ = read_system_file("/etc/resolv.conf")
        nameservers = []
        if resolv_content:
            for line in resolv_content.splitlines():
                if line.strip().startswith("nameserver"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])

        records.append(EvidenceRecord(
            collector_name=self.name,
            target_item="dns_resolv_conf",
            raw_output=resolv_content or "resolv.conf missing",
            parsed_data={
                "nameservers": nameservers,
                "has_nameservers": len(nameservers) > 0
            }
        ))

        return records
