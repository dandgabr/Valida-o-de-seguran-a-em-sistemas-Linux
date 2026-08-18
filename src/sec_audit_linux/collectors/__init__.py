"""Collector package registering all native Linux inspection modules."""

from typing import List
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.collectors.system import SystemCollector
from sec_audit_linux.collectors.packages import PackagesCollector
from sec_audit_linux.collectors.identity import IdentityCollector
from sec_audit_linux.collectors.access_control import AccessControlCollector
from sec_audit_linux.collectors.network import NetworkCollector
from sec_audit_linux.collectors.ssh import SSHCollector
from sec_audit_linux.collectors.logging_audit import LoggingAuditCollector
from sec_audit_linux.collectors.integrity import IntegrityCollector
from sec_audit_linux.collectors.containers import ContainersCollector
from sec_audit_linux.collectors.crypto import CryptoCollector


def get_default_collectors() -> List[BaseCollector]:
    """Returns initialized instances of all standard native Linux collectors."""
    return [
        SystemCollector(),
        PackagesCollector(),
        IdentityCollector(),
        AccessControlCollector(),
        NetworkCollector(),
        SSHCollector(),
        LoggingAuditCollector(),
        IntegrityCollector(),
        ContainersCollector(),
        CryptoCollector()
    ]
