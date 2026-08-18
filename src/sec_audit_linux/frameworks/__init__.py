"""Frameworks package registering all regulatory and security compliance modules."""

from typing import List
from sec_audit_linux.frameworks.base_framework import BaseFramework
from sec_audit_linux.frameworks.cis_benchmarks import CISBenchmarkFramework
from sec_audit_linux.frameworks.cis_controls import CISControlsFramework
from sec_audit_linux.frameworks.nist_800_53 import NIST80053Framework
from sec_audit_linux.frameworks.nist_csf import NISTCSFFramework
from sec_audit_linux.frameworks.iso_27001 import ISO27001Framework
from sec_audit_linux.frameworks.pci_dss import PCIDSSFramework
from sec_audit_linux.frameworks.mitre_attack import MITREAttackFramework
from sec_audit_linux.frameworks.scap import SCAPFramework


def get_default_frameworks() -> List[BaseFramework]:
    """Returns initialized instances of all standard security compliance frameworks."""
    return [
        CISBenchmarkFramework(),
        CISControlsFramework(),
        NIST80053Framework(),
        NISTCSFFramework(),
        ISO27001Framework(),
        PCIDSSFramework(),
        MITREAttackFramework(),
        SCAPFramework()
    ]
