"""Integrations package registering open-source, commercially free security tool adapters."""

from typing import List
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.integrations.lynis_adapter import LynisAdapter
from sec_audit_linux.integrations.checksec_adapter import ChecksecAdapter
from sec_audit_linux.integrations.docker_bench_adapter import DockerBenchAdapter
from sec_audit_linux.integrations.kube_bench_adapter import KubeBenchAdapter
from sec_audit_linux.integrations.trivy_adapter import TrivyAdapter
from sec_audit_linux.integrations.grype_adapter import GrypeAdapter
from sec_audit_linux.integrations.syft_adapter import SyftAdapter
from sec_audit_linux.integrations.rkhunter_adapter import RKHunterAdapter
from sec_audit_linux.integrations.osquery_adapter import OSQueryAdapter
from sec_audit_linux.integrations.openscap_adapter import OpenSCAPAdapter
from sec_audit_linux.integrations.aide_adapter import AIDEAdapter


def get_default_adapters() -> List[BaseToolAdapter]:
    """Returns instances of all open-source security tool adapters."""
    return [
        LynisAdapter(),
        ChecksecAdapter(),
        DockerBenchAdapter(),
        KubeBenchAdapter(),
        TrivyAdapter(),
        GrypeAdapter(),
        SyftAdapter(),
        RKHunterAdapter(),
        OSQueryAdapter(),
        OpenSCAPAdapter(),
        AIDEAdapter()
    ]
