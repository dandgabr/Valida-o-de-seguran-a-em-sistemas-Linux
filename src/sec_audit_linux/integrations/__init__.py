"""Integrations package registering third-party security tool adapters."""

from typing import List
from sec_audit_linux.integrations.base_adapter import BaseToolAdapter
from sec_audit_linux.integrations.lynis_adapter import LynisAdapter
from sec_audit_linux.integrations.openscap_adapter import OpenSCAPAdapter
from sec_audit_linux.integrations.aide_adapter import AIDEAdapter
from sec_audit_linux.integrations.trivy_adapter import TrivyAdapter
from sec_audit_linux.integrations.docker_bench_adapter import DockerBenchAdapter


def get_default_adapters() -> List[BaseToolAdapter]:
    """Returns instances of all external tool adapters."""
    return [
        LynisAdapter(),
        OpenSCAPAdapter(),
        AIDEAdapter(),
        TrivyAdapter(),
        DockerBenchAdapter()
    ]
