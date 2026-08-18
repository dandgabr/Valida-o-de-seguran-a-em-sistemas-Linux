"""Base abstract class for all security collectors."""

from abc import ABC, abstractmethod
from typing import List
from sec_audit_linux.core.models import EvidenceRecord, SystemContext


class BaseCollector(ABC):
    """Abstract base class for system and tool collectors."""

    name: str = "base_collector"
    description: str = "Base security collector"

    @abstractmethod
    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        """
        Executes low-level inspection and returns a list of EvidenceRecords.
        Must not modify system state (strictly read-only).
        """
        pass
