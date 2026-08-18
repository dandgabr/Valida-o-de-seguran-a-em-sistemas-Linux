"""Base abstract class for external security tool adapters."""

from abc import ABC, abstractmethod
from typing import List, Optional
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import check_command_available


class BaseToolAdapter(ABC):
    """Abstract base class for wrapping and parsing external security tools."""

    tool_name: str = "base_tool"
    binary_name: str = "tool"
    description: str = "External security tool adapter"

    def is_available(self) -> bool:
        """Checks if the required binary is installed on the host system."""
        return check_command_available(self.binary_name)

    @abstractmethod
    def run(self, context: SystemContext) -> List[EvidenceRecord]:
        """
        Executes external tool if available, parses its output, and returns EvidenceRecords.
        If unavailable, returns an informative status record.
        """
        pass
