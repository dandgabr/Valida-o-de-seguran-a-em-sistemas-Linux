"""JSON Reporter for programmatic LLM, SIEM, and Agent integration."""

import json
from typing import Dict, Any, Optional
from sec_audit_linux.core.models import AssessmentResult


class JSONReporter:
    """Exports structured JSON data formatted for LLMs, SIEMs, and ADK2 multi-agent systems."""

    @staticmethod
    def to_dict(result: AssessmentResult) -> Dict[str, Any]:
        """Converts AssessmentResult to a structured dictionary."""
        return result.to_dict()

    @staticmethod
    def to_json(result: AssessmentResult, indent: int = 2) -> str:
        """Converts AssessmentResult to a JSON string."""
        return result.to_json(indent=indent)

    @staticmethod
    def export_to_file(result: AssessmentResult, output_path: str, indent: int = 2) -> bool:
        """Saves assessment result to a file."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(result.to_json(indent=indent))
            return True
        except Exception:
            return False
