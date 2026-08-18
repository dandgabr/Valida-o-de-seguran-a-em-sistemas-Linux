"""Evidence Store and Integrity Management Module."""

import json
from typing import Dict, List, Optional, Any
from sec_audit_linux.core.models import EvidenceRecord
from sec_audit_linux.core.utils import calculate_sha256


class EvidenceStore:
    """Manages in-memory and persistent evidence records with tamper-evident SHA-256 integrity verification."""

    def __init__(self):
        self._records: Dict[str, EvidenceRecord] = {}
        self._by_collector: Dict[str, List[str]] = {}
        self._by_target: Dict[str, List[str]] = {}

    def add_record(self, record: EvidenceRecord) -> None:
        """Adds and indexes a new evidence record."""
        # Ensure sha256 checksum is computed
        if not record.sha256_checksum:
            content_to_hash = record.raw_output or json.dumps(record.parsed_data, sort_keys=True)
            record.sha256_checksum = calculate_sha256(content_to_hash)

        self._records[record.evidence_id] = record

        # Index by collector
        if record.collector_name not in self._by_collector:
            self._by_collector[record.collector_name] = []
        self._by_collector[record.collector_name].append(record.evidence_id)

        # Index by target item
        if record.target_item not in self._by_target:
            self._by_target[record.target_item] = []
        self._by_target[record.target_item].append(record.evidence_id)

    def add_records(self, records: List[EvidenceRecord]) -> None:
        """Adds a list of evidence records."""
        for r in records:
            self.add_record(r)

    def get_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Retrieves a specific evidence record by UUID."""
        return self._records.get(evidence_id)

    def get_by_collector(self, collector_name: str) -> List[EvidenceRecord]:
        """Retrieves all evidence records produced by a specific collector."""
        ids = self._by_collector.get(collector_name, [])
        return [self._records[i] for i in ids if i in self._records]

    def get_by_target(self, target_item: str) -> List[EvidenceRecord]:
        """Retrieves all evidence records auditing a specific target file or parameter."""
        ids = self._by_target.get(target_item, [])
        return [self._records[i] for i in ids if i in self._records]

    def get_all_records(self) -> List[EvidenceRecord]:
        """Returns all registered evidence records."""
        return list(self._records.values())

    def verify_integrity(self, evidence_id: str) -> bool:
        """Verifies if the content of an evidence record matches its recorded SHA-256 hash."""
        record = self.get_record(evidence_id)
        if not record:
            return False
        content_to_hash = record.raw_output or json.dumps(record.parsed_data, sort_keys=True)
        return calculate_sha256(content_to_hash) == record.sha256_checksum

    def count(self) -> int:
        """Returns total number of stored evidence records."""
        return len(self._records)

    def export_bundle(self) -> Dict[str, Any]:
        """Exports an evidence bundle dictionary."""
        return {
            "total_records": len(self._records),
            "records": [r.to_dict() for r in self._records.values()]
        }
