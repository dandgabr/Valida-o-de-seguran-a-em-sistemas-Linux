"""Tests for core models, OS detection, evidence store, and scoring."""

import unittest
from sec_audit_linux.core.models import (
    SystemContext,
    EvidenceRecord,
    ControlEvaluation,
    ControlStatus,
    Severity,
    OSFamily
)
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.core.evidence_manager import EvidenceStore
from sec_audit_linux.core.scoring import calculate_weighted_score, summarize_evaluations, calculate_pci_dss_score


class TestCore(unittest.TestCase):

    def test_os_detector(self):
        ctx = OSDetector.detect()
        self.assertIsInstance(ctx, SystemContext)
        self.assertTrue(bool(ctx.hostname))
        self.assertIsInstance(ctx.os_family, OSFamily)
        self.assertGreater(len(ctx.ip_addresses), 0)

    def test_evidence_store(self):
        store = EvidenceStore()
        record = EvidenceRecord(
            collector_name="test_col",
            target_item="test_target",
            raw_output="data=123",
            parsed_data={"data": 123}
        )
        store.add_record(record)

        self.assertEqual(store.count(), 1)
        self.assertIsNotNone(store.get_record(record.evidence_id))
        self.assertEqual(len(store.get_by_collector("test_col")), 1)
        self.assertEqual(len(store.get_by_target("test_target")), 1)
        self.assertTrue(store.verify_integrity(record.evidence_id))

    def test_scoring_calculations(self):
        evals = [
            ControlEvaluation(
                control_id="C1",
                framework_name="F1",
                title="Control 1",
                description="Desc",
                status=ControlStatus.COMPLIANT,
                weight=2.0
            ),
            ControlEvaluation(
                control_id="C2",
                framework_name="F1",
                title="Control 2",
                description="Desc",
                status=ControlStatus.NON_COMPLIANT,
                weight=2.0
            ),
            ControlEvaluation(
                control_id="C3",
                framework_name="F1",
                title="Control 3",
                description="Desc",
                status=ControlStatus.PARTIAL,
                weight=2.0
            ),
            ControlEvaluation(
                control_id="C4",
                framework_name="F1",
                title="Control 4",
                description="Desc",
                status=ControlStatus.NOT_APPLICABLE,
                weight=5.0
            )
        ]

        score = calculate_weighted_score(evals)
        self.assertEqual(score, 50.0)

        summary = summarize_evaluations(evals)
        self.assertEqual(summary["total_controls"], 4)
        self.assertEqual(summary["compliant_count"], 1)
        self.assertEqual(summary["non_compliant_count"], 1)
        self.assertEqual(summary["partial_count"], 1)
        self.assertEqual(summary["not_applicable_count"], 1)


if __name__ == "__main__":
    unittest.main()
