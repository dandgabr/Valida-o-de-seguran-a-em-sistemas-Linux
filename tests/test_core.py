"""Tests for core models, OS detection, evidence store, scoring, and finding deduplication."""

import unittest
from sec_audit_linux.core.models import (
    SystemContext,
    EvidenceRecord,
    ControlEvaluation,
    ControlStatus,
    Severity,
    OSFamily,
    FrameworkResult,
    ToolReport
)
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.core.evidence_manager import EvidenceStore
from sec_audit_linux.core.scoring import calculate_weighted_score, summarize_evaluations, calculate_pci_dss_score
from sec_audit_linux.core.deduplicator import FindingDeduplicator


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
                weight=1.0
            )
        ]

        score = calculate_weighted_score(evals)
        self.assertAlmostEqual(score, 50.0, places=1)

        summary = summarize_evaluations(evals)
        self.assertEqual(summary["compliant_count"], 1)
        self.assertEqual(summary["non_compliant_count"], 1)
        self.assertEqual(summary["partial_count"], 1)
        self.assertEqual(summary["total_controls"], 3)

        pci_score = calculate_pci_dss_score(evals)
        self.assertAlmostEqual(pci_score, 50.0, places=1)

    def test_finding_deduplicator(self):
        fw1 = FrameworkResult(
            framework_id="cis",
            framework_name="CIS Linux",
            version="1.0",
            adherence_percentage=50.0,
            evaluations=[
                ControlEvaluation(
                    control_id="CIS-5.2.1",
                    framework_name="CIS Linux",
                    title="Ensure SSH PermitRootLogin is disabled",
                    description="Disallow direct root login",
                    status=ControlStatus.NON_COMPLIANT,
                    severity=Severity.HIGH,
                    remediation_cmd="sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"
                )
            ]
        )
        fw2 = FrameworkResult(
            framework_id="nist",
            framework_name="NIST 800-53",
            version="1.0",
            adherence_percentage=50.0,
            evaluations=[
                ControlEvaluation(
                    control_id="NIST-AC-6",
                    framework_name="NIST 800-53",
                    title="Least Privilege (PermitRootLogin)",
                    description="Disallow direct root login",
                    status=ControlStatus.NON_COMPLIANT,
                    severity=Severity.CRITICAL
                )
            ]
        )

        deduped = FindingDeduplicator.deduplicate_and_correlate(
            frameworks={"cis": fw1, "nist": fw2},
            tools_reports={}
        )

        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0].severity, Severity.CRITICAL)  # Kept highest severity
        self.assertEqual(len(deduped[0].sources), 2)  # Merged sources
        self.assertIn("CIS Linux (CIS-5.2.1)", deduped[0].sources)
        self.assertIn("NIST 800-53 (NIST-AC-6)", deduped[0].sources)


if __name__ == "__main__":
    unittest.main()
