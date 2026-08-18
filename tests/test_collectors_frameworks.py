"""Tests for collectors, tool adapters, frameworks evaluation, and reports generation."""

import unittest
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.collectors import get_default_collectors
from sec_audit_linux.integrations import get_default_adapters
from sec_audit_linux.frameworks import get_default_frameworks
from sec_audit_linux.core.engine import AuditEngine
from sec_audit_linux.reporters.markdown_reporter import MarkdownReporter
from sec_audit_linux.reporters.json_reporter import JSONReporter
from sec_audit_linux.reporters.remediation_gen import RemediationGenerator
from sec_audit_linux.reporters.tool_reporter import ToolReporter


class TestCollectorsAndFrameworks(unittest.TestCase):

    def test_native_collectors_run(self):
        ctx = OSDetector.detect()
        collectors = get_default_collectors()
        self.assertGreaterEqual(len(collectors), 10)

        for col in collectors:
            records = col.collect(ctx)
            self.assertIsInstance(records, list)
            self.assertGreater(len(records), 0)
            for r in records:
                self.assertEqual(r.collector_name, col.name)
                self.assertTrue(bool(r.target_item))

    def test_open_source_tools_run(self):
        ctx = OSDetector.detect()
        adapters = get_default_adapters()
        self.assertGreaterEqual(len(adapters), 10)

        for adapter in adapters:
            report = adapter.audit(ctx)
            self.assertEqual(report.tool_name, adapter.tool_name)
            self.assertTrue(bool(report.tool_category))
            self.assertTrue(bool(report.license))
            evs = adapter.extract_evidences(report)
            self.assertGreater(len(evs), 0)

            # Test individual report generator
            md_out = ToolReporter.generate_tool_report_md(report)
            self.assertIn(report.tool_name.upper(), md_out)

    def test_full_assessment_pipeline(self):
        engine = AuditEngine()
        for c in get_default_collectors():
            engine.register_collector(c)
        for a in get_default_adapters():
            engine.register_tool_adapter(a)
        for fw in get_default_frameworks():
            engine.register_framework(fw)

        result = engine.run_assessment(run_tools=True)

        self.assertGreaterEqual(result.overall_score, 0.0)
        self.assertLessEqual(result.overall_score, 100.0)
        self.assertEqual(len(result.frameworks), 8)
        self.assertGreaterEqual(len(result.tools_reports), 10)
        self.assertGreater(result.total_evidences, 0)

        # Test all 8 frameworks exist in result
        expected_fws = [
            "cis_benchmarks",
            "cis_controls",
            "nist_800_53",
            "nist_csf",
            "iso_27001",
            "pci_dss",
            "mitre_attack",
            "scap"
        ]
        for ef in expected_fws:
            self.assertIn(ef, result.frameworks)
            fw_res = result.frameworks[ef]
            self.assertGreater(fw_res.total_controls, 0)
            self.assertGreaterEqual(fw_res.adherence_percentage, 0.0)

        # Test Reporters
        exec_md = MarkdownReporter.generate_executive_report(result)
        self.assertIn("# 🛡️ Executive Security & Compliance Assessment Report", exec_md)
        self.assertIn("Compliance Scoreboard by Framework", exec_md)

        tech_md = MarkdownReporter.generate_technical_report(result)
        self.assertIn("# 📋 Technical Security Audit & Hardening Report", tech_md)

        json_dict = JSONReporter.to_dict(result)
        self.assertIn("overall_score", json_dict)
        self.assertIn("frameworks", json_dict)
        self.assertIn("tools_reports", json_dict)

        bash_script = RemediationGenerator.generate_bash_script(result)
        self.assertIn("#!/usr/bin/env bash", bash_script)


if __name__ == "__main__":
    unittest.main()
