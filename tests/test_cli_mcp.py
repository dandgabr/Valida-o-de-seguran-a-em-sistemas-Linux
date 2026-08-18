"""Tests for CLI subcommands and MCP server interaction."""

import json
import os
import tempfile
import unittest
import argparse
from pathlib import Path

from sec_audit_linux.interfaces.mcp_server import MCPServer
from sec_audit_linux.interfaces.cli import cmd_system_info, cmd_list_frameworks, cmd_list_components, cmd_audit


class TestCLIMCP(unittest.TestCase):

    def test_mcp_server_initialize(self):
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }
        resp = server.handle_request(req)
        self.assertEqual(resp["id"], 1)
        self.assertIn("protocolVersion", resp["result"])

    def test_mcp_server_tools_list(self):
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        resp = server.handle_request(req)
        self.assertEqual(resp["id"], 2)
        tools = resp["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        self.assertIn("run_security_audit", tool_names)
        self.assertIn("get_system_context", tool_names)
        self.assertIn("inspect_evidence", tool_names)
        self.assertIn("generate_remediation_plan", tool_names)

    def test_mcp_server_tools_call(self):
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_system_context",
                "arguments": {}
            }
        }
        resp = server.handle_request(req)
        self.assertEqual(resp["id"], 3)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("hostname", content)
        self.assertIn("os_family", content)

    def test_cli_subcommands(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)

            # Test system-info
            args = argparse.Namespace()
            self.assertEqual(cmd_system_info(args), 0)

            # Test list-frameworks
            self.assertEqual(cmd_list_frameworks(args), 0)

            # Test list-components
            self.assertEqual(cmd_list_components(args), 0)

            # Test audit execution with temporary output dir
            audit_args = argparse.Namespace(
                framework="cis_benchmarks,pci_dss",
                component="system,ssh",
                output_dir=str(tmp_path)
            )
            self.assertEqual(cmd_audit(audit_args), 0)
            self.assertTrue((tmp_path / "executive_report.md").exists())
            self.assertTrue((tmp_path / "technical_report.md").exists())
            self.assertTrue((tmp_path / "assessment_result.json").exists())
            self.assertTrue((tmp_path / "remediation_playbook.sh").exists())


if __name__ == "__main__":
    unittest.main()
