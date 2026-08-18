"""Tests for CLI subcommands, MCP server interaction, and open-source tool audits."""

import json
import os
import tempfile
import unittest
import argparse
from pathlib import Path

from sec_audit_linux.interfaces.mcp_server import MCPServer
from sec_audit_linux.interfaces.cli import (
    cmd_system_info,
    cmd_list_frameworks,
    cmd_list_components,
    cmd_list_tools,
    cmd_audit
)
from sec_audit_linux.integrations import get_default_adapters
from sec_audit_linux.reporters.tool_reporter import ToolReporter


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
        self.assertIn("capabilities", resp["result"])

    def test_mcp_server_notifications_and_ping(self):
        server = MCPServer()
        # Notifications should return None (no reply required per MCP specification)
        self.assertIsNone(server.handle_request({"method": "notifications/initialized"}))
        self.assertIsNone(server.handle_request({"method": "initialized"}))

        # Ping should return empty result dict
        ping_resp = server.handle_request({"jsonrpc": "2.0", "id": 10, "method": "ping"})
        self.assertEqual(ping_resp["id"], 10)
        self.assertEqual(ping_resp["result"], {})

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
        self.assertIn("list_integrated_security_tools", tool_names)
        self.assertIn("get_individual_tool_report", tool_names)
        self.assertIn("get_finding_details", tool_names)
        self.assertIn("get_compliance_summary", tool_names)
        self.assertIn("get_sbom_inventory", tool_names)

    def test_mcp_server_resources_and_prompts(self):
        server = MCPServer()

        # Resources list
        res_list = server.handle_request({"jsonrpc": "2.0", "id": 4, "method": "resources/list"})
        self.assertIn("resources", res_list["result"])
        self.assertGreaterEqual(len(res_list["result"]["resources"]), 3)

        # Resource read
        res_read = server.handle_request({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "resources/read",
            "params": {"uri": "audit://system/context"}
        })
        self.assertIn("contents", res_read["result"])

        # Prompts list
        prompts_list = server.handle_request({"jsonrpc": "2.0", "id": 6, "method": "prompts/list"})
        self.assertIn("prompts", prompts_list["result"])
        self.assertGreaterEqual(len(prompts_list["result"]["prompts"]), 3)

        # Prompt get
        prompt_get = server.handle_request({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "prompts/get",
            "params": {"name": "full_security_assessment"}
        })
        self.assertIn("messages", prompt_get["result"])

    def test_mcp_server_tools_call(self):
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_integrated_security_tools",
                "arguments": {}
            }
        }
        resp = server.handle_request(req)
        self.assertEqual(resp["id"], 3)
        content = json.loads(resp["result"]["content"][0]["text"])
        self.assertIn("tools", content)
        self.assertGreaterEqual(len(content["tools"]), 10)

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

            # Test list-tools
            self.assertEqual(cmd_list_tools(args), 0)

            # Test audit execution with tools and temporary output dir
            audit_args = argparse.Namespace(
                framework="cis_benchmarks,pci_dss",
                component="system,ssh",
                tools="checksec,docker_bench",
                no_tools=False,
                output_dir=str(tmp_path)
            )
            self.assertEqual(cmd_audit(audit_args), 0)
            self.assertTrue((tmp_path / "executive_report.md").exists())
            self.assertTrue((tmp_path / "technical_report.md").exists())
            self.assertTrue((tmp_path / "assessment_result.json").exists())
            self.assertTrue((tmp_path / "remediation_playbook.sh").exists())
            self.assertTrue((tmp_path / "tools").exists())


if __name__ == "__main__":
    unittest.main()
