"""Model Context Protocol (MCP) Server for LLM and Multi-Agent Interaction."""

import json
import sys
from typing import Dict, Any, List

from sec_audit_linux.core.engine import AuditEngine
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.collectors import get_default_collectors
from sec_audit_linux.frameworks import get_default_frameworks
from sec_audit_linux.reporters.remediation_gen import RemediationGenerator


class MCPServer:
    """JSON-RPC based Model Context Protocol (MCP) Server for LLMs."""

    def __init__(self):
        self.engine = AuditEngine()
        for c in get_default_collectors():
            self.engine.register_collector(c)
        for fw in get_default_frameworks():
            self.engine.register_framework(fw)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns tool schema definitions exposed to the LLM."""
        return [
            {
                "name": "get_system_context",
                "description": "Returns host operating system details, kernel release, init system, and environment.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_supported_frameworks",
                "description": "Lists all regulatory and security compliance frameworks supported by the platform.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "run_security_audit",
                "description": "Executes technical security audit and calculates compliance adherence percentages.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "frameworks": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of framework IDs to evaluate (e.g. ['cis_benchmarks', 'pci_dss'])"
                        },
                        "components": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of components/collectors to audit (e.g. ['ssh', 'identity', 'system'])"
                        }
                    }
                }
            },
            {
                "name": "inspect_evidence",
                "description": "Retrieves the raw collected evidence and SHA-256 integrity hash for a target item.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_item": {
                            "type": "string",
                            "description": "Identifier of the target item (e.g. 'ssh_server_configuration' or 'selinux_status')"
                        }
                    },
                    "required": ["target_item"]
                }
            },
            {
                "name": "generate_remediation_plan",
                "description": "Generates executable bash commands to remediate non-compliant security controls.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "frameworks": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of frameworks to filter remediation fixes for"
                        }
                    }
                }
            }
        ]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches and executes MCP tool call."""
        if tool_name == "get_system_context":
            ctx = OSDetector.detect()
            return ctx.to_dict()

        elif tool_name == "list_supported_frameworks":
            frameworks = get_default_frameworks()
            return {
                "frameworks": [
                    {
                        "id": fw.framework_id,
                        "name": fw.name,
                        "version": fw.version,
                        "description": fw.description
                    }
                    for fw in frameworks
                ]
            }

        elif tool_name == "run_security_audit":
            fw_list = arguments.get("frameworks")
            comp_list = arguments.get("components")
            result = self.engine.run_assessment(
                framework_ids=fw_list,
                collector_names=comp_list
            )
            return result.to_dict()

        elif tool_name == "inspect_evidence":
            target_item = arguments.get("target_item", "")
            records = self.engine.evidence_store.get_by_target(target_item)
            if not records:
                # Run collection on the fly if not cached
                self.engine.run_assessment()
                records = self.engine.evidence_store.get_by_target(target_item)
            return {
                "target_item": target_item,
                "count": len(records),
                "evidences": [r.to_dict() for r in records]
            }

        elif tool_name == "generate_remediation_plan":
            result = self.engine.run_assessment(framework_ids=arguments.get("frameworks"))
            script = RemediationGenerator.generate_bash_script(result)
            return {
                "hostname": result.system_context.hostname if result.system_context else "Target",
                "bash_remediation_script": script
            }

        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Processes a single JSON-RPC 2.0 request."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": "sec-audit-linux-mcp",
                        "version": "1.0.0"
                    },
                    "capabilities": {
                        "tools": {}
                    }
                }
            }

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": self.get_tool_definitions()
                }
            }

        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments", {})
            try:
                content_res = self.execute_tool(name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(content_res, indent=2)
                            }
                        ]
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32000,
                        "message": str(e)
                    }
                }

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }

    def run_stdio(self) -> None:
        """Starts MCP JSON-RPC server listening on standard input."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


def main() -> int:
    """MCP Server entrypoint."""
    server = MCPServer()
    server.run_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
