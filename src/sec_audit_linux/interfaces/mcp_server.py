"""Model Context Protocol (MCP) Server for LLM and Multi-Agent Interaction."""

import json
import sys
from typing import Dict, Any, List, Optional

from sec_audit_linux.core.engine import AuditEngine
from sec_audit_linux.core.os_detector import OSDetector
from sec_audit_linux.collectors import get_default_collectors
from sec_audit_linux.frameworks import get_default_frameworks
from sec_audit_linux.integrations import get_default_adapters
from sec_audit_linux.reporters.remediation_gen import RemediationGenerator
from sec_audit_linux.reporters.tool_reporter import ToolReporter
from sec_audit_linux.reporters.markdown_reporter import MarkdownReporter


class MCPServer:
    """JSON-RPC 2.0 based Model Context Protocol (MCP) Server for LLMs and Autonomous Agents."""

    def __init__(self):
        self.engine = AuditEngine()
        for c in get_default_collectors():
            self.engine.register_collector(c)
        for a in get_default_adapters():
            self.engine.register_tool_adapter(a)
        for fw in get_default_frameworks():
            self.engine.register_framework(fw)
        self._last_assessment = None

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns tool schema definitions exposed to the LLM."""
        return [
            {
                "name": "get_system_context",
                "description": "Returns host operating system details, kernel release, init system, network IPs, virtualization, and execution user privilege level.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_supported_frameworks",
                "description": "Lists all 8 regulatory and security compliance frameworks supported by the platform (CIS Benchmarks, CIS Controls, NIST SP 800-53, NIST CSF 2.0, ISO/IEC 27001, PCI DSS v4.0, MITRE ATT&CK, SCAP/SSG).",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "list_integrated_security_tools",
                "description": "Lists all 11 integrated open-source security tools (Lynis, Checksec, Docker-Bench, Kube-Bench, Trivy, Grype, Syft, RKHunter, osquery, OpenSCAP, AIDE), license information, categories, and installation availability on the host.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "run_security_audit",
                "description": "Executes technical security audit, collects native evidence, runs open-source tools, validates compliance against frameworks, and returns overall adherence percentages and deduplicated findings ledger.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "frameworks": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of framework IDs to evaluate (e.g. ['cis_benchmarks', 'pci_dss', 'nist_800_53'])"
                        },
                        "components": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of components/collectors to audit (e.g. ['ssh', 'identity', 'system', 'network', 'containers'])"
                        },
                        "tools": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of open-source tools to run (e.g. ['lynis', 'checksec', 'docker_bench', 'trivy', 'syft', 'rkhunter'])"
                        },
                        "run_tools": {
                            "type": "boolean",
                            "description": "Whether to execute external open-source tools (defaults to true)",
                            "default": True
                        }
                    }
                }
            },
            {
                "name": "get_compliance_summary",
                "description": "Retrieves a high-level scoreboard summary with compliance percentages per framework and counts of compliant, non-compliant, and partial controls.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "frameworks": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Optional list of framework IDs to summarize"
                        }
                    }
                }
            },
            {
                "name": "get_individual_tool_report",
                "description": "Retrieves the standalone deep-analysis report, metrics, raw output, and recommendations for a specific open-source security tool.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tool_name": {
                            "type": "string",
                            "description": "Name of the tool ('lynis', 'checksec', 'docker_bench', 'kube_bench', 'trivy', 'grype', 'syft', 'rkhunter', 'osquery', 'openscap', 'aide_adapter')"
                        }
                    },
                    "required": ["tool_name"]
                }
            },
            {
                "name": "get_finding_details",
                "description": "Looks up detailed information for a specific security finding ID (e.g. 'FIND-NETWORK-FIREWALL', 'FIND-AUTH-EMPTY_PASSWORDS', 'FIND-SSH-PERMIT_ROOT_LOGIN') including observed state, expected baseline, correlated frameworks, rationale, and exact remediation command.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Finding identifier or control ID to look up"
                        }
                    },
                    "required": ["finding_id"]
                }
            },
            {
                "name": "inspect_evidence",
                "description": "Retrieves raw collected system evidence records, collector name, timestamp, and SHA-256 cryptographic integrity hash for a target item.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_item": {
                            "type": "string",
                            "description": "Identifier of the target item (e.g. 'ssh_server_configuration', 'kernel_sysctl_runtime', 'shadow_passwords_audit', 'firewall_configuration')"
                        }
                    },
                    "required": ["target_item"]
                }
            },
            {
                "name": "get_sbom_inventory",
                "description": "Retrieves software bill of materials (SBOM) packages cataloged by Syft, optionally filtered by package type (python, binary, gem, java-archive, github-action).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "package_type": {
                            "type": "string",
                            "description": "Optional package type filter (e.g. 'python', 'binary', 'java-archive', 'gem')"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of packages to return (default 100)",
                            "default": 100
                        }
                    }
                }
            },
            {
                "name": "generate_remediation_plan",
                "description": "Generates complete bash remediation playbook script with rollback support, audit logging in /var/log/hardening/, and snapshot backups in /var/backups/hardening/.",
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

    def get_resource_definitions(self) -> List[Dict[str, Any]]:
        """Returns MCP resource definitions."""
        return [
            {
                "uri": "audit://system/context",
                "name": "System Environment Context",
                "mimeType": "application/json",
                "description": "Operating system, kernel, network, and execution environment context"
            },
            {
                "uri": "audit://tools/status",
                "name": "Integrated Security Tools Status",
                "mimeType": "application/json",
                "description": "Status and availability of all 11 open-source security tools"
            },
            {
                "uri": "audit://frameworks/catalog",
                "name": "Supported Frameworks Catalog",
                "mimeType": "application/json",
                "description": "Catalog of all supported compliance frameworks and standards"
            },
            {
                "uri": "audit://compliance/latest",
                "name": "Latest Compliance Scoreboard",
                "mimeType": "application/json",
                "description": "Scoreboard and adherence metrics from the most recent assessment"
            }
        ]

    def get_prompt_definitions(self) -> List[Dict[str, Any]]:
        """Returns MCP prompt definitions."""
        return [
            {
                "name": "full_security_assessment",
                "description": "Prompt to execute full security assessment across all 8 frameworks and 11 open-source tools.",
                "arguments": []
            },
            {
                "name": "cis_hardening_audit",
                "description": "Prompt focusing on CIS Linux Benchmark compliance gaps and hardening recommendations.",
                "arguments": []
            },
            {
                "name": "container_supply_chain_check",
                "description": "Prompt focusing on Container security, Docker Bench, CVE scanners (Trivy/Grype), and Syft SBOM inventory.",
                "arguments": []
            },
            {
                "name": "generate_remediation_playbook",
                "description": "Prompt to inspect failing security controls and produce safe, idempotent remediation commands with rollback.",
                "arguments": []
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

        elif tool_name == "list_integrated_security_tools":
            adapters = get_default_adapters()
            return {
                "tools": [
                    {
                        "tool_name": a.tool_name,
                        "category": a.tool_category,
                        "license": a.license,
                        "installed": a.is_available(),
                        "description": a.description
                    }
                    for a in adapters
                ]
            }

        elif tool_name == "run_security_audit":
            fw_list = arguments.get("frameworks")
            comp_list = arguments.get("components")
            tool_list = arguments.get("tools")
            run_tools = arguments.get("run_tools", True)
            result = self.engine.run_assessment(
                framework_ids=fw_list,
                collector_names=comp_list,
                tool_names=tool_list,
                run_tools=run_tools
            )
            self._last_assessment = result
            return result.to_dict()

        elif tool_name == "get_compliance_summary":
            fw_list = arguments.get("frameworks")
            if not self._last_assessment:
                self._last_assessment = self.engine.run_assessment(framework_ids=fw_list, run_tools=False)
            res = self._last_assessment
            summary = {
                "overall_score": res.overall_score,
                "hostname": res.system_context.hostname if res.system_context else "Target",
                "frameworks": {}
            }
            for fid, fw in res.frameworks.items():
                if fw_list and fid not in fw_list:
                    continue
                summary["frameworks"][fid] = {
                    "name": fw.framework_name,
                    "version": fw.version,
                    "score": fw.adherence_percentage,
                    "compliant": fw.compliant_count,
                    "non_compliant": fw.non_compliant_count,
                    "partial": fw.partial_count,
                    "total": fw.total_controls
                }
            return summary

        elif tool_name == "get_individual_tool_report":
            t_name = arguments.get("tool_name", "")
            adapter = self.engine.tool_adapters.get(t_name)
            if not adapter:
                return {"error": f"Tool adapter not recognized: {t_name}"}
            tool_rep = adapter.audit(self.engine.context)
            return tool_rep.to_dict()

        elif tool_name == "get_finding_details":
            fid = arguments.get("finding_id", "").strip().upper()
            if not self._last_assessment:
                self._last_assessment = self.engine.run_assessment(run_tools=False)
            for f in self._last_assessment.deduplicated_findings:
                if f.finding_id.upper() == fid or fid in f.finding_id.upper() or any(fid in src.upper() for src in f.correlated_sources):
                    return f.to_dict()
            return {"error": f"No finding matching '{fid}' found in latest assessment"}

        elif tool_name == "inspect_evidence":
            target_item = arguments.get("target_item", "")
            records = self.engine.evidence_store.get_by_target(target_item)
            if not records:
                self.engine.run_assessment(run_tools=False)
                records = self.engine.evidence_store.get_by_target(target_item)
            return {
                "target_item": target_item,
                "count": len(records),
                "evidences": [r.to_dict() for r in records]
            }

        elif tool_name == "get_sbom_inventory":
            syft_adapter = self.engine.tool_adapters.get("syft")
            if not syft_adapter or not syft_adapter.is_available():
                return {"error": "Syft tool is not available on host"}
            rep = syft_adapter.audit(self.engine.context)
            pkg_type = arguments.get("package_type")
            limit = arguments.get("limit", 100)
            findings = rep.findings
            if pkg_type:
                findings = [pkg for pkg in findings if pkg.get("type", "").lower() == pkg_type.lower()]
            return {
                "total_cataloged": len(rep.findings),
                "filtered_count": len(findings),
                "package_types": rep.summary_metrics.get("package_types_breakdown", {}),
                "packages": findings[:limit]
            }

        elif tool_name == "generate_remediation_plan":
            fw_filter = arguments.get("frameworks")
            result = self.engine.run_assessment(framework_ids=fw_filter, run_tools=False)
            script = RemediationGenerator.generate_bash_script(result)
            return {
                "hostname": result.system_context.hostname if result.system_context else "Target",
                "bash_remediation_script": script
            }

        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    def read_resource(self, uri: str) -> Dict[str, Any]:
        """Reads MCP resource by URI."""
        if uri == "audit://system/context":
            return OSDetector.detect().to_dict()
        elif uri == "audit://tools/status":
            adapters = get_default_adapters()
            return {
                "tools": [
                    {
                        "tool_name": a.tool_name,
                        "category": a.tool_category,
                        "license": a.license,
                        "installed": a.is_available()
                    }
                    for a in adapters
                ]
            }
        elif uri == "audit://frameworks/catalog":
            frameworks = get_default_frameworks()
            return {
                "frameworks": [
                    {"id": fw.framework_id, "name": fw.name, "version": fw.version, "description": fw.description}
                    for fw in frameworks
                ]
            }
        elif uri == "audit://compliance/latest":
            if not self._last_assessment:
                self._last_assessment = self.engine.run_assessment(run_tools=False)
            return {
                "overall_score": self._last_assessment.overall_score,
                "frameworks": {
                    k: {
                        "name": v.framework_name,
                        "score": v.adherence_percentage,
                        "compliant": v.compliant_count,
                        "total": v.total_controls
                    }
                    for k, v in self._last_assessment.frameworks.items()
                }
            }
        else:
            raise ValueError(f"Resource not found: {uri}")

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Returns prompt template messages."""
        if name == "full_security_assessment":
            return {
                "description": "Execute comprehensive security assessment across all standards",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Please run a complete security audit of this Linux system using the run_security_audit tool, review all 8 frameworks and 11 security tools, identify non-compliant controls, and generate the remediation playbook."
                        }
                    }
                ]
            }
        elif name == "cis_hardening_audit":
            return {
                "description": "Audit CIS Linux Benchmark controls",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Run a targeted CIS Linux Benchmark audit using run_security_audit with frameworks=['cis_benchmarks'] and provide remediation steps for all failing controls."
                        }
                    }
                ]
            }
        elif name == "container_supply_chain_check":
            return {
                "description": "Audit container security and SBOM software supply chain",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Inspect container security (docker_bench, kube_bench), vulnerability scanners (trivy, grype), and software bill of materials (syft) using get_sbom_inventory and get_individual_tool_report."
                        }
                    }
                ]
            }
        elif name == "generate_remediation_playbook":
            return {
                "description": "Generate bash remediation playbook",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Generate an automated bash remediation script with rollback and logging using the generate_remediation_plan tool."
                        }
                    }
                ]
            }
        else:
            raise ValueError(f"Prompt not found: {name}")

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC 2.0 request or notification."""
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Handle MCP notifications (no id, no response expected)
        if method in ["notifications/initialized", "notifications/cancelled", "initialized"]:
            return None

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
                        "tools": {},
                        "resources": {},
                        "prompts": {}
                    }
                }
            }

        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
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

        elif method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": self.get_resource_definitions()
                }
            }

        elif method == "resources/read":
            uri = params.get("uri", "")
            try:
                content = self.read_resource(uri)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(content, indent=2)
                            }
                        ]
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32002,
                        "message": str(e)
                    }
                }

        elif method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "prompts": self.get_prompt_definitions()
                }
            }

        elif method == "prompts/get":
            name = params.get("name", "")
            args = params.get("arguments")
            try:
                prompt_res = self.get_prompt(name, args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": prompt_res
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": str(e)
                    }
                }

        else:
            if req_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
            return None

    def run_stdio(self) -> None:
        """Starts MCP JSON-RPC server listening on standard input."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
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
