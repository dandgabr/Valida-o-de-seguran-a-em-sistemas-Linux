"""Interfaces package for CLI and MCP Server."""

from sec_audit_linux.interfaces.cli import main as cli_main
from sec_audit_linux.interfaces.mcp_server import main as mcp_main

__all__ = ["cli_main", "mcp_main"]
