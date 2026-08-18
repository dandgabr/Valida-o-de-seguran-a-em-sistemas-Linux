"""Utility functions for safe system execution, file inspection, and parsing."""

import hashlib
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any


def calculate_sha256(content: str | bytes) -> str:
    """Calculates SHA-256 checksum of given string or bytes content."""
    if isinstance(content, str):
        content = content.encode("utf-8", errors="replace")
    return hashlib.sha256(content).hexdigest()


def is_root_user() -> bool:
    """Returns True if current execution has root privileges (UID 0)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def check_command_available(cmd_name: str) -> bool:
    """Checks if a command or binary is available in the system PATH."""
    return shutil.which(cmd_name) is not None


def execute_command(
    cmd: List[str] | str,
    timeout: int = 15,
    shell: bool = False
) -> Tuple[str, str, int]:
    """
    Executes a shell or binary command safely with timeout.
    Returns (stdout, stderr, exit_code).
    """
    try:
        proc = subprocess.run(
            cmd,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return proc.stdout or "", proc.stderr or "", proc.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout} seconds", -1
    except FileNotFoundError as e:
        return "", f"Command not found: {str(e)}", 127
    except PermissionError as e:
        return "", f"Permission denied: {str(e)}", 126
    except Exception as e:
        return "", f"Execution error: {str(e)}", -2


def read_system_file(
    file_path: str,
    max_bytes: int = 5_000_000
) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely reads a text file from the filesystem.
    Returns (content, error_message).
    """
    if not os.path.exists(file_path):
        return None, f"File does not exist: {file_path}"
    
    if not os.path.isfile(file_path):
        return None, f"Path is not a regular file: {file_path}"

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(max_bytes)
            return content, None
    except PermissionError:
        return None, f"Permission denied reading file: {file_path}"
    except Exception as e:
        return None, f"Failed to read {file_path}: {str(e)}"


def get_file_stat(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Returns file permissions, UID, GID, and octal mode.
    """
    if not os.path.exists(file_path):
        return None
    try:
        st = os.stat(file_path)
        octal_mode = oct(st.st_mode & 0o7777)[2:].zfill(4)
        return {
            "path": file_path,
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode_octal": octal_mode,
            "size": st.st_size,
            "is_suid": bool(st.st_mode & 0o4000),
            "is_sgid": bool(st.st_mode & 0o2000),
            "is_world_writable": bool(st.st_mode & 0o0002)
        }
    except Exception:
        return None


def parse_key_value_file(
    content: str,
    delimiter: str = "=",
    comment_char: str = "#"
) -> Dict[str, str]:
    """
    Parses key=value configuration files (like /etc/os-release or sysctl files).
    """
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue
        if delimiter in line:
            key, val = line.split(delimiter, 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            result[key] = val
    return result


def parse_colon_file(content: str) -> List[List[str]]:
    """
    Parses colon-separated files like /etc/passwd, /etc/group, /etc/shadow.
    """
    rows = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(line.split(":"))
    return rows
