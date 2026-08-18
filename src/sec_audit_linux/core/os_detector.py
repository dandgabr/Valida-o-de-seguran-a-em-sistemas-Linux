"""Linux Operating System and Environment Detection Module."""

import os
import platform
import socket
from typing import List, Optional
from sec_audit_linux.core.models import SystemContext, OSFamily
from sec_audit_linux.core.utils import read_system_file, parse_key_value_file, execute_command, is_root_user


class OSDetector:
    """Detects Linux distribution, architecture, init system, virtualization, and runtime context."""

    @staticmethod
    def detect() -> SystemContext:
        hostname = socket.gethostname()
        ip_addresses = OSDetector._get_ip_addresses()
        
        # Kernel & Architecture
        uname = platform.uname()
        kernel_release = uname.release
        architecture = uname.machine

        # Distribution from /etc/os-release or /usr/lib/os-release
        os_info = OSDetector._parse_os_release()
        os_id = os_info.get("ID", "linux").lower()
        os_name = os_info.get("NAME", "Linux")
        os_version = os_info.get("VERSION_ID", os_info.get("VERSION", "unknown"))
        os_codename = os_info.get("VERSION_CODENAME", "")
        
        os_family = OSDetector._determine_family(os_id, os_info.get("ID_LIKE", ""))
        init_system = OSDetector._detect_init_system()
        is_container, virtualization = OSDetector._detect_virtualization()

        return SystemContext(
            hostname=hostname,
            ip_addresses=ip_addresses,
            os_family=os_family,
            os_name=os_name,
            os_version=os_version,
            os_id=os_id,
            os_codename=os_codename,
            kernel_release=kernel_release,
            architecture=architecture,
            init_system=init_system,
            is_root=is_root_user(),
            is_container=is_container,
            virtualization=virtualization
        )

    @staticmethod
    def _parse_os_release() -> dict:
        for path in ["/etc/os-release", "/usr/lib/os-release"]:
            content, err = read_system_file(path)
            if content:
                return parse_key_value_file(content)
        return {}

    @staticmethod
    def _determine_family(os_id: str, id_like: str) -> OSFamily:
        combined = f"{os_id} {id_like}".lower()
        if any(x in combined for x in ["rhel", "centos", "rocky", "almalinux", "fedora", "ol", "oracle", "redhat"]):
            return OSFamily.REDHAT
        if any(x in combined for x in ["debian", "ubuntu", "mint", "kali"]):
            return OSFamily.DEBIAN
        if any(x in combined for x in ["suse", "sles", "opensuse"]):
            return OSFamily.SUSE
        if "arch" in combined or "manjaro" in combined:
            return OSFamily.ARCH
        if "alpine" in combined:
            return OSFamily.ALPINE
        return OSFamily.UNKNOWN

    @staticmethod
    def _get_ip_addresses() -> List[str]:
        ips = []
        try:
            # Try via ip route / socket lookup
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            ips.append(primary_ip)
            s.close()
        except Exception:
            pass

        if not ips:
            try:
                out, _, code = execute_command(["hostname", "-I"])
                if code == 0 and out.strip():
                    ips.extend(out.strip().split())
            except Exception:
                pass

        if not ips:
            ips = ["127.0.0.1"]
        return list(dict.fromkeys(ips))

    @staticmethod
    def _detect_init_system() -> str:
        if os.path.exists("/run/systemd/system"):
            return "systemd"
        out, _, code = execute_command(["ps", "-p", "1", "-o", "comm="])
        if code == 0 and out.strip():
            return out.strip()
        return "init"

    @staticmethod
    def _detect_virtualization() -> tuple[bool, str]:
        # Check container indicators
        is_container = False
        if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
            is_container = True
        
        virt_type = "none"
        out, _, code = execute_command(["systemd-detect-virt"])
        if code == 0 and out.strip() and out.strip() != "none":
            virt_type = out.strip()
            if virt_type in ["docker", "podman", "containerd", "lxc", "wsl"]:
                is_container = True
        elif is_container:
            virt_type = "container"

        return is_container, virt_type
