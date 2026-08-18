"""Automated Enterprise Hardening & Remediation Script Generator with Logging, Backup, and Rollback."""

from typing import List, Dict, Any, Set
import re
from sec_audit_linux.core.models import AssessmentResult, ControlStatus, UnifiedFinding


class RemediationGenerator:
    """Generates enterprise-grade bash remediation scripts with rich UX, backups, logging, and rollback."""

    @classmethod
    def _categorize_command(cls, cmd: str, title: str, control_id: str) -> str:
        """Determines the target component category for the remediation command."""
        cmd_lower = cmd.lower()
        title_lower = title.lower()

        if "sysctl" in cmd_lower or "/etc/sysctl" in cmd_lower:
            return "sysctl"
        if "modprobe" in cmd_lower or "modprobe" in title_lower:
            return "modules"
        if "sshd" in cmd_lower or "/etc/ssh" in cmd_lower or "ssh" in title_lower:
            return "ssh"
        if "docker" in cmd_lower or "/etc/docker" in cmd_lower or "container" in title_lower:
            return "docker"
        if "ufw" in cmd_lower or "nftables" in cmd_lower or "iptables" in cmd_lower or "firewall" in title_lower:
            return "firewall"
        if "auditd" in cmd_lower or "auditctl" in cmd_lower or "audit" in title_lower:
            return "auditd"
        if "aide" in cmd_lower or "fim" in title_lower:
            return "aide"
        if "chmod" in cmd_lower or "chown" in cmd_lower or "/etc/passwd" in cmd_lower or "/etc/shadow" in cmd_lower:
            return "permissions"
        if "apt" in cmd_lower or "dnf" in cmd_lower or "yum" in cmd_lower or "zypper" in cmd_lower:
            return "packages"
        if "systemctl" in cmd_lower:
            return "services"

        return "system"

    @classmethod
    def generate_bash_script(cls, result: AssessmentResult) -> str:
        """
        Generates an enterprise-ready, idempotent Bash hardening script featuring:
        - Real-time colored visual feedback with step progression.
        - Timestamped logging to /var/log/hardening/.
        - Auxiliary pre-execution backup in /var/backups/hardening/ with manifest.
        - Comprehensive rollback engine (--rollback and --rollback-comp <component>).
        """
        hostname = result.system_context.hostname if result.system_context else "TargetHost"
        timestamp = result.completed_at or result.started_at

        # Extract and group actionable remediations
        categorized_actions: Dict[str, List[Dict[str, Any]]] = {
            "sysctl": [],
            "modules": [],
            "ssh": [],
            "docker": [],
            "firewall": [],
            "auditd": [],
            "aide": [],
            "permissions": [],
            "services": [],
            "packages": [],
            "system": []
        }

        seen_cmds: Set[str] = set()

        # Process unified findings if available
        if result.unified_findings:
            for finding in result.unified_findings:
                if finding.remediation_cmd:
                    cmd_clean = finding.remediation_cmd.strip()
                    if cmd_clean and cmd_clean not in seen_cmds:
                        seen_cmds.add(cmd_clean)
                        cat = cls._categorize_command(cmd_clean, finding.title, finding.finding_id)
                        categorized_actions[cat].append({
                            "id": finding.finding_id,
                            "title": finding.title,
                            "command": cmd_clean,
                            "sources": finding.sources
                        })
        else:
            # Fallback to framework evaluations
            for fw in result.frameworks.values():
                for e in fw.evaluations:
                    if e.status in [ControlStatus.NON_COMPLIANT, ControlStatus.PARTIAL] and e.remediation_cmd:
                        cmd_clean = e.remediation_cmd.strip()
                        if cmd_clean and cmd_clean not in seen_cmds:
                            seen_cmds.add(cmd_clean)
                            cat = cls._categorize_command(cmd_clean, e.title, e.control_id)
                            categorized_actions[cat].append({
                                "id": e.control_id,
                                "title": e.title,
                                "command": cmd_clean,
                                "sources": [f"{fw.framework_name} ({e.control_id})"]
                            })

        # Generate the dynamic script
        lines = [
            "#!/usr/bin/env bash",
            "# ==============================================================================",
            "# Enterprise Linux Security Hardening, Logging & Rollback Script",
            f"# Generated automatically for host: {hostname}",
            f"# Assessment ID: {result.assessment_id}",
            f"# Scan Date: {timestamp}",
            "# ==============================================================================",
            "set -euo pipefail",
            "",
            "# ------------------------------------------------------------------------------",
            "# Configuration & Paths",
            "# ------------------------------------------------------------------------------",
            "BACKUP_BASE_DIR=\"/var/backups/hardening\"",
            "LOG_DIR=\"/var/log/hardening\"",
            "TIMESTAMP=\"$(date +\"%Y%m%d_%H%M%S\")\"",
            "CURRENT_BACKUP_DIR=\"${BACKUP_BASE_DIR}/backup_${TIMESTAMP}\"",
            "LOG_FILE=\"${LOG_DIR}/hardening_${TIMESTAMP}.log\"",
            "LATEST_LOG_LINK=\"${LOG_DIR}/hardening-latest.log\"",
            "MANIFEST_FILE=\"${CURRENT_BACKUP_DIR}/manifest.json\"",
            "",
            "# Colors for Visual Feedback",
            "RED='\\033[0;31m'",
            "GREEN='\\033[0;32m'",
            "YELLOW='\\033[1;33m'",
            "BLUE='\\033[0;34m'",
            "CYAN='\\033[0;36m'",
            "BOLD='\\033[1m'",
            "NC='\\033[0m'",
            "",
            "# ------------------------------------------------------------------------------",
            "# Logging & UI Feedback Helpers",
            "# ------------------------------------------------------------------------------",
            "log() {",
            "    local level=\"$1\"",
            "    local msg=\"$2\"",
            "    local time_str",
            "    time_str=\"$(date +\"%Y-%m-%d %H:%M:%S\")\"",
            "    if [ -d \"${LOG_DIR}\" ]; then",
            "        echo -e \"[${time_str}] [${level}] ${msg}\" >> \"${LOG_FILE}\" 2>/dev/null || true",
            "    fi",
            "}",
            "",
            "print_header() {",
            "    echo -e \"${BLUE}========================================================================${NC}\"",
            "    echo -e \"${BOLD}${CYAN} $1 ${NC}\"",
            "    echo -e \"${BLUE}========================================================================${NC}\"",
            "}",
            "",
            "print_step() {",
            "    echo -e \"\\n${BOLD}${YELLOW}➤ $1${NC}\"",
            "    log \"STEP\" \"$1\"",
            "}",
            "",
            "print_success() {",
            "    echo -e \"  ${GREEN}✔ $1${NC}\"",
            "    log \"SUCCESS\" \"$1\"",
            "}",
            "",
            "print_info() {",
            "    echo -e \"  ${BLUE}ℹ $1${NC}\"",
            "    log \"INFO\" \"$1\"",
            "}",
            "",
            "print_warn() {",
            "    echo -e \"  ${YELLOW}⚠ $1${NC}\"",
            "    log \"WARN\" \"$1\"",
            "}",
            "",
            "print_error() {",
            "    echo -e \"  ${RED}✖ $1${NC}\"",
            "    log \"ERROR\" \"$1\"",
            "}",
            "",
            "# ------------------------------------------------------------------------------",
            "# Backup Helpers",
            "# ------------------------------------------------------------------------------",
            "init_backup() {",
            "    mkdir -p \"${LOG_DIR}\"",
            "    mkdir -p \"${CURRENT_BACKUP_DIR}/files\"",
            "    ln -sfn \"${LOG_FILE}\" \"${LATEST_LOG_LINK}\"",
            "    cat <<EOF > \"${MANIFEST_FILE}\"",
            "{",
            "  \"backup_id\": \"backup_${TIMESTAMP}\",",
            "  \"created_at\": \"$(date -u +\"%Y-%m-%dT%H:%M:%SZ\")\",",
            f"  \"hostname\": \"{hostname}\",",
            "  \"status\": \"initialized\"",
            "}",
            "EOF",
            "    log \"BACKUP\" \"Backup initialized at ${CURRENT_BACKUP_DIR}\"",
            "}",
            "",
            "backup_target_file() {",
            "    local src_file=\"$1\"",
            "    if [ -f \"${src_file}\" ] || [ -d \"${src_file}\" ]; then",
            "        local rel_path",
            "        rel_path=\"$(echo \"${src_file}\" | sed 's|^/||')\"",
            "        local dest_path=\"${CURRENT_BACKUP_DIR}/files/${rel_path}\"",
            "        mkdir -p \"$(dirname \"${dest_path}\")\"",
            "        cp -a \"${src_file}\" \"${dest_path}\"",
            "        log \"BACKUP\" \"Backed up ${src_file} -> ${dest_path}\"",
            "    fi",
            "}",
            "",
            "# ------------------------------------------------------------------------------",
            "# Hardening Implementation by Component",
            "# ------------------------------------------------------------------------------"
        ]

        # Generate Component Functions
        active_components = [k for k, v in categorized_actions.items() if len(v) > 0]
        if not active_components:
            active_components = ["system"]

        # Ensure critical baseline configs are always present
        if "sysctl" not in active_components:
            active_components.append("sysctl")
        if "ssh" not in active_components:
            active_components.append("ssh")
        if "docker" not in active_components:
            active_components.append("docker")

        step_idx = 1
        for comp in active_components:
            lines.append(f"apply_{comp}() {{")
            lines.append(f"    print_step \"[{step_idx}/{len(active_components)}] Hardening de {comp.upper()}\"")

            # Custom component backups and logic
            if comp == "sysctl":
                lines.append("    backup_target_file \"/etc/sysctl.d/99-security-hardening.conf\"")
                lines.append("    backup_target_file \"/etc/sysctl.conf\"")
                lines.append("    cat <<'EOF' > /etc/sysctl.d/99-security-hardening.conf")
                lines.append("fs.suid_dumpable = 0")
                lines.append("kernel.randomize_va_space = 2")
                lines.append("kernel.yama.ptrace_scope = 1")
                lines.append("kernel.kptr_restrict = 2")
                lines.append("kernel.dmesg_restrict = 1")
                lines.append("net.ipv4.ip_forward = 0")
                lines.append("net.ipv4.conf.all.send_redirects = 0")
                lines.append("net.ipv4.conf.default.send_redirects = 0")
                lines.append("net.ipv4.conf.all.accept_redirects = 0")
                lines.append("net.ipv4.conf.default.accept_redirects = 0")
                lines.append("net.ipv4.conf.all.rp_filter = 1")
                lines.append("net.ipv4.conf.default.rp_filter = 1")
                lines.append("net.ipv4.tcp_syncookies = 1")
                lines.append("EOF")
                lines.append("    sysctl --system >> \"${LOG_FILE}\" 2>&1")
                lines.append("    print_success \"Parâmetros de Kernel aplicados com sucesso.\"")

            elif comp == "ssh":
                lines.append("    mkdir -p /etc/ssh/sshd_config.d")
                lines.append("    backup_target_file \"/etc/ssh/sshd_config.d/01-security-hardening.conf\"")
                lines.append("    backup_target_file \"/etc/ssh/sshd_config\"")
                lines.append("    cat <<'EOF' > /etc/ssh/sshd_config.d/01-security-hardening.conf")
                lines.append("PermitRootLogin no")
                lines.append("PermitEmptyPasswords no")
                lines.append("MaxAuthTries 4")
                lines.append("X11Forwarding no")
                lines.append("EOF")
                lines.append("    local sshd_bin")
                lines.append("    sshd_bin=\"$(command -v sshd 2>/dev/null || true)\"")
                lines.append("    if [ -z \"${sshd_bin}\" ] && [ -x \"/usr/sbin/sshd\" ]; then sshd_bin=\"/usr/sbin/sshd\"; fi")
                lines.append("    if [ -n \"${sshd_bin}\" ] && [ -x \"${sshd_bin}\" ]; then")
                lines.append("        if \"${sshd_bin}\" -t >> \"${LOG_FILE}\" 2>&1; then")
                lines.append("            systemctl reload ssh >> \"${LOG_FILE}\" 2>&1 || systemctl reload sshd >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("            print_success \"OpenSSH reconfigurado e validado.\"")
                lines.append("        else")
                lines.append("            print_warn \"Falha no teste do sshd. Mantendo baseline preventivo.\"")
                lines.append("        fi")
                lines.append("    else")
                lines.append("        print_info \"OpenSSH Server não instalado. Baseline preventivo gravado em /etc/ssh/sshd_config.d/.\"")
                lines.append("    fi")

            elif comp == "docker":
                lines.append("    if command -v docker >/dev/null 2>&1; then")
                lines.append("        mkdir -p /etc/docker")
                lines.append("        backup_target_file \"/etc/docker/daemon.json\"")
                lines.append("        cat <<'EOF' > /etc/docker/daemon.json")
                lines.append("{\n  \"icc\": false,\n  \"no-new-privileges\": true,\n  \"live-restore\": true,\n  \"userland-proxy\": false\n}")
                lines.append("EOF")
                lines.append("        systemctl restart docker >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        print_success \"Docker daemon configurado com restrição de privilégios.\"")
                lines.append("    fi")

            elif comp == "modules":
                lines.append("    for mod in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do")
                lines.append("        local mfile=\"/etc/modprobe.d/${mod}.conf\"")
                lines.append("        backup_target_file \"${mfile}\"")
                lines.append("        echo \"install ${mod} /bin/true\" > \"${mfile}\"")
                lines.append("        echo \"blacklist ${mod}\" >> \"${mfile}\"")
                lines.append("    done")
                lines.append("    print_success \"Módulos de kernel obsoletos bloqueados.\"")

            elif comp == "firewall":
                lines.append("    if command -v ufw >/dev/null 2>&1; then")
                lines.append("        ufw default deny incoming >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        ufw default allow outgoing >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        ufw allow ssh >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        ufw --force enable >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        print_success \"Firewall UFW ativado (Incoming bloqueado, SSH permitido).\"")
                lines.append("    elif command -v nft >/dev/null 2>&1; then")
                lines.append("        systemctl enable --now nftables >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        print_success \"Firewall nftables ativado.\"")
                lines.append("    fi")

            elif comp == "auditd":
                lines.append("    if [ -x \"/usr/sbin/auditd\" ] || command -v auditd >/dev/null 2>&1 || systemctl list-unit-files 2>/dev/null | grep -q \"auditd\"; then")
                lines.append("        systemctl enable auditd >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        systemctl restart auditd >> \"${LOG_FILE}\" 2>&1 || service auditd restart >> \"${LOG_FILE}\" 2>&1 || /usr/sbin/auditd >> \"${LOG_FILE}\" 2>&1 || true")
                lines.append("        print_success \"Serviço auditd ativado e em execução.\"")
                lines.append("    else")
                lines.append("        print_warn \"auditd não localizado como serviço no sistema.\"")
                lines.append("    fi")

            elif comp == "aide":
                lines.append("    if command -v aide >/dev/null 2>&1 || [ -x \"/usr/bin/aide\" ]; then")
                lines.append("        if [ -f \"/var/lib/aide/aide.db\" ] || [ -f \"/var/lib/aide/aide.db.gz\" ]; then")
                lines.append("            print_success \"Base AIDE já inicializada anteriormente.\"")
                lines.append("        else")
                lines.append("            print_info \"Disparando geração de baseline AIDE em segundo plano (-y -f -b)...\"")
                lines.append("            if [ -x \"/usr/sbin/aideinit\" ] || command -v aideinit >/dev/null 2>&1; then")
                lines.append("                aideinit -y -f -b >> \"${LOG_FILE}\" 2>&1 || (nohup aideinit -y -f >/dev/null 2>&1 &) || true")
                lines.append("            else")
                lines.append("                (nohup aide --init -c /etc/aide/aide.conf >/dev/null 2>&1 && cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db &) || true")
                lines.append("            fi")
                lines.append("            print_success \"Inicialização do AIDE executando em segundo plano de forma não-bloqueante.\"")
                lines.append("        fi")
                lines.append("    fi")

            elif comp == "permissions":
                lines.append("    backup_target_file \"/etc/passwd\"")
                lines.append("    backup_target_file \"/etc/shadow\"")
                lines.append("    backup_target_file \"/etc/sudoers\"")
                lines.append("    [ -f /etc/passwd ] && chown root:root /etc/passwd && chmod 0644 /etc/passwd")
                lines.append("    [ -f /etc/shadow ] && (chown root:shadow /etc/shadow 2>/dev/null || chown root:root /etc/shadow) && chmod 0640 /etc/shadow")
                lines.append("    [ -f /etc/sudoers ] && chown root:root /etc/sudoers && chmod 0440 /etc/sudoers")
                lines.append("    print_success \"Permissões estritas em arquivos críticos ajustadas.\"")

            # Execute any specific findings commands registered for this component
            for action in categorized_actions.get(comp, []):
                cmd_raw = action["command"]
                # Skip trivial echoes if handled
                if not ("echo 'permitrootlogin" in cmd_raw.lower() or "sysctl -w net.ipv4" in cmd_raw.lower()):
                    lines.append(f"    # Fix for {action['id']}: {action['title']}")
                    lines.append(f"    print_info \"Executando ajuste: {action['id']}...\"")
                    lines.append(f"    {cmd_raw} >> \"${{LOG_FILE}}\" 2>&1 || print_warn \"Comando retornou código não-zero para {action['id']}\"")

            lines.append("}")
            lines.append("")
            step_idx += 1

        # Rollback & Dispatcher logic
        lines.extend([
            "# ------------------------------------------------------------------------------",
            "# Rollback Functions",
            "# ------------------------------------------------------------------------------",
            "list_backups() {",
            "    print_header \"📦 Backups de Hardening Disponíveis\"",
            "    if [ ! -d \"${BACKUP_BASE_DIR}\" ]; then",
            "        echo \"Nenhum backup encontrado em ${BACKUP_BASE_DIR}.\"",
            "        return 0",
            "    fi",
            "    for bdir in $(ls -d \"${BACKUP_BASE_DIR}\"/backup_* 2>/dev/null | sort -r); do",
            "        local bname",
            "        bname=\"$(basename \"${bdir}\")\"",
            "        local bfiles",
            "        bfiles=\"$(find \"${bdir}/files\" -type f 2>/dev/null | wc -l)\"",
            "        echo -e \" • ${BOLD}${CYAN}${bname}${NC} | Arquivos: ${bfiles} | Data: $(stat -c \"%y\" \"${bdir}\")\"",
            "    done",
            "}",
            "",
            "get_target_backup_dir() {",
            "    local target_id=\"${1:-latest}\"",
            "    if [ \"${target_id}\" = \"latest\" ]; then",
            "        ls -d \"${BACKUP_BASE_DIR}\"/backup_* 2>/dev/null | sort -r | head -n 1",
            "    else",
            "        if [ -d \"${BACKUP_BASE_DIR}/${target_id}\" ]; then",
            "            echo \"${BACKUP_BASE_DIR}/${target_id}\"",
            "        else",
            "            echo \"\"",
            "        fi",
            "    fi",
            "}",
            "",
            "rollback_general() {",
            "    local target_dir",
            "    target_dir=\"$(get_target_backup_dir \"${1:-latest}\")\"",
            "    if [ -z \"${target_dir}\" ] || [ ! -d \"${target_dir}\" ]; then",
            "        print_error \"Backup não encontrado.\"",
            "        exit 1",
            "    fi",
            "    print_header \"⏪ Executando Rollback Geral a partir de: $(basename \"${target_dir}\")\"",
            "    if [ -d \"${target_dir}/files\" ]; then",
            "        cd \"${target_dir}/files\"",
            "        find . -type f | while read -r file; do",
            "            local dest_file=\"/${file#./}\"",
            "            print_info \"Restaurando ${dest_file}...\"",
            "            mkdir -p \"$(dirname \"${dest_file}\")\"",
            "            cp -a \"${file}\" \"${dest_file}\"",
            "        done",
            "        cd - >/dev/null",
            "    fi",
            "    rm -f /etc/sysctl.d/99-security-hardening.conf",
            "    rm -f /etc/ssh/sshd_config.d/01-security-hardening.conf",
            "    sysctl --system >> \"${LOG_FILE}\" 2>&1 || true",
            "    systemctl reload ssh >> \"${LOG_FILE}\" 2>&1 || systemctl reload sshd >> \"${LOG_FILE}\" 2>&1 || true",
            "    print_success \"Rollback Geral concluído com sucesso!\"",
            "}",
            "",
            "rollback_component() {",
            "    local comp=\"$1\"",
            "    local target_dir",
            "    target_dir=\"$(get_target_backup_dir \"${2:-latest}\")\"",
            "    if [ -z \"${target_dir}\" ] || [ ! -d \"${target_dir}\" ]; then",
            "        print_error \"Backup não encontrado.\"",
            "        exit 1",
            "    fi",
            "    print_header \"⏪ Rollback do Componente: ${comp}\"",
            "    case \"${comp}\" in",
            "        sysctl)",
            "            rm -f /etc/sysctl.d/99-security-hardening.conf",
            "            [ -f \"${target_dir}/files/etc/sysctl.conf\" ] && cp -a \"${target_dir}/files/etc/sysctl.conf\" /etc/sysctl.conf",
            "            sysctl --system >> \"${LOG_FILE}\" 2>&1 || true",
            "            print_success \"Sysctl restaurado.\"",
            "            ;;",
            "        ssh)",
            "            rm -f /etc/ssh/sshd_config.d/01-security-hardening.conf",
            "            [ -f \"${target_dir}/files/etc/ssh/sshd_config\" ] && cp -a \"${target_dir}/files/etc/ssh/sshd_config\" /etc/ssh/sshd_config",
            "            systemctl reload ssh >> \"${LOG_FILE}\" 2>&1 || systemctl reload sshd >> \"${LOG_FILE}\" 2>&1 || true",
            "            print_success \"OpenSSH restaurado.\"",
            "            ;;",
            "        docker)",
            "            if [ -f \"${target_dir}/files/etc/docker/daemon.json\" ]; then",
            "                cp -a \"${target_dir}/files/etc/docker/daemon.json\" /etc/docker/daemon.json",
            "            else",
            "                rm -f /etc/docker/daemon.json",
            "            fi",
            "            systemctl restart docker >> \"${LOG_FILE}\" 2>&1 || true",
            "            print_success \"Docker daemon restaurado.\"",
            "            ;;",
            "        modules)",
            "            for mod in cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc; do",
            "                rm -f \"/etc/modprobe.d/${mod}.conf\"",
            "            done",
            "            print_success \"Módulos restaurados.\"",
            "            ;;",
            "        *)",
            "            print_error \"Componente desconhecido: '${comp}'. Opções: sysctl, ssh, docker, modules\"",
            "            exit 1",
            "            ;;",
            "    esac",
            "}",
            "",
            "show_help() {",
            "    echo -e \"${BOLD}Uso:${NC} sudo $0 [OPÇÃO]\"",
            "    echo \"\"",
            "    echo -e \"${BOLD}Opções disponíveis:${NC}\"",
            "    echo \"  --apply                      Aplica todo o conjunto de hardening com backup automático (Padrão)\"",
            "    echo \"  --list-backups               Lista todos os snapshots de backup salvos no sistema\"",
            "    echo \"  --rollback [BACKUP_ID]       Restaura o estado do sistema a partir do último backup\"",
            "    echo \"  --rollback-comp <COMPONENTE> Restaura apenas um componente (sysctl, ssh, docker, modules)\"",
            "    echo \"  --help                       Exibe esta mensagem de ajuda\"",
            "}",
            "",
            "# ------------------------------------------------------------------------------",
            "# Main Dispatcher",
            "# ------------------------------------------------------------------------------",
            "main() {",
            "    local mode=\"${1:---apply}\"",
            "",
            "    if [ \"${mode}\" = \"--help\" ] || [ \"${mode}\" = \"-h\" ]; then",
            "        show_help",
            "        exit 0",
            "    fi",
            "",
            "    if [ \"$(id -u)\" -ne 0 ]; then",
            "        echo -e \"${RED}[!] Erro: Este script precisa ser executado como root (use sudo).${NC}\"",
            "        echo \"    Exemplo: sudo bash $0 --apply\"",
            "        exit 1",
            "    fi",
            "",
            "    case \"${mode}\" in",
            "        --apply)",
            "            init_backup",
            "            print_header \"🛡️  Iniciando Aplicação de Hardening e Correções de Segurança\"",
            "            print_info \"Backup automático em : ${CURRENT_BACKUP_DIR}\"",
            "            print_info \"Registro de log em   : ${LOG_FILE}\"",
            ""
        ])

        for comp in active_components:
            lines.append(f"            apply_{comp}")

        lines.extend([
            "",
            "            print_header \"✅ Hardening Concluído com Sucesso!\"",
            "            echo -e \" 📁 Backup dos arquivos originais : ${BOLD}${GREEN}${CURRENT_BACKUP_DIR}${NC}\"",
            "            echo -e \" 📄 Registro detalhado de logs    : ${BOLD}${GREEN}${LOG_FILE}${NC}\"",
            "            echo -e \"\\n Para reverter as alterações a qualquer momento, execute:\"",
            "            echo -e \"   ${BOLD}${YELLOW}sudo $0 --rollback${NC}  ou  ${BOLD}${YELLOW}sudo $0 --rollback-comp <componente>${NC}\"",
            "            echo -e \"\\n Para auditar e verificar o novo índice de conformidade:\"",
            "            echo -e \"   ${BOLD}${CYAN}sudo sec-audit-linux audit --all${NC}\"",
            "            echo -e \"${BLUE}========================================================================${NC}\"",
            "            ;;",
            "        --list-backups)",
            "            list_backups",
            "            ;;",
            "        --rollback)",
            "            rollback_general \"${2:-latest}\"",
            "            ;;",
            "        --rollback-comp)",
            "            rollback_component \"${2:-}\" \"${3:-latest}\"",
            "            ;;",
            "        *)",
            "            show_help",
            "            exit 1",
            "            ;;",
            "    esac",
            "}",
            "",
            "main \"$@\"",
            ""
        ])

        return "\n".join(lines)
