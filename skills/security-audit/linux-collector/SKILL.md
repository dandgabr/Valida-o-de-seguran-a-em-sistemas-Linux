---
name: linux-collector
description: Detailed guidelines, best practices, and patterns for implementing native Linux security collectors and external tool adapters.
---

# Linux Collector & Inspector Skill

Este guia define os padrões e procedimentos técnicos para a implementação de coletores de evidências nativos em distribuições Linux e adaptadores de ferramentas de auditoria.

## 🎯 Escopo dos Coletores

Cada coletor é responsável por inspecionar uma área do sistema operacional Linux, registrar evidências brutas com SHA-256 e disponibilizar dados estruturados (`parsed_data`) para avaliação de conformidade.

---

## 🛠️ Padrão de Implementação de Coletor

Todos os coletores devem herdar de `sec_audit_linux.collectors.base.BaseCollector` e implementar o método `collect(system_context) -> List[EvidenceRecord]`.

### Exemplo de Estrutura:

```python
from sec_audit_linux.collectors.base import BaseCollector
from sec_audit_linux.core.models import EvidenceRecord, SystemContext
from sec_audit_linux.core.utils import read_system_file, execute_command, calculate_sha256
from typing import List

class SSHCollector(BaseCollector):
    """Collector responsible for auditing OpenSSH server configuration and cryptographic suites."""
    
    name = "ssh"
    description = "OpenSSH Server configuration, authentication rules, and cipher suites"

    def collect(self, context: SystemContext) -> List[EvidenceRecord]:
        evidences = []
        
        # 1. Inspect main sshd configuration
        sshd_config_path = "/etc/ssh/sshd_config"
        content, error = read_system_file(sshd_config_path)
        
        if content:
            evidences.append(EvidenceRecord(
                collector_name=self.name,
                target_item=sshd_config_path,
                raw_output=content,
                parsed_data=self._parse_sshd_config(content),
                sha256_checksum=calculate_sha256(content)
            ))
            
        # 2. Inspect active effective runtime sshd settings
        cmd_out, cmd_err, exit_code = execute_command(["sshd", "-T"])
        if exit_code == 0:
            evidences.append(EvidenceRecord(
                collector_name=self.name,
                target_item="sshd_effective_runtime",
                command_executed="sshd -T",
                raw_output=cmd_out,
                parsed_data=self._parse_effective_sshd(cmd_out),
                sha256_checksum=calculate_sha256(cmd_out)
            ))
            
        return evidences
```

---

## 📋 Mapeamento de Coletores por Componente

| Componente | Fontes Nativas Primárias | Ferramentas Auxiliares |
| :--- | :--- | :--- |
| **Kernel & Boot** | `/proc/sys/*`, `/etc/sysctl.d/*`, `/boot/grub*/grub.cfg`, `/sys/firmware/efi` | `sysctl -a`, `mokutil --sb-state` |
| **Systemd & Serviços** | `systemctl list-unit-files`, `systemctl list-units --type=service` | `systemd-analyze security` |
| **Pacotes & Atualizações** | `/etc/apt/sources.list*`, `/etc/yum.repos.d/*`, `rpm -qa`, `dpkg -l` | `yum check-update`, `apt list --upgradable` |
| **Identidade & Contas** | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/login.defs` | `pwck`, `grpck` |
| **Autenticação & PAM** | `/etc/pam.d/*`, `/etc/security/pwquality.conf`, `/etc/security/faillock.conf` | `authselect current` |
| **Privilégios & Sudo** | `/etc/sudoers`, `/etc/sudoers.d/*` | `sudo -l -U <user>` |
| **Controle de Acesso (MAC)** | `sestatus`, `/etc/selinux/config`, `aa-status`, `apparmor_status` | SELinux booleans, AppArmor profiles |
| **Rede & Firewall** | `/proc/net/*`, `ss -tulpn`, `nft list ruleset`, `iptables-save`, `ufw status` | `firewall-cmd --list-all` |
| **SSH** | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/*`, `sshd -T` | `ssh -Q cipher`, `ssh -Q mac` |
| **Auditoria & Logs** | `/etc/audit/auditd.conf`, `/etc/audit/rules.d/*`, `auditctl -l`, `/etc/rsyslog.conf` | `aureport`, `ausearch` |
| **Integridade (FIM)** | `/var/lib/aide/aide.db.gz`, `/etc/aide.conf` | `aide --check`, `osqueryi` |
| **Containers** | `/var/run/docker.sock`, `/etc/docker/daemon.json`, `docker info` | `docker-bench-security`, `kube-bench` |
| **Criptografia** | `update-crypto-policies --show`, `/etc/crypttab`, `lsblk -f` | `cryptsetup status`, OpenSSL cert checks |

---

## 🔒 Princípios de Segurança do Coletor
1. **Nunca executar comandos que alterem o estado** do sistema operacional (`read-only`).
2. **Definir timeouts estritos** (máximo 15 segundos) em todas as execuções de comandos externos para evitar travamentos em pipes interativos ou prompts.
3. **Tratar dados sensíveis**: valores em arquivos como `/etc/shadow` devem extrair apenas metadados (ex: tipo de hash, dias desde alteração, campos vazios) sem expor hashes de senhas desnecessariamente em relatórios públicos.
