# Linux Security Assessment & Compliance Automation

Plataforma unificada para auditoria técnica, coleta de evidências imutáveis, validação de conformidade, avaliação de hardening e geração automatizada de relatórios para sistemas operacionais **Linux**.

---

## 🎯 Visão Geral do Projeto

A solução foi projetada para atuar como um motor automatizado de auditoria de segurança Linux capaz de:
1. **Inspecionar** nativamente arquivos de configuração, subsistemas do Kernel, parâmetros `sysctl`, `systemd`, `PAM`, `SSH`, privilégios `sudo`, `SELinux`, `AppArmor`, firewall, containers e criptografia.
2. **Integrar** ferramentas consagradas de auditoria e vulnerabilidades (*Lynis, OpenSCAP, AIDE, osquery, Trivy, Docker Bench, kube-bench*) com fallback automático para inspeção nativa.
3. **Correlacionar** evidências técnicas com os principais frameworks de segurança e conformidade da indústria.
4. **Calcular** a aderência percentual normalizada utilizando as fórmulas e perfis de cada framework.
5. **Gerar** documentação e relatórios técnicos e executivos em **Markdown** e payloads estruturados em **JSON** para consumo por humanos e Agentes LLM.
6. **Disponibilizar** interfaces de interação via **CLI** (linha de comando) e **MCP Server** (*Model Context Protocol*) para LLMs e automação multi-agente (ADK2).

---

## 🏛️ Arquitetura e Guias

- 📘 [**Guia de Arquitetura Técnica**](docs/ARCHITECTURE.md): Detalhamento do Core Engine, modelo de dados unificado, coletores, adaptadores e fórmulas de cálculo.
- 🤖 [**Modelo de Agentes de Arquitetura**](docs/AGENTS.md): Definição de papéis, fluxos e ferramentas dos agentes (*Lead Auditor*, *Collector*, *Compliance Analyst*, *Remediation & Reporter*).

---

## 📚 Catálogo de Skills do Projeto

| Categoria | Skill | Caminho | Descrição |
| :--- | :--- | :--- | :--- |
| **Engenharia** | `clean-code-reusability` | [`skills/general/engineering-practices/clean-code-reusability/SKILL.md`](skills/general/engineering-practices/clean-code-reusability/SKILL.md) | Diretrizes para Clean Code, SOLID, modularidade e reuso ativo de código. |
| **Auditoria** | `linux-collector` | [`skills/security-audit/linux-collector/SKILL.md`](skills/security-audit/linux-collector/SKILL.md) | Padrões de inspeção de baixo nível no Linux e adaptadores de ferramentas. |
| **Compliance** | `compliance-mapping` | [`skills/security-audit/compliance-mapping/SKILL.md`](skills/security-audit/compliance-mapping/SKILL.md) | Metodologia de mapeamento de controles e cálculo de aderência por framework. |
| **Evidências** | `evidence-reporting` | [`skills/security-audit/evidence-reporting/SKILL.md`](skills/security-audit/evidence-reporting/SKILL.md) | Geração de relatórios executivos/técnicos em Markdown, JSON e hashes SHA-256. |

---

## 🛡️ Frameworks de Conformidade Suportados

| Framework | Versão / Perfil | Escopo no Linux |
| :--- | :--- | :--- |
| **CIS Benchmarks** | Level 1 & Level 2 (Server / Workstation) | Hardening granular de SO, bootloader, kernel, SSH, PAM e logging. |
| **CIS Controls** | v8 (IG1, IG2, IG3) | Higiene de segurança cibernética e controles prioritários. |
| **NIST CSF** | 2.0 (GV, ID, PR, DE, RS, RC) | Gestão de risco cibernético e funções de governança/proteção. |
| **NIST SP 800-53** | Rev 5 (Famílias AC, AU, CM, IA, SC, SI) | Controles de segurança e privacidade para sistemas federais e corporativos. |
| **ISO/IEC 27001** | 2022 (Anexo A - Cláusula 8) | Controles tecnológicos de segurança da informação em hosts. |
| **PCI DSS** | v4.0 (Requisitos 2, 7, 8, 10, 11) | Proteção do ambiente de dados de titulares de cartão (CDE). |
| **MITRE ATT&CK** | Enterprise Linux Matrix | Cobertura de detecção e mitigação de TTPs de adversários. |
| **SCAP / SSG** | SCAP 1.3 / XCCDF Profiles | Automação de conformidade com perfis do SCAP Security Guide. |

---

## 🐧 Distribuições Linux Suportadas

- **Família Red Hat / RPM**: RHEL 8/9, Rocky Linux 8/9, AlmaLinux 8/9, Oracle Linux 8/9, CentOS Stream 9.
- **Família Debian**: Debian 11/12, Ubuntu Server 20.04/22.04/24.04 LTS.
- **Família SUSE**: SUSE Linux Enterprise Server (SLES) 15, openSUSE Leap / Tumbleweed.

---

## 🛠️ Ferramentas Auxiliares Integráveis

- **Compliance & Hardening**: `Lynis`, `OpenSCAP`, `SCAP Security Guide (SSG)`.
- **Auditoria & Monitoramento**: `auditd`, `AIDE`, `osquery`.
- **Vulnerabilidades & Supply Chain**: `Trivy`, `Grype`, `Syft`.
- **Containers & Cloud Native**: `Docker Bench Security`, `kube-bench`, `kube-hunter`, `Falco`.

---

## 🔌 Interfaces do Sistema

### 1. Interface de Linha de Comando (CLI)
```bash
# Auditoria completa de todos os frameworks
sec-audit-linux audit --all --output-dir ./reports/

# Auditoria focada em CIS Benchmarks e NIST 800-53
sec-audit-linux audit --framework cis_benchmarks,nist_800_53 --output-format markdown,json

# Auditoria de componentes específicos (ex: SSH e PAM)
sec-audit-linux audit --component ssh,identity --output-format markdown
```

### 2. Interface MCP Server (Model Context Protocol)
Permite que Modelos de Linguagem (LLMs) executem auditorias, inspecionem evidências pontuais e consultem guias de remediação através de chamadas de ferramentas padronizadas via JSON-RPC.
