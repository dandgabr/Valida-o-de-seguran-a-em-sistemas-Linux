# Linux Security Assessment & Compliance Automation

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Standards](https://img.shields.io/badge/Compliance-CIS%20%7C%20NIST%20%7C%20ISO%20%7C%20PCI-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Containers-lightgrey.svg)]()

Plataforma unificada de auditoria de segurança, coleta de evidências imutáveis, validação de conformidade regulatória, inspeção profunda de contêineres e geração automatizada de hardening com rollback para sistemas operacionais **Linux**.

---

## 🎯 Visão Geral do Projeto

A solução foi projetada para atuar como um motor automatizado e extensível de cibersegurança Linux capaz de:
1. **Inspecionar Nativamente**: Arquivos de configuração, subsistemas do Kernel (`sysctl`), `systemd`, `PAM`, `SSH`, privilégios `sudoers`, `SELinux`, `AppArmor`, firewall (`UFW`/`nftables`), contêineres Docker e políticas criptográficas.
2. **Integrar 11 Ferramentas Open-Source Corporativas**: *Lynis, Checksec, Docker Bench for Security, Trivy, Grype, Syft (SBOM), RKHunter, AIDE (FIM), kube-bench, osquery, OpenSCAP*.
3. **Deduplicação e Correlação Multi-Fonte**: Motor inteligente que unifica alertas repetidos entre ferramentas e normas em um **Ledger Único de Achados** com rastreabilidade cruzada de fontes (`CIS`, `NIST`, `MITRE`, `Lynis`).
4. **Inspeção Profunda de Docker & Containers**: Análise de `daemon.json`, sockets locais, contêineres privilegiados (`--privileged`), modos de rede (`--net=host`), montagens sensíveis de host e inventário SBOM com varredura de CVEs.
5. **Hardening Corporativo com Rollback e Logs**: Geração automática de scripts de remediação com feedback visual colorido, logs em `/var/log/hardening/`, backups com manifesto em `/var/backups/hardening/` e rollback geral ou granular por componente (`--rollback-comp <comp>`).
6. **Firewall Restrito a RFC 1918**: Políticas de bloqueio por padrão com liberação de SSH restrita às classes A, B e C da RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
7. **Interfaces Múltiplas**: Linha de comando (**CLI**) e servidor **MCP** (*Model Context Protocol*) para agentes autônomos e LLMs.

---

## 🏛️ Documentação e Guias

- 📘 [**Guia de Arquitetura Técnica**](docs/ARCHITECTURE.md): Detalhamento do Core Engine, modelo de dados, coletores, validadores e deduplicação.
- 🛡️ [**Guia de Hardening, Logs e Rollback**](docs/HARDENING_AND_ROLLBACK.md): Manual completo de aplicação, logs, snapshots de backup e comandos de reversão.
- 🧰 [**Integrações de Ferramentas Open-Source**](docs/TOOLS_INTEGRATIONS.md): Detalhamento das 11 ferramentas integradas, licenças, comandos e relatórios individuais.
- 🤖 [**Modelo de Agentes de Arquitetura**](docs/AGENTS.md): Definição de papéis e fluxos de trabalho dos agentes autônomos.

---

## 🛡️ Frameworks de Conformidade Suportados

| Framework | Versão / Perfil | Escopo de Avaliação no Linux |
| :--- | :---: | :--- |
| **CIS Linux Benchmark** | `v3.0.0` (L1 & L2) | Hardening granular de SO, bootloader, kernel, SSH, PAM, logging e permissões. |
| **CIS Critical Security Controls** | `v8.0` (IG1, IG2, IG3) | Higiene cibernética essencial, inventário de ativos e privilégios mínimos. |
| **NIST CSF 2.0** | `2.0` (GV, ID, PR, DE, RS, RC) | Gestão de risco cibernético, governança e proteção de endpoints. |
| **NIST SP 800-53** | `Rev 5` (AC, AU, CM, IA, SC, SI) | Catálogo de controles de segurança para ambientes federais e corporativos. |
| **ISO/IEC 27001** | `2022` (Anexo A - Cláusula 8) | Controles tecnológicos de segurança da informação em hosts e servidores. |
| **PCI DSS** | `v4.0` (Reqs 2, 7, 8, 10, 11) | Requisitos para ambientes de processamento de dados de cartões (CDE). |
| **MITRE ATT&CK** | `v15.0` (Enterprise Linux) | Cobertura e mitigação de Táticas, Técnicas e Procedimentos (TTPs). |
| **SCAP / SSG** | `1.3` (XCCDF Profiles) | Avaliação automatizada de conformidade com perfis do SCAP Security Guide. |

---

## 🛠️ Ferramentas Open-Source Integradas (Livres para Uso Corporativo)

| Ferramenta | Categoria | Licença | Finalidade no Motor |
| :--- | :--- | :---: | :--- |
| **Lynis** | Auditoria e Hardening | `GPL-3.0` | Varredura profunda do sistema operacional e hardening index. |
| **Checksec** | Mitigações de Compilador | `BSD-3-Clause` | Inspeção de PIE, Full RELRO, Stack Canary e NX em binários (`sudo`, `su`, `passwd`). |
| **Docker Bench** | CIS Docker Benchmark | `Apache-2.0` | Auditoria de conformidade para daemon Docker e contêineres. |
| **Trivy** | Scanner de Vulnerabilidades | `Apache-2.0` | Detecção de CVEs Críticas e Altas no sistema e imagens Docker. |
| **Grype** | Scanner de Vulnerabilidades | `Apache-2.0` | Varredura rápida de vulnerabilidades em pacotes de sistema instalados. |
| **Syft** | Supply Chain / SBOM | `Apache-2.0` | Geração de Software Bill of Materials para bibliotecas, JARs, Gems e PyPI. |
| **RKHunter** | Detecção de Malware | `GPL-2.0` | Varredura de rootkits, trojans e alterações suspeitas no kernel. |
| **AIDE** | Integridade de Arquivos (FIM) | `GPL-2.0` | Monitoramento e detecção de adulterações em binários do sistema. |
| **kube-bench** | Kubernetes Security | `Apache-2.0` | Auditoria CIS Kubernetes Benchmark para nós de cluster. |
| **osquery** | Instrumentação SQL | `Apache-2.0` | Consultas relacionais SQL ao estado de baixo nível do sistema operacional. |
| **OpenSCAP** | Automação SCAP | `LGPL-2.1` | Scanner XCCDF/OVAL com perfis oficiais da indústria. |

---

## 🚀 Instalação e Uso Rápido

### 1. Instalação Automática de Dependências e Atalhos
Execute o instalador multiplataforma para configurar os atalhos globais no sistema:

```bash
# Instala dependências do SO (apt/dnf/zypper/pacman) e cria atalhos globais
sudo ./scripts/install_system_bin.sh
```

---

### 2. Executando a Auditoria Completa

Para executar a auditoria em todos os 8 frameworks e 11 ferramentas com privilégios elevados:

```bash
sudo sec-audit-linux audit --all --output-dir ./audit_reports
```

#### Relatórios Gerados em `./audit_reports/`:
- 📊 **`executive_report.md`**: Resumo executivo com scoreboard e **Tabela de Achados Deduplicados Multi-Fonte**.
- 📋 **`technical_report.md`**: Trilha técnica detalhada com justificativas, evidências e comandos.
- 💾 **`assessment_result.json`**: Payload estruturado completo pronto para ingestão por SIEM e Agentes LLM.
- ⚡ **`remediation_playbook.sh`**: Script de remediação empresarial com backup, logs e rollback.
- 🧰 **`tools/`**: Relatórios individuais autônomos gerados por cada ferramenta (*Lynis, Checksec, Syft, Trivy, Docker Bench, RKHunter, AIDE*).

---

### 3. Outros Comandos da CLI

```bash
# Exibir diagnóstico e contexto do sistema operacional detectado
sec-audit-linux system-info

# Listar todos os frameworks de conformidade suportados
sec-audit-linux list-frameworks

# Listar os 10 coletores de componentes auditáveis
sec-audit-linux list-components

# Listar as 11 ferramentas integradas e seus status de instalação
sec-audit-linux list-tools

# Auditoria filtrada apenas para CIS Benchmarks e NIST 800-53
sudo sec-audit-linux audit --framework cis_benchmarks,nist_800_53 --output-dir ./audit_reports

# Auditoria filtrada apenas para componentes de SSH e Containers
sudo sec-audit-linux audit --component ssh,containers --output-dir ./audit_reports
```

---

### 4. Executando o Script de Hardening com Logs e Rollback

O script gerado permite aplicar as correções e reverter qualquer alteração com facilidade:

```bash
# 1. Aplicar todas as 10 etapas de hardening (com backup e logs automáticos):
sudo ./audit_reports/remediation_playbook.sh --apply

# 2. Listar os snapshots de backup salvos no sistema:
sudo ./audit_reports/remediation_playbook.sh --list-backups

# 3. Desfazer 100% das alterações (Rollback Geral):
sudo ./audit_reports/remediation_playbook.sh --rollback

# 4. Desfazer apenas um serviço específico (Rollback Granular):
sudo ./audit_reports/remediation_playbook.sh --rollback-comp ssh
sudo ./audit_reports/remediation_playbook.sh --rollback-comp sysctl
sudo ./audit_reports/remediation_playbook.sh --rollback-comp docker
sudo ./audit_reports/remediation_playbook.sh --rollback-comp sudoers
```

---

### 5. Execução do Servidor MCP (Model Context Protocol)

Para conectar o motor de auditoria ao Claude Desktop, Antigravity ou orquestradores ADK2:

```bash
sec-audit-mcp
```

#### Ferramentas MCP Expostas:
- `run_security_audit`: Executa a avaliação completa ou filtrada e retorna JSON estruturado.
- `inspect_evidence`: Consulta evidências técnicas brutas de um componente específico.
- `get_system_context`: Retorna os metadados do host (OS, kernel, init system, virtualization).
- `generate_remediation_plan`: Gera script de hardening dinâmico para os achados detectados.
- `list_integrated_security_tools`: Lista ferramentas open-source instaladas e suas métricas.
- `get_individual_tool_report`: Retorna o relatório independente de uma ferramenta em Markdown/JSON.

---

## 🧪 Suíte de Testes Automatizados

O projeto conta com uma suíte de testes unitários e de integração abrangendo coletores, frameworks, adaptadores de ferramentas, deduplicação, CLI e servidor MCP:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v
```

---

## 📄 Licença

Este projeto é distribuído sob a licença **Apache 2.0**. Todas as ferramentas externas integradas são de código aberto (*Open Source*) com licenças compatíveis e livres para uso comercial/corporativo (*Apache-2.0, BSD-3-Clause, MIT, GPL-2.0/3.0, LGPL-2.1*).
