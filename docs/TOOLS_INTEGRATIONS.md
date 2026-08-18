# 🧰 Guia de Integração de Ferramentas Open-Source

Este documento detalha o funcionamento, as licenças, as categorias, as bandeiras de execução não-bloqueantes e os relatórios individuais produzidos pelas **11 ferramentas open-source** integradas ao motor de auditoria.

Todas as ferramentas selecionadas são **livres para uso corporativo e comercial** (*Commercial / Corporate Free*).

---

## 📋 1. Catálogo Completo das 11 Ferramentas

| Ferramenta | Categoria | Licença de Uso | Binário Padrão | Status no Host |
| :--- | :--- | :---: | :--- | :---: |
| **Lynis** | Auditoria e Hardening de SO | `GPL-3.0` | `/usr/sbin/lynis` | ✅ Instalado |
| **Checksec** | Mitigações de Compilador | `BSD-3-Clause` | `/usr/bin/checksec` | ✅ Instalado |
| **Docker Bench** | CIS Docker Benchmark | `Apache-2.0` | `/usr/local/bin/docker-bench-security` | ✅ Instalado |
| **Trivy** | Scanner de Vulnerabilidades e Segredos | `Apache-2.0` | `/usr/local/bin/trivy` | ✅ Instalado |
| **Grype** | Scanner de Vulnerabilidades em Pacotes | `Apache-2.0` | `/usr/local/bin/grype` | ✅ Instalado |
| **Syft** | Supply Chain & SBOM (*Software Bill of Materials*) | `Apache-2.0` | `/usr/local/bin/syft` | ✅ Instalado |
| **RKHunter** | Detecção de Rootkits e Trojans | `GPL-2.0` | `/usr/bin/rkhunter` | ✅ Instalado |
| **AIDE** | File Integrity Monitoring (FIM) | `GPL-2.0` | `/usr/bin/aide` | ✅ Instalado |
| **kube-bench** | CIS Kubernetes Benchmark | `Apache-2.0` | `/usr/local/bin/kube-bench` | ℹ️ Fallback se sem K8s |
| **osquery** | Instrumentação Relacional SQL do SO | `Apache-2.0` | `/usr/bin/osqueryi` | ℹ️ Fallback se ausente |
| **OpenSCAP** | Scanner XCCDF/OVAL de Conformidade | `LGPL-2.1` | `/usr/bin/oscap` | ℹ️ Fallback se ausente |

---

## 🔍 2. Detalhamento Operacional de Cada Adaptador

### 1. Lynis (`LynisAdapter`)
- **Objetivo**: Avalia a postura de segurança geral do Linux, índices de hardening (*Hardening Index*), configurações do kernel e sugestões de mitigação.
- **Comando Executado**:
  ```bash
  lynis audit system --quick --cronjob --report-file /tmp/lynis-report.dat
  ```
- **Relatório Gerado**: `audit_reports/tools/lynis_report.md` e `.json`.

---

### 2. Checksec (`ChecksecAdapter`)
- **Objetivo**: Verifica a presença de proteções de compilador contra estouro de buffer e corrupção de memória nos binários executáveis essenciais (`sudo`, `passwd`, `su`, `dockerd`).
- **Propriedades Inspecionadas**:
  - **PIE (*Position Independent Executable*)**: Permite carga em endereços aleatórios de memória (ASLR).
  - **RELRO (*Relocation Read-Only*)**: Protege a tabela GOT (*Global Offset Table*) contra sobrescrita maliciosa.
  - **Stack Canary**: Valor sentinela que detecta estouro de pilha antes de desvios de ponteiro de instrução.
  - **NX (*No-Execute / DEP*)**: Impede a execução de código na pilha ou heap.
- **Comando Executado**:
  ```bash
  checksec --file=/usr/bin/sudo --format=json
  ```
- **Relatório Gerado**: `audit_reports/tools/checksec_report.md` e `.json`.

---

### 3. Docker Bench for Security (`DockerBenchAdapter`)
- **Objetivo**: Avalia o daemon Docker e contêineres locais contra as recomendações oficiais do **CIS Docker Benchmark**.
- **Seções Auditadas**:
  1. Configuração do Host para Docker.
  2. Configuração do Daemon Docker (`/etc/docker/daemon.json`).
  3. Arquivos de configuração e permissões do Docker.
  4. Imagens de Contêineres e Dockerfiles.
  5. Configurações de Segurança do Runtime de Contêineres.
  6. Operações de Segurança do Docker.
- **Relatório Gerado**: `audit_reports/tools/docker_bench_report.md` e `.json`.

---

### 4. Trivy (`TrivyAdapter`)
- **Objetivo**: Varredura profunda de CVEs Críticas e Altas no sistema de arquivos e em imagens Docker.
- **Comando Executado**:
  ```bash
  trivy fs --skip-db-update --severity HIGH,CRITICAL --format json -q /etc
  ```
- **Relatório Gerado**: `audit_reports/tools/trivy_report.md` e `.json`.

---

### 5. Grype (`GrypeAdapter`)
- **Objetivo**: Scanner ultrarrápido de vulnerabilidades em pacotes instalados no sistema operacional (Debian/Ubuntu, RPM, Alpine).
- **Comando Executado**:
  ```bash
  grype -q -o json --check-for-updates=false dir:/etc
  ```
- **Relatório Gerado**: `audit_reports/tools/grype_report.md` e `.json`.

---

### 6. Syft (`SyftAdapter`)
- **Objetivo**: Catalogação completa do **Software Bill of Materials (SBOM)**, identificando dependências em múltiplos ecossistemas (Java JARs, Python PyPI, Ruby Gems, Binários, GitHub Actions).
- **Comando Executado**:
  ```bash
  syft scan -q -o json dir:/etc
  ```
- **Relatório Gerado**: `audit_reports/tools/syft_report.md` e `.json`.

---

### 7. RKHunter (`RKHunterAdapter`)
- **Objetivo**: Detecção de rootkits conhecidos, trojans, backdoors, arquivos ocultos suspeitos e adulterações em tabelas de chamadas de sistema no kernel.
- **Comando Executado**:
  ```bash
  rkhunter --check --sk --nocolors --report-warnings-only --quiet
  ```
- **Relatório Gerado**: `audit_reports/tools/rkhunter_report.md` e `.json`.

---

### 8. AIDE (`AIDEAdapter`)
- **Objetivo**: Monitoramento e detecção de adulterações em binários do sistema através de hashes criptográficos SHA-256.
- **Comando Executado**:
  ```bash
  aide --check --quiet
  ```
- **Relatório Gerado**: `audit_reports/tools/aide_adapter_report.md` e `.json`.

---

## 📂 3. Onde Encontrar os Relatórios Individuais

Ao executar `sec-audit-linux audit --all --output-dir ./audit_reports`, a subpasta `./audit_reports/tools/` conterá os relatórios dedicados de cada ferramenta:

```text
audit_reports/
├── executive_report.md
├── technical_report.md
├── assessment_result.json
├── remediation_playbook.sh
└── tools/
    ├── checksec_report.md
    ├── checksec_report.json
    ├── docker_bench_report.md
    ├── docker_bench_report.json
    ├── grype_report.md
    ├── grype_report.json
    ├── lynis_report.md
    ├── lynis_report.json
    ├── rkhunter_report.md
    ├── rkhunter_report.json
    ├── syft_report.md
    ├── syft_report.json
    ├── trivy_report.md
    └── trivy_report.json
```
