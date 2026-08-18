---
name: compliance-mapping
description: Standard methodology and calculation formulas for mapping technical evidence to security and compliance frameworks (CIS, NIST, ISO 27001, PCI DSS, MITRE ATT&CK).
---

# Compliance & Framework Mapping Skill

Este guia estabelece a metodologia unificada para correlacionar evidências técnicas com os requisitos de conformidade e calcular o índice de aderência percentual por framework.

---

## 📐 Estrutura de um Módulo de Framework

Cada framework deve herdar de `sec_audit_linux.frameworks.base_framework.BaseFramework` e implementar:
1. `evaluate_controls(evidences: List[EvidenceRecord], context: SystemContext) -> FrameworkResult`
2. `calculate_adherence_score(evaluations: List[ControlEvaluation]) -> float`

```python
from sec_audit_linux.frameworks.base_framework import BaseFramework
from sec_audit_linux.core.models import FrameworkResult, ControlEvaluation, ControlStatus

class CISBenchmarkFramework(BaseFramework):
    framework_id = "cis_benchmarks"
    name = "CIS Linux Benchmark"
    version = "v3.0.0"

    def evaluate_controls(self, evidences, context):
        evaluations = []
        # Avaliar cada controle baseado nas evidências registradas
        # ...
        adherence = self.calculate_adherence_score(evaluations)
        return FrameworkResult(
            framework_name=self.name,
            adherence_percentage=adherence,
            evaluations=evaluations
        )

    def calculate_adherence_score(self, evaluations):
        applicable = [e for e in evaluations if e.status != ControlStatus.NOT_APPLICABLE]
        if not applicable:
            return 100.0
        total_weight = sum(e.weight for e in applicable)
        earned_weight = sum(e.weight for e in applicable if e.status == ControlStatus.COMPLIANT)
        # Parciais ganham 50% do peso
        earned_weight += sum(e.weight * 0.5 for e in applicable if e.status == ControlStatus.PARTIAL)
        return round((earned_weight / total_weight) * 100.0, 2)
```

---

## 🎯 Regras Específicas por Framework

### 1. CIS Benchmarks (Linux)
- **Classificação**: Level 1 (Server / Workstation) e Level 2 (High Security / Defense in Depth).
- **Escopo**: Foco em configurações técnicas granulares (Kernel, Filesystem, SSH, PAM, Firewall, Logging).
- **Cálculo**: Ponderação baseada em pontos por controle aplicável com suporte a perfis L1 e L2.

### 2. CIS Critical Security Controls (v8)
- **Classificação**: Implementation Groups (IG1 - Higiene Básica, IG2 - Empresas Médias, IG3 - Empresas de Alto Risco).
- **Mapeamento**: Agrupamento de verificações técnicas por *Safeguards* (ex: 3.3 - Data Protection, 4.1 - Access Control Management).

### 3. NIST Cybersecurity Framework (CSF 2.0)
- **Funções**: *Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)*.
- **Cálculo**: Média de conformidade das Subcategorias com peso igual por Categoria.

### 4. NIST SP 800-53 (Rev 5)
- **Famílias**:
  - `AC` (Access Control): Sudo, PAM, contas locais, timeouts.
  - `AU` (Audit and Accountability): auditd rules, integridade de logs, retenção.
  - `CM` (Configuration Management): Pacotes instalados, repositórios, serviços desnecessários.
  - `IA` (Identification and Authentication): Complexidade de senha, MFA, lockout.
  - `SC` (System and Communications Protection): Firewall, SSH ciphers, portas expostas.
  - `SI` (System and Information Integrity): AIDE, antivírus/EDR, patches pendentes.

### 5. ISO/IEC 27001:2022 (Anexo A)
- **Controles**: Cláusula 8 (Controles Tecnológicos):
  - 8.1 (Dispositivos de ponto final), 8.2 (Direitos de acesso privilegiado), 8.7 (Proteção contra malware), 8.8 (Gestão de vulnerabilidades técnicas), 8.9 (Gestão de configuração), 8.20 (Segurança de redes), 8.24 (Uso de criptografia).

### 6. PCI DSS v4.0
- **Princípio**: Abordagem estrita para hosts no escopo CDE (*Cardholder Data Environment*).
- **Requisitos**: Requisito 2 (Configurações seguras), Requisito 7 (Restrição de acesso), Requisito 8 (Identificação e autenticação), Requisito 10 (Monitoramento e logs), Requisito 11 (Testes de segurança e FIM).

### 7. MITRE ATT&CK (Enterprise - Linux Matrix)
- **Táticas Mapeadas**:
  - *Initial Access* (T1190, T1078)
  - *Execution* (T1059.004)
  - *Persistence* (T1543.002 - Systemd service, T1053.003 - Cron)
  - *Privilege Escalation* (T1548.003 - Sudo/Sudoers, T1068)
  - *Defense Evasion* (T1562.001 - Disable Security Tools like SELinux/Auditd)
  - *Credential Access* (T1003.008 - /etc/passwd and /etc/shadow)
  - *Lateral Movement* (T1021.004 - SSH)

### 8. SCAP / SSG (Security Content Automation Protocol)
- Execução de perfis XCCDF via OpenSCAP quando disponível, com mapeamento direto dos resultados XCCDF para o modelo unificado de `ControlEvaluation`.
