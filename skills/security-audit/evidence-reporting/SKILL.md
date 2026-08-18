---
name: evidence-reporting
description: Instructions and formats for generating tamper-evident evidence packages, technical/executive Markdown reports, JSON payloads for LLMs, and remediation playbooks.
---

# Evidence & Reporting Skill

Este guia define as especificações e padrões para a geração de relatórios de auditoria, playbooks de remediação e pacotes de evidências imutáveis.

---

## 📄 Formatos de Saída Suportados

### 1. Relatório Executivo em Markdown (`executive_report.md`)
- **Público**: CISOs, Gestores de TI, Auditores de Governança.
- **Conteúdo**:
  - Resumo de Postura de Segurança (Pontuação Global e por Framework).
  - Tabela consolidada de conformidade (Aderente vs Não Aderente).
  - Heatmap de risco por severidade (Crítico, Alto, Médio, Baixo).
  - Top 5 Desvios Críticos com maior impacto de segurança.

### 2. Relatório Técnico Detalhado em Markdown (`technical_report.md`)
- **Público**: Engenheiros de Segurança, Sysadmins, DevOps, Auditores Técnicos.
- **Conteúdo**:
  - Detalhamento de cada controle auditado com ID, Severidade e Status.
  - Evidência técnica bruta com bloco de código formatado.
  - Justificativa técnica (*Rationale*) e Referências normativas.
  - Passo a passo de remediação (*Remediation Guide*) com comandos exatos.

### 3. Payload JSON Estruturado (`assessment_result.json`)
- **Público**: Modelos de Linguagem (LLMs), MCP Clients, Servidores SIEM, ADK2 Multi-Agent Orchestrators.
- **Esquema JSON**:
```json
{
  "system_context": {
    "hostname": "srv-app-prod01",
    "os_name": "Rocky Linux",
    "os_version": "9.4",
    "kernel": "5.14.0-427.el9.x86_64",
    "scan_timestamp": "2026-08-18T14:00:00Z"
  },
  "overall_score": 84.5,
  "frameworks": {
    "cis_benchmarks": {
      "adherence_percentage": 88.2,
      "compliant_controls": 120,
      "non_compliant_controls": 16,
      "evaluations": [
        {
          "control_id": "CIS-5.2.1",
          "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
          "status": "compliant",
          "severity": "HIGH",
          "actual_value": "0600 root:root",
          "evidence_id": "ev-uuid-001"
        }
      ]
    }
  }
}
```

### 4. Playbooks de Remediação (`remediation_playbook.sh` / `.yml`)
- Scripts Shell idempotentes ou Playbooks Ansible gerados automaticamente a partir dos controles não aderentes para correção rápida dos desvios detectados.
