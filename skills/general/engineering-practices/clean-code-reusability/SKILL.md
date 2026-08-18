---
name: clean-code-reusability
description: Guidelines and procedures for maintaining clean code, SOLID principles, code reusability, and preventing duplication across the repository.
---

# Clean Code & Code Reusability Skill

Este documento estabelece o padrão rigoroso de Clean Code, manutenibilidade e reutilização ativa de código para o projeto de auditoria e conformidade de segurança Linux.

## 🎯 Objetivos

1. Evitar duplicações de lógica de parsing, execução de comandos e validações de segurança.
2. Garantir aderência aos princípios SOLID e separação clara de responsabilidades.
3. Facilitar a extensão para novas distribuições Linux, novas ferramentas e novos frameworks regulatórios.

---

## 🧭 Diretrizes de Desenvolvimento

### 1. Pesquisa Prévia Antes de Implementar
Antes de criar qualquer nova função, classe ou utilitário:
- Execute buscas no repositório (`grep_search` ou listagem de módulos) para verificar se já existem parsers, utilitários de comando ou classes base no pacote `core` ou `collectors`.
- Reutilize os métodos utilitários de execução segura de comando, leitura de `/proc` ou `/sys`, e cálculo de hash SHA-256 presentes no `sec_audit_linux.core`.

### 2. Responsabilidade Única (Single Responsibility Principle)
- **Coletores (`collectors/`)**: Apenas coletam o estado do sistema e registram a evidência bruta (`EvidenceRecord`). Não devem conter regras de pontuação de compliance.
- **Frameworks (`frameworks/`)**: Consomem as evidências e aplicam as regras de avaliação (`ControlEvaluation`) e a fórmula de aderência do respectivo framework. Não executam comandos de baixo nível diretamente no SO.
- **Reporters (`reporters/`)**: Transformam os resultados de avaliação (`AssessmentResult`) em formatos de saída específicos (Markdown, JSON, HTML). Não realizam re-avaliação de regras.

### 3. Modelo de Herança e Composição
- Todos os coletores herdam de `BaseCollector`.
- Todos os frameworks herdam de `BaseFramework`.
- Todos os adaptadores de ferramentas herdam de `BaseToolAdapter`.
- Todas as estruturas de dados utilizam tipagem estrita com dataclasses ou Pydantic.

### 4. Tratamento de Erros e Exceções
- Nunca utilize blocos `except: pass` vazios.
- Trate explicitamente exceções comuns de ambiente Linux: `FileNotFoundError`, `PermissionError`, `subprocess.TimeoutExpired`, `UnicodeDecodeError`.
- Quando um comando ou arquivo não puder ser acessado por falta de privilégios de root, registre o status correspondente (`INSUFFICIENT_PRIVILEGES`) sem interromper a execução do restante da auditoria.

### 5. Documentação e Padrões de Código
- Comentários e docstrings no código devem ser preferencialmente em **Inglês**.
- Mensagens de commit devem seguir o padrão *Conventional Commits* (ex: `feat(ssh): add ciphers and macs validation`, `fix(sysctl): handle missing proc entries`).
- Interações no chat com o desenvolvedor em **Português**.
