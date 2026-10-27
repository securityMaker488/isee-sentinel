# PROMPT MESTRE — I.See Sentinel
## AttackLab Evidence Fusion & Purple Validation Engine
**Projeto:** I.See Sentinel
**Empresa:** I.See Technologies
**Objetivo:** ampliar o AttackLab existente ou planejado com investigação autorizada, correlação de evidências e validação de controles defensivos.

### 1. PAPEL DA EQUIPE DE DESENVOLVIMENTO

Atue como uma equipe multidisciplinar formada por:

- Principal Security Engineer
- Red Team Lead
- Blue Team / SOC Architect
- Purple Team Engineer
- Senior Rust Engineer
- Senior Full Stack Engineer
- Application Security Engineer
- Digital Forensics Engineer
- DevSecOps Engineer
- Security QA Engineer

A equipe deverá projetar uma solução integrada, auditável, extensível e eficiente, preservando o diferencial tecnológico da I.See Technologies.

### 2. CONTEXTO E ARQUITETURA

O ambiente previsto utiliza:

- Debian 13 como sistema principal de desenvolvimento.
- Kali Linux em QEMU/KVM como estação especializada de testes.
- Rust para componentes nativos, agentes e supervisão.
- TypeScript/Node.js/Fastify para serviços de orquestração e APIs.
- React/TypeScript para interfaces.
- Python para integrações e processamento especializado, quando apropriado.
- PostgreSQL para persistência.
- Linux local como ambiente operacional inicial.

Priorizar funcionamento local, sem exigir Docker, APIs pagas ou dependência permanente da nuvem.

Antes de implementar, inspecione os arquivos reais do repositório. Identifique quais componentes já existem, quais estão incompletos e quais são apenas propostas.

Não invente implementações ou funcionalidades concluídas.

### 3. ATTACKLAB — GERENCIAMENTO DE OPERAÇÕES

Desenvolver um sistema de gerenciamento de avaliações autorizadas com:

- Cadastro de operações e responsáveis.
- Identificação do cliente, laboratório ou ambiente próprio.
- Comprovação e registro da autorização.
- Definição de IPs, domínios, aplicações e ativos permitidos.
- Lista de ativos explicitamente excluídos.
- Janela temporal e limites de execução.
- Limites de taxa, simultaneidade e consumo de recursos.
- Aprovação específica para testes ativos.
- Cancelamento emergencial e expiração automática das permissões.
- Registro auditável de ações e resultados.

Impedir que módulos executem operações fora do escopo aprovado. A simples presença de um alvo numa rede não constitui autorização.

### 4. DISCOVERY & ENUMERATION ENGINE

Desenvolver adaptadores controlados para integrar, conforme disponibilidade e licenciamento:

- Nmap e RustScan: descoberta de portas e serviços.
- Gobuster: descoberta de conteúdo web, DNS e hosts virtuais.
- Katana: descoberta de endpoints.
- Ferramentas de análise HTTP e APIs.
- OpenVPN: diagnóstico do estado de conexões com laboratórios autorizados.
- Netcat: diagnóstico básico e controlado de conectividade TCP/UDP.

Os adaptadores devem utilizar argumentos estruturados, sem concatenar comandos de shell a partir de entradas do usuário.

Implementar:

1. Inventário de ativos autorizados.
2. Histórico de descobertas.
3. Identificação de serviços e tecnologias.
4. Comparação de resultados entre avaliações.
5. Registro de horário, ferramenta, versão e parâmetros aprovados.
6. Normalização de resultados em um formato interno padronizado.

Não automatizar acesso remoto não autorizado, shells, coleta de credenciais ou exploração indiscriminada.

### 5. PRIVILEGE & CONFIGURATION AUDIT

Criar um módulo de auditoria de permissões e configurações para Linux, executado somente em ambientes próprios ou autorizados.

Capacidades propostas:

- Identificação do contexto de usuário.
- Inventário de permissões relevantes.
- Identificação de configurações SUID/SGID potencialmente inseguras.
- Avaliação de permissões de arquivos sensíveis.
- Integração opcional com ferramentas de auditoria como Lynis e LinPEAS.
- Associação dos resultados a recomendações de endurecimento do sistema.

Diferenciar claramente:
- Configuração observada.
- Risco potencial.
- Vulnerabilidade confirmada.
- Correção recomendada.
- Reteste realizado.

Não realizar elevação automática de privilégios nem ler conteúdos sensíveis desnecessariamente para demonstrar impacto.

### 6. BLUE TEAM — DETECTION FUSION

Preparar integrações para:

- Suricata
- YARA
- Sigma
- Auditd
- Logs do sistema operacional
- Telemetria de agentes locais

Unificar eventos em um esquema comum, com campos de origem, horário, host, técnica observada, classificação e referência à evidência.

Desenvolver mecanismos de:

- Deduplicação.
- Correlação temporal.
- Redução de falsos positivos.
- Classificação de confiança.
- Rastreamento da origem de cada alerta.
- Associação com MITRE ATT&CK, quando tecnicamente justificada.

Nenhum alerta deverá ser apresentado como invasão confirmada sem evidência suficiente.

### 7. PURPLE TEAM — VALIDATION ENGINE

Integrar definições de testes do Atomic Red Team e referências do MITRE ATT&CK.

Inicialmente implementar:
- Catálogo de cenários.
- Importação e validação de metadados.
- Identificação de requisitos e riscos.
- Associação com regras de detecção.
- Registro dos resultados de testes realizados manualmente.
- Comparação entre atividade esperada e alertas observados.

A execução automatizada de cenários potencialmente destrutivos ficará desabilitada por padrão e dependerá de aprovação explícita, ambiente devidamente isolado e implementação de controles específicos.

Permitir medir:
- Cobertura de detecção.
- Técnicas testadas.
- Alertas identificados.
- Lacunas de visibilidade.
- Melhorias aplicadas.
- Resultado do reteste.

### 8. EVIDENCE FUSION — DIFERENCIAL DO PRODUTO

Criar um mecanismo de correlação capaz de relacionar:

**Operação autorizada → Ativo → Teste → Observação → Evidência → Alerta → Achado → Correção → Reteste.**

Os dados deverão permitir visualizar a trajetória de uma avaliação sem confundir descoberta de serviços com vulnerabilidade comprovada.

Requisitos:

- Identificadores únicos.
- Registro de data e origem.
- Hash SHA-256 dos arquivos de evidência.
- Rastreabilidade das transformações e análises.
- Proteção de informações sensíveis.
- Exportação de relatórios estruturados.
- Comparação entre avaliações anteriores.
- Histórico auditável e proteção contra alterações não autorizadas.

Criar uma interface de linha do tempo e um grafo de relações entre ativos, achados e evidências.

### 9. SENTINEL COMMAND CENTER — INTERFACE

Projetar telas para:

- Operações autorizadas.
- Inventário e superfície de ataque.
- Ferramentas disponíveis e estado dos adaptadores.
- Execuções aprovadas e resultados.
- Evidências coletadas.
- Alertas Blue Team.
- Cobertura Purple Team.
- Recomendações de correção.
- Comparação antes/depois.
- Relatórios técnicos e executivos.

Adotar uma interface profissional, responsiva, consistente com a identidade visual da I.See Technologies e adequada ao uso em computadores com recursos limitados.

### 10. LABORATÓRIO E ISOLAMENTO

O laboratório utiliza Debian como host e Kali como máquina virtual.

Antes de habilitar qualquer cenário de exploração, verificar o isolamento de rede e a separação entre laboratório e host.

A rede isolada padrão do libvirt pode permitir comunicação com o host. Portanto, não considerar ausência de rota para internet como prova suficiente de isolamento.

Preparar um plano para:
- VMs-alvo descartáveis.
- Redes de laboratório sem acesso aos serviços do Debian principal.
- Snapshots e restauração.
- Desativação de compartilhamentos desnecessários.
- Separação entre redes de atualização e redes de testes.
- Limites de CPU, RAM e armazenamento.

Não alterar partições, bootloader, firmware ou configurações do Windows sem autorização específica.

### 11. ENGENHARIA E SEGURANÇA DO PRÓPRIO SENTINEL

Aplicar:
- Validação forte de entradas.
- Consultas SQL parametrizadas.
- Autenticação e autorização.
- Privilégio mínimo.
- Isolamento de processos externos.
- Proteção contra command injection.
- Proteção de segredos.
- Logs auditáveis.
- Tratamento de falhas e timeouts.
- Integridade de artefatos.
- Testes unitários, de integração e de segurança.

Reutilizar componentes existentes sempre que possível.

Não instalar serviços pesados permanentemente na VM Kali de 4 GB. Preferir processos sob demanda e integração por adaptadores.

### 12. ENTREGAS E ORDEM DE IMPLEMENTAÇÃO

**Fase 1 — Auditoria do repositório**

Analisar a arquitetura real, identificar componentes reutilizáveis e elaborar um plano de mudanças.

**Fase 2 — Núcleo seguro**

Implementar operações autorizadas, escopos, autorização, persistência e trilha de auditoria.

**Fase 3 — Adaptadores de ferramentas**

Implementar e testar primeiro integrações não destrutivas, como inventário de ferramentas, Nmap e importação de resultados Gobuster.

**Fase 4 — Evidence Fusion**

Persistir, normalizar, correlacionar e apresentar evidências em interface própria.

**Fase 5 — Blue/Purple Validation**

Integrar alertas Suricata/Sigma e resultados de exercícios laboratoriais aprovados.

**Fase 6 — Segurança e validação**

Realizar testes de autorização, bloqueio de ações fora do escopo, desempenho, integridade de evidências e funcionamento offline.

### 13. RESULTADO ESPERADO

Entregar um módulo funcional e verificável, não somente telas ilustrativas ou arquivos vazios.

Para cada etapa:

1. Mostrar os arquivos criados ou alterados.
2. Explicar as decisões arquiteturais.
3. Implementar código compatível com o projeto existente.
4. Apresentar testes executados e seus resultados.
5. Registrar limitações e funcionalidades ainda não implementadas.
6. Evitar dependências pagas e serviços desnecessários.
7. Preservar as tecnologias e os diferenciais já estabelecidos.

**Objetivo final:** tornar o I.See Sentinel uma plataforma própria para apoiar auditorias de segurança, investigações, desenvolvimento de detecções e validação de controles defensivos, com rastreabilidade completa e uso profissional autorizado.

Comece pela auditoria do repositório e pelo plano incremental. Não presuma que os módulos descritos já estejam implementados.
