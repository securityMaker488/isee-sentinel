# Retomada vigente — V11.0 — 02/11/2026

Leia primeiro ../PROJECT_STATE.md e ../ROADMAP.md. As seções abaixo são histórico; não reiniciar os trabalhos já encerrados.

---

# Continuidade atual V6.6 — 24/10/2026

V6.6 é a referência atual; cópia em ESPECIFICACAO-V6.6.txt, SHA256
31cecb4835cc7b640bfdfbedc79247af9d9b745fd71d1fd24e290517c8e04bff.
Operador pediu concluir tudo viável Windows antes de Debian. Retomar daqui,
sem revisão ampla de arquivos já conferidos. O bloco V6.5 abaixo é histórico.

Em integração: pacote0.2, matriz central PORTFOLIO_CAPABILITY_MATRIX.md e JSON,
ARCHITECTURE/ROADMAP0–16 e governança. Migração003/agents.ts liga sensor HMAC
com validade/revogação/replay/baseline explícita e alerta de integridade.
Binário Rust REAL passou scripts/verify-agent.ts contra API loopback isolada:
primeira coleta, aprovação, igual, divergência/alerta, revogação bloqueada.
Rust18testes e Pythonintegrity8+1skip relatados pelo executor.

Migração004/operations.ts: casos/notas/evidências/estados e SecureFix de CÓPIA
cifrada com aprovação/aplicar/verificar/rollback;6testes dirigidos passaram.
Migração005/analyses.ts:7tipos de artefatos, npm/CycloneDX/Nmap/HAR/SARIF,
IAM/identidade/IA, PE/ELF/timeline;17testes novos/34core passaram.
reporting.ts exporta análise/caso com evidência verificada e reteste ausente
declarado. agents.test.ts6casos passou em memória e está sendo executado
em PostgreSQL temporário com runtime restrito.

Migração006/lab.ts: adaptador Nmap externo opcional, IPv4lab,16portas,
argumentos fixos/sem shell,40s,lockglobal,outputcifrado. lab.test/docsATTACKLAB
estão sendo finalizados. Nenhuma varredura real executada.
Telas Endpoint/Operations/Analysis/Lab/Capabilities montadas; browserQA
ampliado escrito, execução após build ainda pendente.

Próximas ações: finalizarlab,build/testesJS/browser, corrigir integração;
validar grants nativos e restore atualizado; worker Python portátil de
PCAP/PCAPNG/SQLite/plist em desenvolvimento por agente (não disponível ainda).
Consolidar MODULE_STATUS/VALIDATION_REPORT/matriz/inventário e ZIP V6.6.
Cluster TEMPORÁRIO de testes work/postgres-validation foi iniciado na porta
55432; pará-lo ao encerrar. Serviço5432 preexistente preservado.

Ainda faltam módulos reais além desse recorte: EDR/XDR, aquisição forense,
mobile completo, TI, DAST, correção no host e recuperação de serviços.
Não declarar100%. Debian/boot/partições/drivers/Kali/Podman não foram alterados.
Sem conta operacional do fundador; credenciais QA são sintéticas.
ZIP V6.5 anterior está desatualizado.

## Histórico anterior V6.5 (não é o estado corrente)

Especificação vigente: **Elite V6.5**. V5 e V6.3 são históricos; suas decisões
substituídas estão no comparativo. Quando o operador disser “continue oq estava
fazendo”, retomar deste registro, sem releituras/revisões grandes já concluídas.
Corrigir erros encontrados e testar alterações relacionadas.

## Estado entregue

- Repositório Git local inicializado em `main`, sem publicação ou remoto.
- Núcleo TypeScript/React/Fastify e migrações PostgreSQL: operador único, MFA,
  recuperação, empresas/projetos, escopos, auditoria e evidências cifradas.
- SecureBuild baseline com seis regras; relatório JSON com cálculo explicável
  de risco; BarrierMatrix registra 14 camadas sem presumir proteção ativa.
- SOC: eventos versionados e deduplicados; cinco falhas correlacionadas geram
  alerta e incidente. Simulações exigem laboratório e ficam identificadas.
- Agente Rust e validador Python: protótipos offline testados; não são EDR nem
  coletor Linux/Windows conectado ao backend.
- Build e 37 testes JavaScript passaram. Os 19 testes API passaram também em
  PostgreSQL 18.6 com identidade runtime restrita. Rust: 9; Python: 8 + 1 skip.
- Browser E2E reproduzível pelos scripts `qa:server` e `qa:browser`: 12 etapas,
  sem erros JavaScript/console; empresas/projetos e visual mobile conferidos.
- Backup nativo restaurado em banco novo: 14 tabelas comparadas, cadeia íntegra.

## Próxima sequência, sem pular dependências

1. Fase 0/1: executar o diagnóstico no Debian real e obter mapa de partições e
   backups antes de qualquer migração. Debian/KDE, dual boot, drivers e discos
   não foram alterados nesta sessão Windows.
2. Homologar o núcleo no Debian: PostgreSQL dedicado, identidades de serviço,
   permissões de arquivos, bootstrap do fundador e restore com chave sob custódia.
3. Conectar o agente Linux à ingestão com identidade de serviço autenticada,
   escopo explícito, revogação e proteção contra replay. Até lá, observações Rust
   não são apresentadas como telemetria operacional do painel.
4. Expandir SecureBuild por verificações reais de dependências/autorização/API,
   com evidências e testes de falso positivo/negativo.
5. Seguir FASES-V6.5.md para ambientes opcionais, defesa, investigação,
   adaptadores e Windows. Nenhum módulo avança a M4–M6 automaticamente.

Não há serviço publicado, credencial padrão ou instância operacional do fundador
provisionada. As contas vistas nos testes e imagens pertencem a bancos sintéticos
isolados. Windows/serviço PostgreSQL preexistente foram preservados.
