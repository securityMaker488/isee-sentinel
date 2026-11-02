# Estado do projeto — 02/11/2026

## Retomada — uma linha de desenvolvimento

Guia: docs/GUIA-MESTRE-CONSOLIDADO.md. Fila: ROADMAP.md. Fontes/hashes:
docs/PROMPT-COVERAGE.json. Ao receber “continue”, retomar este checkpoint e
somente arquivos da tarefa. Não repetir auditoria ampla nem reler prompts.

**Posição: V11 Marco1/Rust Core, parcialmente entregue; AttackLab A2 permanece
parcial.** V11 foi incorporada ao guia, preservando requisitos V6.9/complementos.
As fases antigas são mapa de cobertura, não fila paralela. Windows/plataforma
não estão100% concluídos. Completar desenvolvimento portátil aqui; parar para
Debian13 KDE quando só restarem dependências reais de Linux. Não transferir
implementação ausente como se fosse apenas homologação do SO.

## Incremento entregue — supervisão Rust da inspeção

- Novo packages/execution-engine, CLI sentinel-execution0.1.0: contrato estrito,
  worker Python fixo/confiável, exit code real, hashes antes/depois, timeout e
  saída limitada; EOF/AbortSignal encerra e aguarda o filho. Safe Rust próprio.
- API integra caminho opcional SENTINEL_EXECUTION_PATH, recibo em relatório e
  auditoria, revalidação250ms durante execução e cancelamento ao detectar perda
  de escopo. Sem Rust, permanece caminho direto com validação anterior/posterior.
  Configuração explícita inválida falha sem fallback silencioso. UI identifica
  supervisor configurado. Job SQL failed/SCOPE_REQUIRED e recibo cancelled são
  estados distintos; nenhuma migração001–013 foi editada ou adicionada.
- Preservados ZIP/TAR/TAR.GZ USTAR, planos/revisões imutáveis, static.scan,
  criptografia, evidências e PolicyGate. Contrato/ADR: docs/RUST-ENGINES.md.
- Pesquisa:110 repositórios públicos inventariados,9 revisões com leitura dirigida;
  licenças/código/testes localizados em registro de pesquisa interno. Nenhum
  código externo executado ou incorporado. Referência F tem dois textos de
  licença diferentes; outros não têm licença identificada. Integração não liberada.

## Validação deste incremento

- Baseline d67e95b:185 JS passaram/1 POSIX skip; agente Rust14+4 passou.
  CI desse commit também confirmada: Windows2022 e Ubuntu24.04 passaram,
  run41486645508. Não repetir agora suites inalteradas sem motivo novo.
- Novo supervisor:fmt/clippy -Dwarnings/build e4 Rust passaram;7 testes de
  processos reais passaram. TypeScript/build44 módulos e suíte completa:
  194 passaram,0 falhas,1 skip POSIX (195 casos).
- API importações:14 passaram também no PostgreSQL18/runtime restrito,
  incluindo revogação/expiração que encerram o PID Python e preservam original.
- Backup/restore:41 tabelas idênticas,13 migrações,22 importações/jobs,14 planos/
  revisões/etapas/execuções/vínculos,36 evidências e126 eventos; auditoria íntegra.
- Navegador:ZIP/TAR/TAR.GZ via plano, recibos Rust nos JSONs exportados, falhas,
  revogação, TAR.GZ avulso e390px passaram. Worker Python não foi alterado;
  seus24 testes passaram no incremento TAR anterior, sem nova alegação local.
- Benchmark sintético debug,8 amostras/caminho: mediana128,11ms direto e186,51ms
  supervisionado na reprodução; binário873984 bytes. Não mede carga/RAM/CPU nem
  demonstra aceleração. Script scripts/benchmark-execution.ts. cargo audit não
  disponível neste ambiente; não executado.
- Logs .sentinel/v11-*.log, resultados/capturas .sentinel/qa. Relatório A–G em
  VALIDATION_REPORT.md. CI do novo incremento ainda será consultada após push.

## Próximo passo concreto

1. M1: conter e encerrar processo/árvore após morte do supervisor, com provas de
   PID e limites por SO. Hoje é somente worker confiável sem descendentes; não
   habilitar plugins arbitrários/Nmap por esse runtime. Job Objects/cgroups,
   sandbox/rede e cotas de SO ainda não implementados. Contratos portáteis e
   testes Windows podem avançar aqui; prova Linux correspondente exige Debian.
2. Depois, runtime/job model recuperável, cancelamento geral, idempotência e
   cotas. Novos estados exigem nova migração; preservar identidades/evidências.
3. M2: cliente HTTP Rust/URL exata, DNS/IP fixado, SSRF/redirects e limites em
   servidor sintético; depois Git por adaptador próprio. Manifesto Nmap não
   autoriza HTTP. Não refazer ZIP/TAR ou planos. Seguir M3–M5 conforme ROADMAP.

Limites importantes: polling não é atômico, cancelamento pelo painel/fila/retries
não existem; matar o próprio supervisor à força pode deixar Python ativo. Hash
não é assinatura digital nem resiste a host/administrador comprometido.

## Base e continuidade

Guia27 seções/8 fontes/651 títulos; V11 original41767 bytes preservado com hash.
React/Fastify/PostgreSQL, fundador/MFA, clientes/projetos/ativos, PolicyGate,
mandatos/manifestos, evidências cifradas e auditoria continuam. Agente Rust HMAC/
FIM finito, casos, análises offline, SecureFix CÓPIA SSH, RiskGraph e perícia
preservados. Não presumir EDR completo, pentest geral ou isolamento de VM.

Git privado autorizado: https://github.com/securityMaker488/isee-sentinel,
main/origin HTTPS; base inicial d67e95b39bd950b2c129e15d1ff6c4e23020f1d5.
Conferir git log/status na retomada. Credenciais/bancos/dumps/.sentinel/target
não entram no Git. Usar fonte sincronizada e recompilar por SO, sem depender
desta conversa. DEVELOPMENT/TESTING e docs/RUST-ENGINES.md explicam reprodução.

QA4311 e PostgreSQL dedicado55432 foram encerrados após este incremento;
5432 preexistente preservado. Windows/partições/bootloader/firmware/firewall/Kali
não foram alterados. Sem bloqueio externo para o próximo incremento portátil.
