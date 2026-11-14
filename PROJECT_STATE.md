# Estado do projeto — 13/11/2026

## Retomada — uma linha de desenvolvimento

Guia: docs/GUIA-MESTRE-CONSOLIDADO.md. Fila: ROADMAP.md. Fontes/hashes:
docs/PROMPT-COVERAGE.json. Ao receber “continue”, retomar este checkpoint e
somente arquivos da tarefa. Não repetir auditoria ampla nem reler prompts.

**Posição: V11 Marco 1/Rust Core, parcial; AttackLab A2 permanece parcial.**
As fases antigas são mapa de cobertura, sem fila paralela. Windows/plataforma
não estão100% concluídos. Completar desenvolvimento portátil aqui; parar para
Debian13 KDE quando só restarem dependências reais de Linux. Não transferir
implementação ausente como se fosse apenas homologação do SO.

## Incremento atual — cancelamento por requerimento no painel

- Base main/2dcaa0f (publicação AGPL-3.0 concluída). Fila única: M1 do ROADMAP.
  Incremento menor e funcional: o cancelamento pedido pelo operador, que
  existia só como perda de autorização. O incremento anterior (contenção de
  árvore no cancelamento, supervisor 0.2.0) fica preservado no
  VALIDATION_REPORT.md.
- Entregue: `POST /api/jobs/:id/cancel`, contrato geral por job, sem UI
  fictícia. Estado terminal próprio `cancelled` (migração014), registro do
  requerente e do instante do pedido em `jobs`, auditoria
  `job.cancel_requested` e `import.cancelled`, botão "Cancelar inspeção" na
  tela de importações e recarga da lista durante a execução.
- Autorização: o cancelamento exige as mesmas operações e o mesmo escopo
  vigente que autorizaram o job (import/forensics: scan+evidence.import;
  securebuild/lab_nmap: scan), no mesmo ativo e na mesma organização. Pedido
  sem escopo é 403 e não grava nada; job de outra organização é 404; job que
  não está em execução é 409. O cancelamento não amplia mandato nem escopo.
- Interrupção: o motor publica seu `AbortController`; o pedido aborta a
  execução. Com o supervisor Rust, a árvore do worker é encerrada na hora e o
  recibo fica `cancelled`. Sem supervisor Rust, o pedido fica registrado e a
  inspeção termina na fronteira seguinte — limitação real, dita na tela, não
  mascarada.
- Durabilidade: o pedido é gravado antes do sinal
  (`jobs.cancel_requested_at`/`cancel_requested_by`). O registro de execução em
  memória é volátil por desenho; job órfão segue marcado `interrupted` pela
  inicialização do servidor.
- O original em quarentena é preservado e continua verificável; a evidência não
  é apagada; o lock de execução é liberado; a requisição que originou a
  importação recebe 409 `IMPORT_CANCELLED`.

## Validação atual e evidências

- Incremento do cancelamento: suíte completa com supervisor real e Python real
  — 202 casos, 200 passaram, 0 falhas, 2 skips por SO, 37,3s. Os 2 casos novos
  (apps/api/test/job-cancellation.test.ts) cobrem o cancelamento de uma
  inspeção em andamento e as guardas de autorização, isolamento e organização.
- Percurso no navegador em 13/11/2026 contra servidor sintético efêmero:
  23 verificações, todas aprovadas, código de saída 0, console sem erros, com
  Python real na importação ZIP e na perícia PCAP. O roteiro
  (scripts/browser-qa.cjs) foi corrigido antes: usava rótulos da tela
  anteriores ao suporte TAR, trocados em 02/11/2026, o que o havia tornado
  inexecutável. Nova asserção cobre o histórico de importações: linha
  concluída como "Inspecionada · em quarentena", sem "Cancelar inspeção" em
  linha concluída e com o texto de explicação presente. O cancelamento de uma
  inspeção em andamento segue verificado pela API, não pelo navegador.
- Comportamento verificado no caso principal: o pedido de cancelamento
  responde 200 `cancelling`; a requisição que originou a importação recebe 409
  `IMPORT_CANCELLED`; o job fica `cancelled` com `error_code=IMPORT_CANCELLED`;
  `cancel_requested_at` e `cancel_requested_by` ficam preenchidos; a evidência
  permanece e responde `integrityVerified:true`; o lock de execução é
  liberado; a auditoria contém `job.cancel_requested` e `import.cancelled`.
- Guardas verificadas: job inexistente 404, job concluído 409, pedido sem
  escopo 403 sem gravar nada, job de outra organização 404 e job sem execução
  local responde `cancel_requested` (pedido durável, sem motor a interromper).
- fmt/clippy -Dwarnings/build do supervisor passaram neste incremento; o crate
  não teve código alterado, apenas o campo de licença (AGPL-3.0-only).
- Incremento anterior (contenção de árvore, supervisor 0.2.0): fmt/clippy/
  build e 4 Rust passaram; 12 casos de processo, 11 passaram/1 skip Linux no
  Windows, incluindo os 2 de árvore encerrada (cancelamento e timeout) com
  descendente herdando o pipe; controle negativo com a terminação desligada
  fez os 2 casos falharem (`captureComplete:false`). PostgreSQL18/runtime
  restrito, backup/restore, medição debug/Windows e QA de navegador são
  históricos de 02/11, não repetidos aqui.
- CI43450994529 (commit fc1dfcc) e CI43452527408 (commit 2a0486a) aprovaram em
  Windows2022 e Ubuntu24.04; o caminho Linux (grupo+rlimits) roda em Linux real
  nessas execuções. A CI0026313 (run41557312004) validava 0.1.1, não 0.2.0.
  A CI deste incremento, 43530124903 (commit 1067d73), aprovou nos dois SOs:
  Ubuntu24.04 com 202 casos/201 passaram/1 ignorado e Windows2022 com
  202/200/2 ignorados.
- Logs .sentinel/lifetime-*.log e lifetime-performance.json. No local, cargo
  audit continua indisponível.

## Próximo passo concreto

1. M1 (restante): job model recuperável, idempotência e cotas acumuladas.
   Novos estados SQL exigem nova migração. Preservar identidades, revisão/hash
   do mandato, evidências e comportamento após interrupção. O cancelamento
   geral está entregue no caminho de importação; forensics, AttackLab e
   SecureBuild devem publicar o mesmo `AbortController` para entrar no
   contrato de `POST /api/jobs/:id/cancel`. Fechar pipe herdado na origem
   exigiria criação de processo própria (handle list) — fora do recorte atual.
2. M2: HTTP Rust/URL exata/DNS-IP/SSRF/redirects e limites em servidor sintético,
   depois Git por adaptador próprio. Manifesto Nmap não autoriza HTTP. Não
   refazer ZIP/TAR ou planos; seguir M3–M5 conforme ROADMAP.
3. Homologar Debian13 KDE quando só restarem dependências reais de Linux.

Limites: sem sandbox de SO/rede/cgroups, cotas CPU/RAM/disco acumuladas, fila/
retries ou fila distribuída; o registro de cancelamento em memória vale só
para o processo que executa o job; polling250ms não é atômico. Job Objects e
grupos de processos são contenção de processo, não isolamento. Hash/recibo não
é assinatura digital. Linux/Debian, serviço do agente e QEMU/Kali ainda
precisam de homologação própria.

## Base e continuidade

Guia27 seções/8 fontes/651 títulos; V11 original41767 bytes com hash. Pesquisa
prévia:110 repositórios públicos inventariados,9 leituras dirigidas/revisões;
nenhum código terceiro executado/incorporado. Duas das referências tinham
licença dupla ou ausente, e referências não concedem autorização de integração.
Não repetir pesquisa sem
necessidade concreta. Arquivos/decisões: docs/RUST-ENGINES.md e registro de pesquisa
interno, mantido fora do repositório.

React/Fastify/PostgreSQL, fundador/MFA, clientes/projetos/ativos, PolicyGate,
mandatos/manifestos, evidências cifradas e auditoria continuam. Agente HMAC/FIM
finito, casos, análises offline, SecureFix CÓPIA SSH, RiskGraph e perícia
preservados. Não presumir EDR completo, pentest geral ou isolamento de VM.

Git: https://github.com/securityMaker488/isee-sentinel, main/origin HTTPS, **público
desde 13/11/2026** sob AGPL-3.0, por decisão do titular. Publicação executada:
push do histórico reescrito com `--force-with-lease` (1b79d4a → 916f427) e
mudança de visibilidade. A série pré-reescrita foi removida do repositório local
(refs, reflog e prune) e permanece apenas no espelho privado de backup, verificado
e fora da árvore versionada. O e-mail pessoal nos metadados dos commits foi
mantido, por decisão do titular. Impacto conhecido: commits antigos podem
continuar acessíveis no GitHub por SHA até a coleta de lixo; os logs de CI
verificados não contêm os termos redigidos. Conferir git log/status na retomada.
Credenciais/bancos/dumps/.sentinel/target não entram
no Git. Recompilar por SO; não depender desta conversa. DEVELOPMENT/TESTING
e docs/RUST-ENGINES.md explicam reprodução e o contrato atualizado.

PostgreSQL dedicado55432 encerrado após os testes; o QA4311 foi iniciado e
encerrado no fim da verificação do navegador, sem serviço em execução ao fim
deste incremento. Serviço5432 preexistente preservado. Para reiniciar o cluster
de QA, passar explicitamente -h127.0.0.1 -p55432 ao pg_ctl; a configuração
padrão não fixa a porta dedicada. Windows/partições/bootloader/firmware/
firewall/Kali não alterados. Sem bloqueio externo para continuar código
portátil Windows.
