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

## Incremento atual — contenção de árvore no cancelamento, supervisor 0.2.0

- Base main/7e1797f, supervisor 0.1.1 integrationado. Não repetir pesquisa nem
  auditoria anterior; a V11 e as oito fontes seguem consolidadas.
- Prova antes do código: sonda fora do repositório mediu o host (V1 job externo
  ao supervisor/V2 job aninhado). Jobs aninhados funcionam nesta máquina; o job
  interno pode ser terminado sem matar o supervisor. Prova do host, não
  homologação de outro SO.
- Windows: job externo continua protegendo a vida do worker quando o supervisor
  morre; job interno criado após o spawn recebe o worker, carrega limites
  (64 processos, 512MiB, CPU=timeout+60s, KILL_ON_JOB_CLOSE) e é terminado em
  cancelamento/timeout e no caminho normal. Falha ao estabelecer o contêiner
  recusa a execução.
- Linux: worker vira líder do seu grupo de processos (setpgid antes do exec) e o
  grupo recebe SIGKILL no cancelamento/timeout; PDEATHSIG/NO_NEW_PRIVS e
  recusa de interpretador set-ID permanecem; RLIMIT_CPU/DATA/FSIZE/NOFILE
  aplicados antes do exec. A árvore não fica contida após morte forçada do
  supervisor e um descendente que crie novo grupo escapa. O caminho Linux foi
  verificado localmente por compilação cruzada (check e clippy para
  x86_64-unknown-linux-gnu); a execução fica com a CI Ubuntu24.04 e o Debian13
  continua por homologar.
- Captura com prazo de 2s: pipe herdado não bloqueia o recibo. Captura
  incompleta vira `captureComplete:false` + estado `capture_incomplete`, nunca
  `completed`.
- Recibo: versão0.2.0, containment windows_job_tree/linux_process_group e
  captureComplete novo; API valida SO/versão/campo e persiste; 0.1.1 e 0.1.0
  recusados sem fallback. Atualizar API e binário juntos. FFI fica somente em
  lifetime.rs (exceção explícita a deny(unsafe); CLI mantém forbid). 23
  dependências externas, as mesmas de 0.1.1. Nenhuma migração001–013, parser,
  agente ou interface foi alterada.

## Validação atual e evidências

- fmt/clippy -Dwarnings/build e4 Rust passaram. Processos:12 casos,11 passaram/1
  skip Linux no Windows, incluindo os 2 novos de árvore encerrada
  (cancelamento e timeout) com descendente herdando o pipe.
- TypeScript/build44 módulos e suíte completa com supervisor real:200 casos,198
  passaram,0 falhas,2 skips por SO,38,0s. Sem o supervisor a mesma suíte teve
  19 skips,32,3s.
- Controle negativo: cópia do binário com a terminação de árvore desligada fez
  os 2 casos novos falharem (`captureComplete:false`), provando que não são
  vacuosos.
- PostgreSQL18/runtime restrito:não repetido neste incremento; as 14 execuções
  de 02/11 são históricos e não validam 0.2.0.
- Backup/restore, medição debug/Windows (medianas128,50ms/191,47ms) e QA de
  navegador:históricos de 02/11, preservados sem novo QA neste incremento.
- Logs .sentinel/lifetime-*.log e lifetime-performance.json. No local, cargo
  audit continua indisponível. CI0026313 aprovada em Windows2022 e Ubuntu24.04:
  run41557312004, concluída em02/11 às22:10 (America/Bahia). Esse resultado não
  valida 0.2.0; a CI deste código ainda não foi executada.

## Próximo passo concreto

1. M1 (restante): runtime/job model recuperável, cancelamento geral pelo painel,
   idempotência e cotas acumuladas. Novos estados SQL exigem nova migração.
   Preservar identidades, revisão/hash do mandato, evidências e comportamento
   após interrupção. Fechar pipe herdado na origem exigiria criação de processo
   própria (handle list) — fora do recorte atual.
2. M2: HTTP Rust/URL exata/DNS-IP/SSRF/redirects e limites em servidor sintético,
   depois Git por adaptador próprio. Manifesto Nmap não autoriza HTTP. Não
   refazer ZIP/TAR ou planos; seguir M3–M5 conforme ROADMAP.
3. Homologar Debian13 KDE quando só restarem dependências reais de Linux.

Limites: sem sandbox de SO/rede/cgroups, cotas CPU/RAM/disco acumuladas, fila/
retries ou cancelamento geral pelo painel; polling250ms não é atômico. Job
Objects e grupos de processos são contenção de processo, não isolamento.
Hash/recibo não é assinatura digital. Linux/Debian, serviço do agente e
QEMU/Kali ainda precisam de homologação própria.

## Base e continuidade

Guia27 seções/8 fontes/651 títulos; V11 original41767 bytes com hash. Pesquisa
prévia:110 repositórios públicos inventariados,9 leituras dirigidas/revisões;
nenhum código terceiro executado/incorporado. Referência F tem licenças distintas;
referências não concedem autorização de integração. Não repetir pesquisa sem
necessidade concreta. Arquivos/decisões: docs/projetos de referência autorizados-RESEARCH e RUST-ENGINES.

React/Fastify/PostgreSQL, fundador/MFA, clientes/projetos/ativos, PolicyGate,
mandatos/manifestos, evidências cifradas e auditoria continuam. Agente HMAC/FIM
finito, casos, análises offline, SecureFix CÓPIA SSH, RiskGraph e perícia
preservados. Não presumir EDR completo, pentest geral ou isolamento de VM.

Git privado autorizado: https://github.com/securityMaker488/isee-sentinel,
main/origin HTTPS, privacidade reconfirmada antes do push atual. Código entregue:
fc1dfcc59bfda62121a3de9eff739f6b88b5df7a. Registro posterior só documental usa
[skip ci], sem atribuir nova suíte ao registro. Conferir git
log/status na retomada. Credenciais/bancos/dumps/.sentinel/target não entram
no Git. Recompilar por SO; não depender desta conversa. DEVELOPMENT/TESTING
e docs/RUST-ENGINES.md explicam reprodução e o contrato atualizado.

PostgreSQL dedicado55432 encerrado após os testes; QA4311 não iniciado neste
incremento. Serviço5432 preexistente preservado. Para reiniciar o cluster de QA,
passar explicitamente -h127.0.0.1 -p55432 ao pg_ctl; a configuração padrão não
fixa a porta dedicada. Windows/partições/bootloader/firmware/firewall/Kali não
alterados. Sem bloqueio externo para continuar código portátil Windows.
