# Estado do projeto — 02/11/2026

## Retomada — uma linha de desenvolvimento

Guia: docs/GUIA-MESTRE-CONSOLIDADO.md. Fila: ROADMAP.md. Fontes/hashes:
docs/PROMPT-COVERAGE.json. Ao receber “continue”, retomar este checkpoint e
somente arquivos da tarefa. Não repetir auditoria ampla nem reler prompts.

**Posição: V11 Marco 1/Rust Core, parcial; AttackLab A2 permanece parcial.**
As fases antigas são mapa de cobertura, sem fila paralela. Windows/plataforma
não estão100% concluídos. Completar desenvolvimento portátil aqui; parar para
Debian13 KDE quando só restarem dependências reais de Linux. Não transferir
implementação ausente como se fosse apenas homologação do SO.

## Incremento atual — proteção de vida do worker, supervisor 0.1.1

- Base main/3b4d1ef (registro) e0a76557 (código), ambos sincronizados. A V11 e
  as oito fontes já estão consolidadas; não repetir pesquisa/auditoria anterior.
- Windows: Job Object privado/não herdável atribui o supervisor antes de spawn,
  sem breakaway; handle permanece até o SO encerrar o processo. Matar o
  supervisor encerrou worker e neto sintético nos testes locais.
- Linux: código configura PDEATHSIG/SIGKILL e NO_NEW_PRIVS antes de exec, confere
  pai após configurar e recusa interpretador set-ID/capabilities. Protege filho
  direto, sem prometer árvore Linux. Caminho validado na CI Ubuntu24.04;
  Debian13 continua por homologar.
- FFI fica somente em lifetime.rs, com invariantes/ADR. Biblioteca deny(unsafe),
  exceção explícita nesse módulo; CLI mantém forbid.23 dependências externas
  resolvidas, incluindo bindings já presentes no agente. Não afirmar zero unsafe.
- Recibo contém containment e versão0.1.1; API valida SO/versão e persiste ambos
  no relatório/auditoria. Atualizar API e binário juntos. Configuração recusada
  não abre fallback. Mantidos mandatos/revisões, cancelamento por escopo e
  evidências; nenhuma migração001–013, parser, agente ou interface foi alterada.

## Validação atual e evidências

- fmt/clippy -Dwarnings/build e4 Rust passaram. Processos:9 passaram/1 skip Linux
  no Windows, incluindo morte forçada de supervisor e neto; repetidos após ajuste
  de teste. TypeScript/build44 módulos e suíte completa:196 passaram,0 falhas,
  2 skips por SO (198 casos),34,105s.
- PostgreSQL18/runtime restrito:14 testes passaram (6,410s), recibo0.1.1/mode
  persistido nos três formatos e cancelamento por revogação/expiração mantido.
- Backup/restore:41 tabelas idênticas,13 migrações,22 importações/jobs,14 planos/
  revisões/etapas/execuções/vínculos,36 evidências e126 eventos; auditoria íntegra.
- Medição debug/Windows:8 amostras por caminho, ZIP514 bytes; medianas128,50ms
  direto/191,47ms supervisionado; binário879104 bytes. Sem ganho de velocidade;
  RAM/CPU/carga não medidos. Script scripts/benchmark-execution.ts.
- Logs .sentinel/lifetime-*.log e lifetime-performance.json. No local,
  cargo audit continua indisponível. CI0026313 aprovada em Windows2022 e
  Ubuntu24.04: run41557312004, concluída em02/11 às22:10 (America/Bahia).
  https://github.com/securityMaker488/isee-sentinel/actions/runs/41557312004
  Guarda pré-commit passou:222 arquivos/índice,351 blobs históricos.
- Baseline0a76557 teve CI Windows2022/Ubuntu24.04 aprovada, run41514577061;
  esse resultado não valida o código0.1.1. Browser e workers sem alterações
  conservam as evidências anteriores, sem alegar novo QA neste incremento.

## Próximo passo concreto

1. M1: contenção de árvores também no cancelamento/timeout normal, sem captura
   presa em pipes herdados; limites por SO. O runtime atual só aceita o worker
   confiável sem descendentes. Não habilitar plugins/Nmap por esse recorte.
2. Depois, runtime/job model recuperável, cancelamento geral, idempotência e
   cotas. Novos estados SQL exigem nova migração. Preservar identidades,
   revisão/hash do mandato, evidências e comportamento após interrupção.
3. M2: HTTP Rust/URL exata/DNS-IP/SSRF/redirects e limites em servidor sintético,
   depois Git por adaptador próprio. Manifesto Nmap não autoriza HTTP. Não
   refazer ZIP/TAR ou planos; seguir M3–M5 conforme ROADMAP.

Limites: sem sandbox de SO/rede/cgroups, cotas CPU/RAM/disco, fila/retries ou
cancelamento geral pelo painel; polling250ms não é atômico. Job Objects não
protegem contra host comprometido. Hash/recibo não é assinatura digital.
Linux/Debian, serviço do agente e QEMU/Kali ainda precisam de homologação própria.

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
0026313060ca155201a7fcf56cfb902d3cd69641. Registro posterior só documental usa
[skip ci], sem atribuir nova suíte ao registro. Conferir git
log/status na retomada. Credenciais/bancos/dumps/.sentinel/target não entram
no Git. Recompilar por SO; não depender desta conversa. DEVELOPMENT/TESTING
e docs/RUST-ENGINES.md explicam reprodução e o contrato atualizado.

PostgreSQL dedicado55432 encerrado após os testes; QA4311 não iniciado neste
incremento. Serviço5432 preexistente preservado. Para reiniciar o cluster de QA,
passar explicitamente -h127.0.0.1 -p55432 ao pg_ctl; a configuração padrão não
fixa a porta dedicada. Windows/partições/bootloader/firmware/firewall/Kali não
alterados. Sem bloqueio externo para continuar código portátil Windows.
