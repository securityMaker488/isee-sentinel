# Validação de desenvolvimento — Windows — atualizado em02/11/2026

Diretriz V11.0 e requisitos anteriores, versão de desenvolvimento 0.2.0. Resultados de fixtures
sintéticas e ambientes locais controlados. Não constituem homologação Debian,
liberação para clientes, certificação ou prontidão comercial.

## Incremento V11 — supervisão Rust e pesquisa — 02/11/2026

### A. Estado inicial

Branch main, árvore inicialmente limpa, commit
`d67e95b39bd950b2c129e15d1ff6c4e23020f1d5`. Reutilizados planos/mandatos,
13 migrações, importação ZIP/TAR/TAR.GZ e worker Python1.1, agente Rust e UI.
Baseline JS185 passaram/1 POSIX skip; agente Rust14 unitários+4 CLI passaram.
[CI d67e95b](https://github.com/securityMaker488/isee-sentinel/actions/runs/41486645508)
confirmada em02/11: Windows2022 e Ubuntu24.04 concluíram com sucesso.
A revisão focou novos requisitos e interfaces afetadas, preservando a auditoria.
Lacunas iniciais relevantes: revogação não encerrava worker; não havia recibo
nativo/engine de execução Rust, contenção geral, fila recuperável ou cliente HTTP.

### B. Pesquisa

110 repositórios públicos paginados:106 projetos de referência autorizados e4 projetos de referência autorizados. Nove referências
solicitadas examinadas em revisões fixas: Referência A, Referência B, Referência C,
Referência D, Referência E, Referência F, Referência G, Referência H e Referência I.
[Pesquisa](registro de pesquisa interno) e [registro](registro de pesquisa interno)
contêm commits, manifests/licenças, arquivos lidos/hashes, testes localizados,
compatibilidade não comprovada e decisões. Nenhum terceiro foi compilado,
executado ou incorporado. Referência I só contém README nessa revisão. Referência F
contém LICENSE AGPL e license.md CC-BY-NC-SA; não tratar como licença resolvida.
Conceitos aproveitados: exit code real e integridade antes/depois, com código próprio.

### C. Implementação e decisões

Criados `packages/execution-engine/{Cargo.toml,Cargo.lock,src/lib.rs,src/main.rs}`,
`apps/api/src/execution.ts`, `apps/api/test/execution.test.ts` e
`scripts/benchmark-execution.ts`. Alterados API app/imports e teste imports,
ImportView, .env.example e workflow CI. Nenhuma migração ou parser foi alterado.
A nova CLI0.1.0 usa contrato JSON v1, um worker confiável, ambiente reduzido,
hashes, códigos de saída, buffers limitados, timeout e cancelamento por pipe.
API conserva autorização/transações; revalida durante inspeção quando Rust está
configurado, valida recibo e o persiste em relatório/auditoria. UI identifica a
configuração. O caminho direto anterior permanece sem cancelamento durante execução.

Documentação criada: fonte V11 byte a byte, pesquisa MD/JSON, RUST-ENGINES/ADR
e inventário de dependências. Atualizados guia/índice/registro, AGENTS,
PROJECT_STATE/ROADMAP, arquitetura/ameaças/licenças, matriz/estado de módulos,
README, operação/testes/continuidade e contratos de importação/planos. Guia único
agora contém27 seções/8 fontes/651 títulos. A V11 governa marcos0–5, sem apagar
requisitos nem abrir fila paralela. O crate independente evita migrar o agente,
reescrever o parser ou adicionar runtime assíncrono sem necessidade demonstrada.

### D. Segurança e limitações

Melhorias verificadas: perda de escopo encerra Python; resposta não pode converter
exit7 em sucesso; divergência de original/worker/recibo nega aceitação; stdout/
stderr têm limites e stderr não vaza conteúdo. Campos desconhecidos e comandos
arbitrários são recusados. A UI/HTTP não escolhe executável ou argumentos.
MFA/CSRF/organização/projeto/PolicyGate continuam nos caminhos existentes.
Rust próprio usa `forbid(unsafe_code)`; isso não audita dependências transitivas.
21 pacotes externos no lockfile novo, sem alteração de dependências JS/agente.

Limites: worker deve ser confiável e não criar descendentes; não há sandbox de
SO, bloqueio de rede, Job Objects/cgroups ou cotas CPU/RAM. Morte forçada do
supervisor pode deixar filho ativo. Polling250ms soma latência do banco e não é
atômico. Recibo cancelled não muda schema SQL: job failed/SCOPE_REQUIRED e
original preservado. Hash não assina evidências nem protege host comprometido.
Não habilitar outros plugins neste runtime antes da contenção. Não foram
alterados Windows/rede/firewall/sudoers/VMs; somente ferramentas do usuário e
serviços dedicados de QA usados. Nenhum teste ofensivo externo foi iniciado.

### E. Testes executados

| Comando/fluxo | Resultado observado |
|---|---|
| cargo fmt --manifest-path packages/execution-engine/Cargo.toml -- --check | Passou |
| cargo clippy --locked --manifest-path packages/execution-engine/Cargo.toml --all-targets -- -D warnings | Passou |
| cargo test/build --locked com esse manifest | 4 testes Rust passaram; build debug concluído |
| npx tsx --test apps/api/test/execution.test.ts | 7 passaram, processos reais;3,018s |
| npx tsx --test apps/api/test/imports.test.ts | 14 passaram em PGlite; também14 em PostgreSQL18/runtime restrito,6,184s |
| npm run check com Python/binário Rust reais | TypeScript/build44 módulos;194 passaram,0 falhas,1 skip POSIX;195 casos,37,678s |
| Backup/restore do banco de testes nativo | 41 tabelas idênticas,13 migrações,22 importações/jobs,14 planos/revisões/etapas/execuções/vínculos,36 evidências e126 eventos; auditoria íntegra |
| node scripts/browser-archive-qa.cjs | ZIP/TAR/TAR.GZ reais pelo plano, exportação, falha preservada, revogação, TAR.GZ avulso e390px passaram; JSONs exportados confirmam recibos Rust completed |
| cargo audit --version | Comando indisponível; auditoria de advisories não executada |
| npm run test:repository / verify:repository | 3 testes passaram; guarda pré-commit aprovou221 candidatos/221 blobs do índice/309 históricos, sem padrões de alta confiança ou caminhos proibidos encontrados |
| CI do código0a76557 | Windows2022 e Ubuntu24.04 passaram; run41514577061 concluída em02/11 às20:02:02 UTC,5min32s após início do run |

Os sete casos nativos cobrem contrato desconhecido/hash/budgets, env reduzido,
exit7 enganoso, AbortSignal com PID encerrado, excesso stdout/stderr, mutação do
original, UTF-8 inválido, timeout800ms e EOF. Dois novos testes da API verificam
recibo real nos três formatos e cancelamento por revogação/expiração, preservando
plano/original/auditoria e liberando o bloqueio persistido. Estão incluídos nos14,
que por sua vez estão incluídos nos195; não somar contagens repetidas.

Uma tentativa inicial de baseline falhou por leitura negada do esbuild fora da
raiz restrita; repetição com acesso ao workspace real passou. Não foi defeito do
produto nem motivo para modificar dependências. Fastify mantém aviso conhecido
de disableRequestLogging depreciado. Python/imports24 passou no incremento TAR;
o parser não mudou nem sua suíte foi repetida localmente nesta etapa.
Logs: .sentinel/v11-baseline-unrestricted.log, v11-rust-baseline.log,
v11-supervisor-test.log, v11-imports-test.log, v11-final-check.log,
v11-native.log, v11-restore.log e v11-browser.log. Não versionar dados de QA,
credenciais, dumps ou screenshots com dados privados.
[CI 0a76557](https://github.com/securityMaker488/isee-sentinel/actions/runs/41514577061)
verificada com sucesso nos dois jobs. O build também passou após a atualização
da matriz/documentação. Commit final só de documentação usa [skip ci] e não
altera código/workflow/dependências; não representa nova execução da suíte.
A guarda procura padrões definidos, não prova ausência universal de segredos.

### F. Desempenho

Medição serial do ZIP sintético514 bytes,8 amostras por caminho, Windows/debug,
binário873984 bytes. `npx tsx scripts/benchmark-execution.ts`, Python local e
nenhum banco/rede envolvidos. Originalmente medianas131,89ms direto/194,00ms
Rust; reprodução pelo script versionado:128,11ms/186,51ms, mínimos123,85/172,64ms
e máximos139,54/204,73ms. Logs v11-performance.json e v11-performance-repro.json.
A supervisão adiciona processo e verificações; **não houve ganho de velocidade**.
Não medidos: RAM/CPU, carga sustentada, release, outros tamanhos, Linux/Debian.
Não interpretar pequena amostra como benchmark de capacidade operacional.

### G. Continuidade

M0 atendido como auditoria/pesquisa dirigida; M1 parcial. Próxima tarefa única:
contenção/encerramento após morte do supervisor, contratos e testes por SO;
depois runtime/job model recuperável e cotas, antes do cliente HTTP M2/URL/Git.
ADR/limites em docs/RUST-ENGINES.md; checkpoint/ordem em PROJECT_STATE/ROADMAP.
Não há bloqueio externo para avançar código portátil Windows. Debian13/KDE,
Nmap real, serviço do agente, QEMU/Kali e isolamento continuam sem homologação.
QA4311 e PostgreSQL dedicado55432 encerrados; serviço5432 preexistente preservado.

## Incremento inspeção no plano e TAR — 02/11/2026

Arquivos criados: migrações012/013, test_inspect_tar.py, fixtures base64 TAR e
TAR.GZ, browser-archive-qa.cjs. Alterados: core/assessment-plan, API
assessment-plans/imports, testes de planos/imports, AssessmentView/ImportView/menu,
qa-server, inspect_archive/fixture_project e documentação/matriz/checkpoint.
Decisões: reutilizar os vínculos existentes; separar formato explícito do nome;
revalidar mandato/hash em cada fronteira; não executar nem extrair conteúdo.
Contratos: docs/ASSESSMENT-PLANS.md, IMPORT_PIPELINE.md e docs/IMPORT-ARCHIVE-WORKER.md.
Migrações001–011 preservadas. Sem nova dependência.

| Verificação | Resultado |
|---|---|
| TypeScript/build | Passaram,44 módulos; último ajuste visual recompilado |
| Suíte JS com Python real | 185 passaram,0 falhas,1 skip POSIX no Windows |
| Worker imports | 24 passaram, incluindo12 de TAR/gzip e regressão ZIP |
| API imports em PostgreSQL18/runtime restrito | 12 passaram, sem skips, com worker real nos três formatos |
| Backup/restore | 41 tabelas idênticas,13 migrações,17 importações/jobs,9 planos/revisões/etapas/execuções/vínculos,26 evidências e87 eventos; auditoria íntegra |
| Navegador arquivos | Três uploads reais pelo plano, exportações/identidade/hashes, falha preservada, revisão ao mudar formato, TAR.GZ avulso,390px e revogação passaram |
| Regressão navegador estático | Criação/revisão/execução/exportação, truncamento identificado,390px, troca de contexto e revogação passaram |

A primeira execução apontou um ponto e vírgula em comentário da nova migração012
incompatível com o splitter local. Corrigido antes da entrega; os testes acima
foram executados após a correção. QA de arquivos foi repetido após o ajuste final
que oculta campos até selecionar uma etapa. Logs .sentinel/archive-*.log,
captura archive-plan-mobile.png inspecionada e JSONs em .sentinel/qa.

TAR limitado a USTAR UTF-8 regular/diretório, sem PAX/GNU/sparse/base-256.
Revogação não interrompe um processo iniciado: há revalidação antes do worker e
antes de aceitar o resultado. Não há cancelamento atômico no intervalo de criação
do processo. Os limites de stream não equivalem a cotas de memória do SO.
URL/Git, fila geral, recuperação, ProofLab e homologação Debian permanecem abertos.
Serviços temporários4311/55432 encerrados após testes em02/11;5432 preservado.
CI d67e95b confirmada em02/11: Windows2022/Ubuntu24.04 passaram,
run41486645508. Rust e demais workers não foram repetidos localmente nesse
incremento TAR; o baseline do incremento V11 está registrado acima.

## Incremento planos de avaliação — 01/11/2026

Arquivos: migração011, core/assessment-plan, API assessment-plans e integração
app.ts/scans, runtime-grants, AssessmentView/css/menu, testes core/API/navegador.
Contrato e decisões: docs/ASSESSMENT-PLANS.md. Nenhuma migração001–010 foi editada.

| Verificação | Resultado |
|---|---|
| TypeScript e build web | Passaram;44 módulos |
| Suíte completa com Python real | 179 passaram,0 falhas,1 skip POSIX no Windows |
| Planos/core/API focados | 3 core e18 API passaram |
| PostgreSQL18 nativo/runtime restrito | 18 testes API passaram |
| Backup/restore | 41 tabelas idênticas;11 migrações;17 planos,21 revisões,22 etapas,10 execuções/vínculos,34 evidências e138 eventos; auditoria íntegra |
| Navegador | Criar/revisar/executar/exportar, histórico,390px, resposta antiga descartada na troca de organização e revogação passaram; console sem erros |

Cobertura: identidade/CSRF/papéis, organização/projeto/ativos, UUIDs canônicos,
revisões concorrentes, hashes/imutabilidade/FKs, bytes, expiração/revogação/
substituição, exclusões de inventário, ausência de vínculos retroativos e rollback
integral com falha injetada na segunda evidência. A execução integrada é somente
estática e usa arquivos sintéticos; inventário é metadado, sem Nmap real.
O aviso de100 resultados foi testado na UI por resposta sintética explicitamente
marcada no roteiro. Não representa teste de carga com101 scans.

Ajuste final da consulta obtém lock antes de ler revisões e resultados: evita
misturar uma execução nova com um histórico lido antes dela.18 testes API
passaram novamente após esse ajuste. Build/suíte completa/PostgreSQL/restore
foram executados antes dele; a CI final confirmou o código enviado, incluindo
o ajuste de leitura sob lock e a compilação final.

[CI do código d16ec25](https://github.com/securityMaker488/isee-sentinel/actions/runs/41372768013):
Windows2022 e Ubuntu24.04 passaram, duração total4m48s. Resultado observado
em01/11 e registrado em02/11. Inclui build/suíte JS, verificação de repositório,
auditoria de dependências, Rust e workers Python. Esse resultado corresponde a
d16ec25f3f1cd4a0f2532e790aaf3f3f30a81c51; o commit posterior de fechamento altera
somente documentação e usa [skip ci]. Ubuntu não substitui homologação Debian.

Verificação local antes do envio do código:203 arquivos candidatos/203 blobs no
índice/256 históricos, sem padrões bloqueados. Serviços temporários4311/55432
encerrados após validação; PostgreSQL preexistente5432 preservado.

Logs: .sentinel/assessment-build.log, assessment-full-test.log,
assessment-api-focused.log, assessment-native-test.log, assessment-restore.log,
assessment-browser.log. Capturas assessment-completed.png/assessment-mobile.png
em .sentinel/qa foram inspecionadas. Segredos, dumps e dados de QA ficam fora do Git.
Rust e workers Python não foram alterados nem repetidos isoladamente neste
incremento local; sua execução na CI passou conforme registro acima.

Limites: demais perfis apenas planejáveis, fila/pausa/cancelamento geral ausentes,
sem vínculo de importação ou comparação/reteste generalizados. Fase Windows e
produto completo ainda em desenvolvimento; Debian13 KDE não homologado.

## Incremento manifesto de alvos e guia único — 27/10/2026

Código: migração010; core/target-manifest e authorization; API authorization-manager,
policy/lab; telas AuthorizationView/LabView; testes de política/API/navegador.
Não reescreve migrações001–009, não atribui autorização histórica nem executa Nmap real.
Guia único: docs/GUIA-MESTRE-CONSOLIDADO.md; sete fontes integrais/hashes e563
títulos indexados em docs/PROMPT-COVERAGE.json. Uma fila global0–12 é preservada.

| Verificação | Resultado deste incremento |
|---|---|
| TypeScript e build web | Passaram |
| Suíte completa com Python real | 158 passaram,0 falhas,1 skip POSIX no Windows |
| Focados autorização/lab | 50 passaram; manifesto puro adicional incluído na suíte completa |
| API Authorization Manager / PostgreSQL18 restrito | 26 passaram, incluindo migração010 e histórico esquema1 |
| Restore PostgreSQL nativo | 36 tabelas idênticas,10 migrações,37 mandatos/39 vínculos,3 scans e225 eventos; auditoria íntegra |
| Navegador | Manifesto preenchido/revisado/exportado, inclusão/exclusão, aprovação/revogação, políticas,390px e console passaram |

Positivos/negativos cobrem pares ativo/endereço, portas por alvo, exclusões que
prevalecem, formato/capacidade, alteração do hash, imutabilidade, empresa/projeto,
revogação/expiração, bloqueio legado e rechecagem antes do despacho. O scanner
é injetado; nenhuma rede foi varrida. Campos de referência no scan preservam a
revisão original mesmo após substituição da autorização. Cancelamento imediato,
operação/plano completos e integrações Blue/Purple/Gobuster seguem pendentes.

CI749bf63: [Windows2022 passou](https://github.com/securityMaker488/isee-sentinel/actions/runs/40437546235/job/121969735462)
em3m59s. [Ubuntu24.04](https://github.com/securityMaker488/isee-sentinel/actions/runs/40437546235/job/121969735715)
passou no doctor corrigido e em145/146 testes; a perícia rejeitou symlink Python.
Correção alinha resolução realpath ao worker ZIP, mantendo argumentos fixos,
ambiente reduzido e Python isolado. Testes locais de perícia:6pass/1skip POSIX.
A correção foi confirmada na [CI do código dff15a3](https://github.com/securityMaker488/isee-sentinel/actions/runs/40568763223):
Windows2022 e Ubuntu24.04 passaram; duração total de4m16s. Resultado consultado
em29/10/2026. Inclui a regressão POSIX no Ubuntu, sem equivaler à homologação Debian.

Evidências locais: .sentinel/manifest-full-test.log, manifest-focused-test.log,
manifest-native-test.log, manifest-restore.log, manifest-browser-test.log e
.sentinel/qa/authorization-approved.png/authorization-mobile.png. Credenciais,
dumps e evidências de QA não foram incluídos no repositório. Rust/Python isolados
históricos não foram repetidos localmente, pois suas fontes permanecem inalteradas.

## GitHub privado, CI e complemento AttackLab — histórico de26/10

Repositório privado criado e primeiro envio0a097b1 confirmado por igualdade entre
HEAD local e main remoto. A verificação anterior ao envio cobriu182 arquivos do
índice e174 blobs históricos; as duas alterações finais de README/metadado do
relatório receberam verificação adicional no índice e na cópia de trabalho.
O metadado de especificação dos relatórios foi corrigido de6.6 para6.9; os cinco
testes de integração OpenAPI/relatório passaram após essa alteração.

A [CI inicial](https://github.com/securityMaker488/isee-sentinel/actions/runs/40401553438)
passou no Windows2022. Ubuntu24.04 falhou antes do build: o diagnóstico resolvia
o link rustc/cargo para rustup e comparava a versão do gerenciador à do compilador.
`scripts/executable-path.mjs` preserva o nome invocado, mantendo o despacho do
proxy. Dois testes passaram localmente; um de link POSIX foi ignorado no Windows
e será executado na CI Ubuntu. O doctor completo local passou após a correção.
A CI também recebe o caminho real do Python para não ignorar os testes dos workers.

O complemento AttackLab foi registrado e recebeu auditoria dirigida de código.
Plano: docs/ATTACKLAB-EVIDENCE-FUSION-PLAN.md. Isso não implementou Gobuster,
Suricata/Sigma/Atomic nem homologou rede isolada, Linux ou execução ativa nova.
Naquele checkpoint, incluir alvos/exclusões no pedido era a próxima tarefa;
o incremento de27/10 acima a implementa. O próximo passo atual é PROJECT_STATE.md.

## Incremento Authorization Manager

| Verificação executada em 26/10/2026 | Resultado |
|---|---|
| TypeScript/API e build React/Vite | Passaram |
| Suíte JS completa com Python real configurado | 146 passaram, sem falhas nem skips |
| Política estruturada | 13 testes novos incluídos na suíte completa |
| Authorization Manager na API | 20 testes novos incluídos na suíte completa |
| Os mesmos 20 testes em PostgreSQL18, runtime restrito | Passaram; migração009 e novos grants exercitados |
| Backup/restore nativo | 36 tabelas idênticas, 9 migrações, auditoria íntegra; 30 mandatos e31 vínculos |
| Navegador Edge/Playwright, fluxo de autorização | Rascunho, download da prova, revisão, aprovação, limites, bloqueio legado, revogação e viewport390px passaram; console sem erros |

Foram exercitados alteração de risco/perfil por novo rascunho, imutabilidade,
projetos/empresas isolados, falha de integridade, vigência, bytes UTF-8 reais,
portas permitidas, observação assinada do agente e transições de cópia SecureFix.
Os testes de autorização usam substitutos de Nmap/workers para provar que a
política bloqueia antes do despacho. A suíte completa também executou os testes
existentes com Python real. Rust e suítes Python isoladas não foram repetidos:
suas fontes não mudaram neste incremento. Credenciais de QA não foram versionadas.

Script reproduzível: `scripts/browser-authorization-qa.cjs`. Capturas em
`.sentinel/qa/authorization-approved.png` e `authorization-mobile.png`.
Uma tentativa de navegador precedeu o término da inicialização do servidor e
recebeu conexão recusada; após a prontidão, o fluxo completo acima passou.

## Checkpoint anterior preservado

Os resultados abaixo são históricos do incremento anterior, não uma segunda
execução das suítes inalteradas neste incremento.

| Verificação executada | Resultado e alcance |
|---|---|
| `scripts/setup-windows.ps1` | Passou: diagnóstico, instalação pelo lockfile sem scripts, build React/TypeScript e Rust |
| `npm test` com `SENTINEL_TEST_PYTHON_PATH` | 113 passaram, sem falhas ou skips; inclui Python real de perícia e ZIP |
| Rust `cargo test --locked` | 18 passaram: 14 biblioteca/transporte + 4 CLI |
| Python integridade | 8 passaram; 1 específico de Unix ignorado no Windows |
| Python perícia | 16 passaram: PCAP/PCAPNG/SQLite/plist e entradas malformadas |
| Python ZIP | 12 passaram: caminhos, links, colisões, tamanho, CRC, metadados, consentimento e ausência de extração |
| Guarda do repositório | 3 passaram, incluindo segredo no índice já removido da cópia de trabalho |
| API ZIP no PostgreSQL nativo | 6 passaram com runtime restrito; Python real positivo e negativo |
| API perícia no PostgreSQL nativo | 5 passaram com runtime restrito, incluindo Python real |
| API agentes/análises no PostgreSQL nativo | 6 passaram no checkpoint anterior; não representa Linux |
| Binário Rust real → API | Passou coleta autorizada, HMAC, baseline, alteração, alerta e revogação |
| Backup/restore PostgreSQL 18 | 34 tabelas comparadas linha a linha; 8 migrações; auditoria íntegra |
| Navegador Edge/Playwright | Fluxo completo passou, incluindo viewport de390px e console sem erros |
| Auditoria npm | Nenhuma vulnerabilidade reportada pela base consultada; não prova ausência de falhas |

Nas suítes JS, Rust, Python e guarda: **170 testes passaram e 1 foi ignorado**.
Integrações nativas e navegador são verificações adicionais, sem duplicar essa
soma. Resultados correspondem à execução registrada, não a futuras alterações.

## Percurso no navegador

Login/MFA; ativo e escopos; SecureBuild e relatório; SOC sintético; evidência;
cadastro/download único e revogação do agente; nota/evidência/transição/relatório
do caso; proposta SSH, aprovação, aplicação à cópia, verificação e restauração;
análise de dependências; ZIP com Python real e quarentena; PCAP com Python real;
RiskGraph acessível; Nmap indisponível com execução desabilitada; matriz;
isolamento entre empresas/projetos; layout estreito e console sem erros.

Falhas encontradas e corrigidas: rótulos acessíveis de selects/textarea e limite
global insuficiente para atualizações do painel. O teto geral passou de200 para
600 requisições/minuto; login mantém10/minuto e bloqueio persistente por conta.
MFA, CSRF e autorização continuam cobertos pelos testes. O replay completo do
navegador passou após as correções.

## Limitações

O restore anterior usou banco sintético com dados de importação; o atual usou
os registros dos testes de autorização, agente e cópia SecureFix. Tabelas sem registros
foram comparadas vazias. Validou conteúdo cifrado idêntico e cadeia de auditoria,
sem exercitar todos os tipos populados, perda elétrica ou custódia de chave de
instalação real. Banco temporário em55432, separado do serviço preexistente5432.

Nmap foi testado com executor injetado. Nmap real, Kali/QEMU, redes isoladas,
desempenho sustentado, fuzzing ampliado e Debian permanecem pendentes. Resultados
de CI remota são discriminados acima por revisão/ambiente.
Python `-I`, ambiente reduzido e timeout não constituem VM nem bloqueio de rede
imposto pelo SO. Os workers implementados não acessam rede nem executam entradas.

Fastify emitiu aviso de depreciação de `disableRequestLogging`, sem falha. Avaliar
migração dessa opção junto a atualização compatível, preservando a redação de logs.

Reprodução: TESTING.md, DEVELOPMENT.md e scripts versionados. Credenciais de QA,
bancos, chaves e dumps não integram o Git ou pacote. Screenshots de dados
sintéticos ficam em `.sentinel/qa` e cópias selecionadas na pasta de entrega.
