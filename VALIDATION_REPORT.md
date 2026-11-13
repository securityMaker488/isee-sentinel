# Validação de desenvolvimento — Windows — atualizado em02/11/2026

Diretriz V11.0 e requisitos anteriores, versão de desenvolvimento 0.2.0. Resultados de fixtures
sintéticas e ambientes locais controlados. Não constituem homologação Debian,
liberação para clientes, certificação ou prontidão comercial.

## Preparação de publicação pública — 13/11/2026

### A. Autorização e escopo

O titular autorizou, nesta data, a publicação pública do repositório sob
GNU AGPL-3.0 e a reescrita do histórico necessária para não expor o registro
interno de pesquisa sobre os projetos de referência estudados. O escopo desta
etapa é **preparação local**: árvore sanitizada, histórico reescrito
localmente, backup verificado e relatório. Não houve envio ao remoto, não houve
force-push e a visibilidade do repositório continua **privada** até a aprovação
final do titular. A autorização para reescrever o histórico é única, datada e
não se estende a outras publicações.

### B. Backup privado e verificável

Espelho local fora do repositório, criado antes de qualquer alteração:
`C:\Users\golde\isee-sentinel-backup\isee-sentinel-2026-11-13.git`
(`git clone --mirror`), com `git fsck --full --strict` sem erros. O espelho
guarda duas séries: `refs/heads/main` em `1b79d4ad…` (a série publicada até
então, 16 commits) e `refs/heads/archive/pre-publication` em `00f7bd83…` (a
série com a árvore já sanitizada, 17 commits), num total de 17 objetos de
commit. Manifesto por commit (SHA-1, SHA da árvore, autor, data, assunto),
organizado por ref, em `manifest-commits-2026-11-13.txt`, com o sha256 do
manifesto em `manifest-commits-2026-11-13.txt.sha256`
(`e81194413ff9097aa4219addc467f1119a003acb6e68bd07d31a9a7af0d51267`).
O espelho guarda a série completa, inclusive o registro interno de pesquisa e
as URLs que o histórico público não terá, e fica fora da árvore versionada.

### C. Auditoria de atribuição legal

Nenhum código de terceiros incorporado: nenhum diretório vendorizado, nenhum
cabeçalho de copyright alheio nos 119 arquivos de código versionados e nenhum
bloco de código de terceiros no repositório. O registro interno de pesquisa
guardava apenas metadados (revisões, hashes, caminhos de testes), sem
excerpts de código, e foi removido da árvore e do histórico público.

Dependências de terceiros: 274 pacotes npm com licença resolvida (o inventário
em `docs/generated/dependencies.json` cobre exatamente o `package-lock.json`;
só os três pacotes do próprio workspace apareciam sem licença e agora declaram
AGPL-3.0-only), 23 pacotes do supervisor e 147 pacotes do crate do agente, ambos
com inventário novo ou atualizado em `docs/generated/`. As licenças são
predominantemente MIT/Apache-2.0, com Unicode-3.0, ISC, BSD-3-Clause, Zlib,
BSL-1.0, CDLA-Permissive-2.0, Unlicense e uma entrada dual
(MIT/Apache-2.0/LGPL-2.1-or-later) que merece revisão jurídica antes de
distribuição comercial. Nenhum aviso de licença ou copyright de terceiro foi
removido: o registro interno de pesquisa saiu, os inventários e as declarações
das dependências ficaram.

### D. Redação e integridade da especificação

O capítulo 02 da especificação V11 (bibliografia dos projetos de referência)
foi redigido por decisão do titular: nomes e URLs viraram "Referência A..I" e
"Referência interna", preservando as listas técnicas de capacidades e todo o
resto do documento byte a byte. O arquivo passou de 41767 para 42846 bytes;
`sha256` original `065bf67c…` e redigido `3e7c4c24…` estão registrados em
`docs/PROMPT-COVERAGE.json`, que também passou a espelhar os 88 títulos
redigidos, preservando a cadeia de custódia do anexo do operador.

### E. Estado do histórico reescrito

A reescrita remove dos 17 commits o registro interno de pesquisa e as menções
aos projetos estudados, preservando integralmente código, testes, migrações e
documentação técnica. Ela é feita localmente; o remoto continua com a série
anterior e nenhum force-push foi executado.

Verificação automatizada do histórico reescrito (18 commits, 222 arquivos
distintos, 421 blobs de texto): **0 ocorrências** de qualquer nome ou URL dos
projetos de referência; dossiê de pesquisa **ausente de todos os commits**;
**0 dos 119 arquivos de código, teste e migração** perdidos ou alterados pela
reescrita; árvore final byte a byte idêntica à árvore sanitizada
(`482be5fc09b6d6bfc396802c2f3338c731292056`) no momento da reescrita — os dois
commits posteriores acrescentam apenas documentação (`GITHUB.md` e este
registro) e nenhum código. A guarda de repositório passa
sobre o histórico reescrito (221 blobs de índice, 454 blobs de histórico) e a
suíte completa foi repetida sobre a árvore final: 200 casos, 198 passaram, 0
falhas, 2 ignorados por SO, 42,8s, mais os 3 testes da própria guarda.

A série anterior fica preservada em espelho privado
(`C:\Users\golde\isee-sentinel-backup`) e, até a publicação, na branch local
`archive/DO-NOT-PUSH-pre-publication-2026-11-13`, que **não** deve ser enviada
(`--all`/`--mirror` estão proibidos). Consequência prevista: os hashes de
commit mudam e a atualização do remoto exigirá `--force-with-lease`, com a
autorização já dada, seguida de nova execução da CI sobre o histórico
reescrito.

### F. Limites desta etapa

Não foram reexecutados PostgreSQL, navegador, perf/Benchmark nem Debian; a
suíte completa e o build Rust foram repetidos sobre a árvore sanitizada antes
da reescrita. O repositório segue privado até a aprovação do titular. Hashes
antigos citados em documentos anteriores ficaram sem objeto no histórico
reescrito e foram mantidos apenas como registro do que foi validado antes da
reescrita.



### A. Base e B. Prova dirigida antes do código

Retomada de main/7e1797f, supervisor 0.1.1 integrado e documentado. Não repetida
a pesquisa de repositórios nem a auditoria ampla. A dúvida de projeto era única:
como encerrar a árvore do worker em cancelamento/timeout normal sem deixar um
descendente vivo e sem prender a captura em pipe herdado. Um programa
descartável, fora do repositório, mediu o host antes de qualquer linha de
código: (V1) supervisor fora de job, worker atribuído depois do spawn,
`TerminateJobObject` matou worker e neto e o supervisor sobreviveu; (V2)
supervisor dentro de job externo, worker herdou o job externo e recebeu um job
interno, e terminar o job interno matou a árvore sem tocar no supervisor.
Conclusão: jobs aninhados funcionam nesta máquina e o job interno pode ser
terminado sem matar quem o supervisiona. A prova vale para este host, não é
homologação de outro SO.

### C. Implementação e D. Segurança

`packages/execution-engine` foi para 0.2.0. `lifetime.rs` passou a ter duas
camadas: o job externo (0.1.1) segue como garantia de morte do supervisor, e um
job interno, criado após o spawn, recebe o worker e carrega os limites por SO
(processos vivos 64, memória 512MiB, tempo de CPU = timeout+60s,
KILL_ON_JOB_CLOSE). No Linux, o worker torna-se líder do seu grupo de processos
(setpgid antes do exec) e o grupo recebe SIGKILL; PDEATHSIG e NO_NEW_PRIVS
continuam como antes; RLIMIT_CPU/DATA/FSIZE/NOFILE passam a ser aplicados ao
filho antes do exec. Falha ao estabelecer o contêiner recusa a execução: não há
execução sem contenção.

A captura deixou de ser `join` sem prazo: os leitores têm deadline de 2s e, se
o pipe não fechar, o recibo registra `captureComplete:false` e o estado
`capture_incomplete` — nunca `completed`. O JSON v1 do recibo ganha
`captureComplete`; `containment` passa a `windows_job_tree`/`linux_process_group`
e a API exige engine 0.2.0, recusando 0.1.1 e 0.1.0 sem fallback. A API valida
e persiste o novo campo; nenhum estado SQL novo, nenhuma migração, UI, agente
ou parser alterados. 23 dependências externas, as mesmas de 0.1.1. FFI continua
isolada em lifetime.rs, única exceção a deny(unsafe_code); CLI mantém forbid.

Isso continua não sendo sandbox de SO/rede: Job Objects e grupos de processos
são contenção de processo, não isolamento. Continuam abertos: no Linux a árvore
não fica contida por completo após morte forçada do supervisor (o sinal cobre o
filho direto) e um descendente que crie novo grupo/sessão escapa; no Windows um
descendente anterior à atribuição ao job interno sobrevive ao cancelamento até
a saída do supervisor. Fechar o pipe herdado na origem exigiria criação de
processo própria com `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, fora deste recorte.
O worker continua confiável por contrato: a contenção de árvore é defesa em
profundidade, não habilitação de plugins.

### E. Testes observados

| Verificação | Resultado local Windows |
|---|---|
| Sonda de jobs aninhados (programa fora do repositório) | V1 e V2: atribuição e terminação de job interno concluíram árvore sem afetar o supervisor |
| cargo fmt/clippy -Dwarnings/test/build, --offline | Passaram; 4 testes Rust |
| cargo check/clippy para x86_64-unknown-linux-gnu | Compilou e passou o lint do caminho Linux; não executado |
| npx tsx --test apps/api/test/execution.test.ts | 12 casos: 11 passaram, 1 ignorado (Linux); 4,59s |
| npm test com supervisor e Python reais | 200 casos: 198 passaram, 0 falhas, 2 ignorados por SO; 38,0s |
| npm run check (typecheck + build do painel + suíte) | 44 módulos compilados; suíte sem o supervisor: 200 casos, 181 passaram, 19 ignorados; 32,3s |
| Controle negativo (árvore sem terminação) | Binário cópia com a terminação de árvore desligada: os 2 casos novos falham (`captureComplete:false`), o que prova que não são vacuosos |
| CI43450994529 (commit fc1dfcc) | Windows2022 e Ubuntu24.04 aprovados; Ubuntu 200 casos/199 passaram/1 ignorado, Windows 200/198/2; casos novos de árvore aprovados nos dois SOs |
| CI43452527408 (commit 2a0486a, com o ajuste do helper) | Windows2022 e Ubuntu24.04 aprovados |

Casos novos: cancelamento e timeout encerram worker e descendente, o descendente
herda o pipe de stdout e mesmo assim o recibo sai com captura completa e
`captureComplete:true`; o PID do descendente é observado como terminado. O
controle negativo, com a terminação de árvore desligada, reproduziu o problema
original: a captura ficou presa no pipe herdado, o recibo saiu com
`captureComplete:false` e o teste falhou. Sem o job interno, o descendente ainda
morre quando o supervisor sai (job externo), o que mostra por que a asserção de
captura completa — e não só a morte do PID — é a prova do controle.

Fragilidade pré-existente corrigida neste incremento: a CI de 05/11
(run42033523252, do commit de README) já falhava no Ubuntu porque o helper
`terminated()` tratava ESRCH na leitura de `/proc/<pid>/stat` como erro,
quando o processo havia sido colhido entre a abertura e a leitura. O helper
passa a tratar ESRCH como ENOENT (processo encerrado). A falha era da base e
não deste incremento, mas os casos novos usam o mesmo helper. O caso de timeout
também passou a usar 3000ms, para que o worker consiga iniciar e criar o
descendente em máquina mais lenta antes do fim do prazo.

Não executados neste incremento: cluster PostgreSQL dedicado (14 testes do
incremento anterior não repetidos), navegador, agente, perf/Benchmark, Debian e
`cargo audit` (ausente no ambiente). O caminho Linux foi verificado localmente
por compilação cruzada (`cargo check` e `cargo clippy -D warnings` para
x86_64-unknown-linux-gnu, com o alvo Rust instalado para isso) e **executado na
CI Ubuntu 24.04**: os dois casos de árvore passaram no Linux real (grupo de
processos + rlimits), e o job Linux da CI43450994529 aprovou. A execução no
Debian13 continua pendente de homologação. PID zumbi Linux continua sendo
processo terminado aguardando o reaper do sistema.

### F. Desempenho e G. Continuidade

Não houve medição de desempenho neste incremento: a comparação com a medição de
02/11 (medianas 128,50ms direto/191,47ms supervisionado, binário 879104 bytes)
não é repetida, e a diferença de binário não é medida. Sem afirmação de ganho
ou regressão. Custos de RAM/CPU/carga não medidos.

M1 continua parcial: encerrar a árvore e liberar a captura era o recorte. Próximo
incremento: job model recuperável, cancelamento geral pelo painel, idempotência
e cotas acumuladas; depois M2 (cliente HTTP Rust com URL exata, DNS/IP, SSRF e
redirects). Preservar escopos, revisão/hash do mandato e evidências. Linux segue
pendente de homologação no Debian13 KDE. PROJECT_STATE/ROADMAP mantêm a fila
única.


## Incremento M1 — vida do worker após falha, 0.1.1 — 02/11/2026

### A. Base e B. Pesquisa dirigida

Retomada de main/3b4d1ef, código0a76557 com CI aprovada. Não repetidas auditoria
ou pesquisa de repositórios. Consultados contratos oficiais Job Objects/atribuição
Windows e PDEATHSIG Linux, com links na ADR em docs/RUST-ENGINES.md; bindings
windows-sys/libc já presentes no cache/lockfile do agente. Risco tratado: matar
forçadamente Rust0.1.0 podia deixar o worker ativo. Quarentena e consentimento
existentes permanecem pré-requisitos.

### C. Implementação e D. Segurança

Novo src/lifetime.rs no crate execution-engine. Alterados lib.rs/Cargo.toml/lock,
API execution.ts, testes execution/imports, inventário de licenças e documentação
vigente/ameaças/matriz/checkpoint. Versão0.1.1; JSON v1 acrescenta containment,
validado conforme SO e persistido. Nenhuma migração, UI, agente ou parser mudou.

Windows cria job anônimo/não herdável, configura KILL_ON_JOB_CLOSE e atribui o
supervisor antes do spawn; handle fica vivo até saída/morte do processo. Linux
recusa interpretador privilegiado e configura NO_NEW_PRIVS/PDEATHSIG com checagem
de pai, protegendo filho direto. Falhas negam spawn. FFI está isolada numa única
exceção a deny(unsafe_code); CLI conserva forbid. Comentários SAFETY e ADR
registram invariantes, propriedade dos handles, buffers e restrições após fork.
São23 dependências externas resolvidas, sem código de terceiros incorporado.

Isso não é sandbox de SO/rede, nem garante árvores Linux ou cancelamento normal
de filhos que herdam pipes. Worker confiável sem descendentes continua sendo o
único adaptador suportado. Job Objects não isolam contra código hostil no mesmo
host; não habilitar plugins. Sem mudanças de firewall, SO, privilégios ou serviços
persistentes. API e binário devem ser atualizados juntos; recibo antigo é recusado.

### E. Testes observados

| Verificação | Resultado local Windows |
|---|---|
| cargo fmt/clippy -Dwarnings/test/build, --locked/--offline | Passaram;4 testes Rust |
| npx tsx --test apps/api/test/execution.test.ts | 9 passaram,1 caso Linux ignorado;3,047s na repetição final |
| npm run check com Python e Rust reais | Build44 módulos;196 passaram,0 falhas,2 skips por SO;198 casos,34,105s |
| API imports/PostgreSQL18/runtime restrito | 14 passaram;6,410s, recibos0.1.1 e modo persistidos |
| Backup/restore nativo | 41 tabelas idênticas,13 migrações,22 importações/jobs,14 planos/revisões/etapas/execuções/vínculos,36 evidências e126 eventos; auditoria íntegra |
| Guarda antes do commit0026313 | Passou:222 candidatos/índice,351 blobs históricos; sem padrões de alta confiança ou caminhos proibidos encontrados |
| CI0026313 | Windows2022 e Ubuntu24.04 passaram; run41557312004,5min18s; final02/11 às22:10:01 America/Bahia (03/11 01:10:01 UTC) |

Casos novos: morte forçada do supervisor encerra Python; no Windows encerra
neto sintético também. Caso Linux recusa set-ID antes do worker; fixture de
sucesso observa NoNewPrivs. Os controles Linux passaram na CI Ubuntu24.04;
não foram executados no host Windows nem homologados no Debian. PID zumbi após
morte do pai conta como terminado,
aguardando o reaper do sistema. Testes removem somente seus próprios temporários.
Não somar9/14 aos196: já fazem parte da suíte. Navegador/parser/agente inalterados
não foram repetidos localmente; resultados anteriores continuam históricos.

A primeira checagem TypeScript detectou tipo literal ainda0.1.0/sem containment;
corrigido antes da suíte completa. A primeira inicialização de QA sem porta
explícita encontrou o serviço já existente; repetida com127.0.0.1:55432 passou,
sem alterar5432. Cluster dedicado encerrado após restore. Fastify mantém aviso
de depreciação conhecido. cargo audit não disponível. Logs .sentinel/lifetime-*.log.
[CI0026313](https://github.com/securityMaker488/isee-sentinel/actions/runs/41557312004)
confirmada com sucesso nos dois jobs. Registro final documental usa [skip ci],
sem alteração de código/workflow/dependências e sem alegar nova execução.

### F. Performance e G. Continuidade

`scripts/benchmark-execution.ts`: Windows/debug,8 amostras/caminho, ZIP514 bytes.
Medianas128,50ms direto/191,47ms supervisionado; mínimos124,92/176,79ms;
máximos140,34/199,41ms; binário879104 bytes. Registro em lifetime-performance.json
(03/11 UTC, ainda02/11 no fuso America/Bahia). Custo adicional esperado, sem ganho
de velocidade; não medidos CPU/RAM/carga/produção. Comparações entre rodadas
pequenas não constituem prova estatística de regressão ou melhora.

M1 continua parcial. Próximo incremento: árvores/cancelamento/timeout sem pipes
presos, limites por SO, depois job model recuperável/cotas; preservar escopos e
evidências. Linux passou na CI Ubuntu e ainda requer homologação no Debian13
KDE. PROJECT_STATE/ROADMAP mantêm a fila única.

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

110 repositórios públicos paginados em dois perfis, e nove referências solicitadas
examinadas em revisões fixas. O registro com commits, manifests/licenças,
arquivos lidos/hashes, testes localizados, compatibilidade não comprovada e
decisões foi movido para fora do repositório em 13/11/2026, por decisão do
titular, antes da publicação: a identificação dos projetos e as URLs não são
publicadas. Nenhum terceiro foi compilado, executado ou incorporado, e nenhum
aviso de licença de terceiro foi removido; duas das referências tinham licença
dupla ou ausente e não foram tratadas como licença resolvida. Conceitos
aproveitados: exit code real e integridade antes/depois, com código próprio.

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
