# Rust engines — decisão arquitetural e contrato inicial

02/11/2026. Diretriz V11, Marco1 parcial. Este documento registra uma decisão
implementada; a lista de motores abaixo não implica oito novos executáveis.

## ADR: supervisão do worker existente, sem reescrita

Adicionar `packages/execution-engine` como crate independente, com lockfile,
biblioteca e CLI `sentinel-execution`0.2.0. API Fastify conserva identidade,
mandatos/PolicyGate, transações e evidências; Python conserva o parser auditado.
A UI informa qual supervisor está configurado e o relatório exporta seu recibo.
Não mover o agente nem criar um workspace/crates vazios sem dependência real.

Usar threads e std::process para um único filho confiável; Tokio/serviço
permanente não são necessários neste recorte. A CLI mantém forbid(unsafe_code);
a biblioteca usa deny(unsafe_code), com uma única exceção em lifetime.rs para
FFI de proteção do processo. Justificativa/invariantes na ADR abaixo. Isso não
audita unsafe transitivo. Serde/serde_json/sha2 e bindings windows-sys/libc
reutilizam dependências presentes no agente;23 pacotes externos resolvidos,
inventário em generated/execution-dependencies.json.

Configuração opcional `SENTINEL_EXECUTION_PATH` seleciona o binário compilado para
a máquina atual; `SENTINEL_PYTHON_PATH` continua obrigatório. Sem a primeira,
o caminho Node existente é mantido. Configuração explícita inválida falha sem
fallback silencioso. A configuração é do operador local, nunca campo HTTP.
`GET /api/imports/status` expõe `supervisor` e `authorizationCancellation`;
esses campos indicam configuração, não prova de instalação ou isolamento.

## Contrato v1

A CLI aceita somente `--python CAMINHO_ABSOLUTO --worker CAMINHO_ABSOLUTO`.
Na integração, o worker é fixado em `workers/imports/inspect_archive.py`.
Não há parâmetro de comando, script, shell ou argumentos livres vindo da API.

Stdin recebe um objeto JSON seguido de newline em até2s/8192 bytes. Campos
obrigatórios: `schemaVersion:1`, `operation:"archive.inspect"`, `jobId` UUID,
`file` absoluto, `format` zip/tar/tar.gz, `inputSha256` hexadecimal minúsculo,
`maxInputBytes`, `maxOutputBytes` e `timeoutMs`. Campos desconhecidos e limites
fora de16MiB/2MiB/45s são recusados. Stdin fica aberto: EOF ou byte adicional
cancela a execução. A invocação não funciona como pipeline que fecha stdin logo
após o pedido. API e testes mantêm a concessão aberta até o término.

O supervisor verifica SHA-256 do original e do worker antes/depois, recusa arquivo
direto simbólico/especial, inicia Python `-I -B` sem shell, reduz o ambiente e
limita stdout/stderr. Stderr não é exportado; só sua contagem limitada é registrada.
Timeout, cancelamento ou excesso de saída matam e aguardam o filho antes da resposta.
Código de saída não zero nunca se torna sucesso por uma alegação no stdout.

Resposta: `{receipt,stdout}`. O recibo inclui versão/engine/job, estado, exitCode,
duração, hashes de original/worker/stdout, contadores, truncamento, completude da
captura e `containment` (windows_job_tree ou linux_process_group). A API exige
engine0.2.0 e o modo correspondente ao SO; atualizar API e binário juntos.
Recibo0.1.1 e 0.1.0 são recusados, sem fallback. Formato de pedido/schemaVersion1
permanece igual. `stdout` só é retornado no sucesso UTF-8. Estados: completed,
failed, cancelled, timed_out, output_limit, integrity_failed, invalid_output e
capture_incomplete. CLI retorna0 no sucesso,3 na falha com recibo e2 na recusa
de contrato/configuração. Falha anterior ao spawn não necessariamente gera
recibo; a API mantém seu próprio evento de falha.

A API valida identidade/versão/hash/tamanhos/estado/código de saída antes de aceitar
o relatório. Persiste apenas campos conhecidos em `report.execution` e auditoria.
O hash detecta divergência, não é assinatura digital nem autentica um host já
comprometido. Conteúdo do relatório continua sujeito às validações do importador.

## Escopo, falhas e fronteiras

Com Rust configurado, a API revalida os mesmos escopos/mandato/hash a cada250ms,
sem consultas concorrentes, além das verificações antes e depois da execução.
Revogação/expiração/erro de política fecha stdin. Intervalo de polling e latência
do banco impedem promessa de cancelamento instantâneo/atômico. Nos testes,
revogação e expiração encerraram o PID Python real e preservaram evidência/plano.

As13 migrações existentes são mantidas. O job continua `failed` com
`SCOPE_REQUIRED` quando a política deixa de valer; o recibo audita `cancelled`
para o processo. Não inventar um novo estado SQL sem migração futura. Sem Rust,
a revalidação é anterior/posterior e não cancela o worker durante a execução.

Desde0.2.0, o cancelamento e o timeout normais encerram a **árvore** do worker:
no Windows, um Job Object interno recebe o worker e é terminado; no Linux, o
worker é líder do seu grupo de processos e o grupo recebe SIGKILL. A captura tem
prazo próprio: um descendente que herda o pipe não bloqueia o recibo; quando a
captura não fecha no prazo, o recibo registra `captureComplete:false` e o estado
`capture_incomplete`, nunca `completed`. Job Object externo mantém a proteção
após morte do supervisor; PDEATHSIG mantém o filho direto no Linux. Falha ao
configurar nega spawn; plataformas diferentes de Windows/Linux são recusadas.
Provas por SO e limites da árvore aparecem na ADR abaixo; Debian continua por
homologar.

EOF após morte da API cancela enquanto o supervisor está vivo. Watchdog Node
fecha o pipe em46s e limita supervisor defeituoso em50s. O controle do SO cobre
o worker direto se o supervisor termina; não é garantia de sandbox. No Linux, um
descendente que crie novo grupo/sessão escapa do grupo do worker, e a árvore não
tem contenção completa após morte forçada do supervisor: o sinal cobre o filho
direto. Diretório privado/arquivo exclusivo e hashes não eliminam todas as
corridas de filesystem; interpretar/configurar Python privilegiado não é
suportado.

Fila recuperável, idempotência geral, retries, pausa/cancelamento pelo painel,
observabilidade completa e cotas acumuladas continuam pendentes. Não migrar
Nmap/perícia ou ferramentas de terceiros para este runtime antes de comprovar
contenção e contratos de cada adaptador. Uso autorizado é decidido pelo PolicyGate,
não por esse binário isolado nem pela presença de um alvo na rede.

## Compilar e testar

Na raiz, com Rust/Cargo e Python instalados:

```text
cargo fmt --manifest-path packages/execution-engine/Cargo.toml -- --check
cargo clippy --locked --manifest-path packages/execution-engine/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path packages/execution-engine/Cargo.toml
cargo build --locked --manifest-path packages/execution-engine/Cargo.toml
```

Para integração, definir `SENTINEL_TEST_EXECUTION_PATH` com o caminho absoluto
`packages/execution-engine/target/debug/sentinel-execution` (`.exe` no Windows)
e `SENTINEL_TEST_PYTHON_PATH` com Python local. Então:

```text
npx tsx --test apps/api/test/execution.test.ts apps/api/test/imports.test.ts
npm run check
```

A CI compila e configura ambos automaticamente. Sem essas variáveis, os testes
nativos sinalizam skip; não contabilizar como validação do supervisor. QA usa
`SENTINEL_EXECUTION_PATH` e `SENTINEL_TEST_PYTHON_PATH` no servidor sintético,
seguido de `node scripts/browser-archive-qa.cjs`. Recompilar ao mudar de SO;
não transportar target/binários Windows para Debian. `cargo audit` não está
instalado no ambiente local deste checkpoint, portanto não foi executado.

## Estado dos nove motores V11

| Motor | Código comprovado / lacuna |
|---|---|
| Execution | Supervisor0.2.0 integrado, árvore encerrada em cancelamento/timeout e proteção após morte do supervisor; cotas acumuladas, fila recuperável e plugins ainda ausentes |
| Web/API | Análise OpenAPI TypeScript existente; cliente HTTP/crawler Rust ainda ausentes |
| Network | Parsers Nmap/HAR e perícia PCAP existentes; engine Rust de rede ausente |
| Detection | Core TypeScript normaliza/correlaciona eventos; engine Rust e ingestão ampla não entregues |
| Evidence | API/PostgreSQL cifra/hash/audita e vincula evidências; contrato de recibo Rust inicial; engine Rust independente ausente |
| Forensics | Worker Python PCAP/PCAPNG/SQLite/plist existente; processamento Rust ausente |
| Agent Runtime | Agente Rust HMAC/FIM finito existente; serviço/telemetria ampliada dependem de implementação/homologação |
| SecureCode Coordinator | Análises estáticas/SARIF existentes; coordenação Rust de Semgrep/Bandit/Trivy ausente |
| AI Security Coordinator | Análise offline limitada existente; coordenador/modelo local e runtime isolado ausentes |

Próximo incremento: job model recuperável, cancelamento geral pelo painel,
idempotência e cotas acumuladas; depois M2 (cliente HTTP Rust com URL exata,
DNS/IP, SSRF e redirects). Não ampliar executores antes dos controles. ROADMAP
é a fila; essa decisão não cria cronograma paralelo.


## ADR: proteção após falha do supervisor — 0.1.1

O processo Python podia sobreviver a uma morte forçada do Rust0.1.0, mesmo com
cancelamento cooperativo funcionando. A biblioteca padrão não oferece sozinha
os dois controles necessários. Por isso lifetime.rs é a única exceção explícita
a deny(unsafe_code); comentários SAFETY registram propriedade dos handles,
layout/tamanho dos buffers e restrições após fork. A CLI e o restante da
biblioteca continuam sem unsafe autorizado. Nenhum privilégio administrativo,
serviço, firewall ou configuração persistente do Windows é alterado.

No Windows, criar Job Object anônimo/não herdável com KILL_ON_JOB_CLOSE e atribuir
o próprio supervisor **antes** do spawn. O filho herda o job; não habilitar flags
de breakaway. OnceLock retém um único handle até o fim do processo, inclusive
morte forçada. Esse handle intencionalmente não sofre Drop antecipado, que
mataria o supervisor antes do recibo; o SO o fecha na saída. Erros anteriores
à atribuição liberam o handle e recusam o worker. É contrato da CLI de um job,
**não** biblioteca a embutir na API/agente persistentes. Compatibilidade com job
aninhado deve ser comprovada no ambiente. [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
e [atribuição](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject).

No Linux, recusar interpretador set-ID ou com security.capability; configurar
NO_NEW_PRIVS e PDEATHSIG/SIGKILL no filho antes de exec. Conferir getppid após
armar o sinal fecha a corrida em que o pai já morreu. O callback após fork não
aloca buffers, registra logs nem usa locks. A thread criadora permanece viva.
Esse sinal não protege descendentes criados por fork; a garantia atual exige
Python confiável sem mudança de credenciais nem novos filhos. [Contrato Linux](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html).

Testes reais interrompem o supervisor e observam o PID do worker; no Windows
incluem um neto sintético. Linux tem teste de interpretador set-ID recusado e
NoNewPrivs observado no próprio worker. PID zumbi Linux significa processo
terminado aguardando o reaper do sistema, não execução viva nem reap feito pelo
supervisor morto. Nenhum destes testes é homologação Debian. Testes e ambiente
constam de VALIDATION_REPORT.md. Captura de pipes herdados numa árvore geral e
cotas completas permanecem no M1, sem liberar plugins por causa deste recorte.

## ADR: contenção de árvore no cancelamento normal — 0.2.0

O 0.1.1 matava apenas o filho direto. Um descendente do worker sobrevivia ao
cancelamento/timeout e, ao herdar o pipe de stdout, mantinha a captura aberta:
o supervisor podia ficar esperando um EOF que não chegava e nunca emitia o
recibo. O M1 exigia árvore contida no cancelamento normal **e** recibo sempre
emitido. Três decisões, na ordem em que foram tomadas.

**Prova antes do código.** Um programa descartável, fora do repositório, mediu o
comportamento do host: (V1) supervisor fora de job, worker atribuído depois do
spawn, `TerminateJobObject` matou worker e neto e o supervisor sobreviveu;
(V2) supervisor dentro de um job externo, worker herdou o job externo e foi
atribuído a um job interno, e terminar o job interno matou a árvore sem tocar
no supervisor. Conclusão: jobs aninhados funcionam nesta máquina e o job interno
pode ser terminado sem matar quem o supervisiona. A prova não é homologação de
outro SO.

**Duas camadas.** O job externo (0.1.1) continua sendo a garantia de morte do
supervisor: todo descendente herda a associação e morre com o processo. O job
interno é criado depois do spawn, recebe o worker e carrega os limites por SO
(processos vivos, memória, tempo de CPU). Cancelamento, timeout e o caminho
normal terminam o job interno; a API nunca confia em um sinal cooperativo do
worker. No Linux, o worker é líder do seu grupo de processos e o grupo recebe
SIGKILL no mesmo caminho; PDEATHSIG continua cobrindo o filho direto quando o
supervisor morre. Falha ao estabelecer o contêiner recusa a execução: não há
execução sem contenção.

**Captura com prazo.** Matar a árvore fecha os pipes, mas um descendente criado
entre o spawn e a atribuição ao job interno pode escapar do job interno (a
atribuição a job não alcança filhos já existentes). A captura passa a ter prazo
próprio: se o pipe não fechar, o recibo registra `captureComplete:false` e o
estado `capture_incomplete`, e nunca `completed`. Fechar o pipe herdado na
origem exigiria `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` em uma criação de processo
própria; isso continua fora deste recorte.

**Limites por SO.** Windows: job interno com `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`,
`JOB_OBJECT_LIMIT_JOB_MEMORY`, `JOB_OBJECT_LIMIT_JOB_TIME` e
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; o tempo de CPU do job é o timeout da
requisição mais 60s, para que o backstop do SO só atue se o supervisor falhar.
Linux: `RLIMIT_CPU` (timeout+60s/timeout+120s), `RLIMIT_DATA` 1GiB,
`RLIMIT_FSIZE` 64MiB e `RLIMIT_NOFILE` 256 no filho, antes do exec. Nenhum
deles é sandbox de rede ou de disco.

**Fronteiras que continuam abertas.** O Linux não contém a árvore completa após
morte forçada do supervisor (o sinal cobre o filho direto) e um descendente que
crie novo grupo/sessão escapa do grupo. No Windows, um descendente anterior à
atribuição ao job interno sobrevive ao cancelamento até a saída do supervisor,
que fecha o job externo. Nada disso é garantia de isolamento: são contenção de
processo, não sandbox. O worker continua sendo confiável por contrato; a
contenção de árvore é defesa em profundidade, não habilitação de plugins.

