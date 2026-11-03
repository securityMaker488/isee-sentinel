# Rust engines — decisão arquitetural e contrato inicial

02/11/2026. Diretriz V11, Marco1 parcial. Este documento registra uma decisão
implementada; a lista de motores abaixo não implica oito novos executáveis.

## ADR: supervisão do worker existente, sem reescrita

Adicionar `packages/execution-engine` como crate independente, com lockfile,
biblioteca e CLI `sentinel-execution`0.1.1. API Fastify conserva identidade,
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
duração, hashes de original/worker/stdout, contadores, truncamento e
`containment` (windows_job ou linux_parent_death). A API exige engine0.1.1 e
o modo correspondente ao SO; atualizar API e binário juntos. Recibo0.1.0
é recusado, sem fallback. Formato de pedido/schemaVersion1 permanece igual. `stdout` só
é retornado no sucesso UTF-8. Estados: completed, failed, cancelled, timed_out,
output_limit, integrity_failed e invalid_output. CLI retorna0 no sucesso,3 na
falha com recibo e2 na recusa de contrato/configuração. Falha anterior ao spawn
não necessariamente gera recibo; a API mantém seu próprio evento de falha.

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

Este supervisor aceita **somente um worker confiável que não cria descendentes**.
Não habilita plugins externos, sandbox, bloqueio de rede, cgroups ou limites de
memória/CPU/disco. Desde0.1.1, Job Object protege a vida dos processos Windows;
Linux configura sinal de morte do pai para o filho direto. Falha ao configurar
nega spawn; plataformas diferentes de Windows/Linux são recusadas. Provas por
SO e limites da árvore aparecem na ADR abaixo; Debian continua por homologar.

EOF após morte da API cancela enquanto o supervisor está vivo. Watchdog Node
fecha o pipe em46s e limita supervisor defeituoso em50s. O controle do SO cobre
o worker direto se o supervisor termina; não é garantia de sandbox. Descendentes
Linux e cancelamento normal de árvores que herdam pipes ainda não são suportados.
Diretório privado/arquivo exclusivo e hashes não eliminam todas as corridas de
filesystem; interpretar/configurar Python privilegiado não é suportado.

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
| Execution | Supervisor0.1.1 integrado, proteção após morte do supervisor Windows/filho Linux; árvore geral, cotas e fila ainda parciais |
| Web/API | Análise OpenAPI TypeScript existente; cliente HTTP/crawler Rust ainda ausentes |
| Network | Parsers Nmap/HAR e perícia PCAP existentes; engine Rust de rede ausente |
| Detection | Core TypeScript normaliza/correlaciona eventos; engine Rust e ingestão ampla não entregues |
| Evidence | API/PostgreSQL cifra/hash/audita e vincula evidências; contrato de recibo Rust inicial; engine Rust independente ausente |
| Forensics | Worker Python PCAP/PCAPNG/SQLite/plist existente; processamento Rust ausente |
| Agent Runtime | Agente Rust HMAC/FIM finito existente; serviço/telemetria ampliada dependem de implementação/homologação |
| SecureCode Coordinator | Análises estáticas/SARIF existentes; coordenação Rust de Semgrep/Bandit/Trivy ausente |
| AI Security Coordinator | Análise offline limitada existente; coordenador/modelo local e runtime isolado ausentes |

Próximo incremento: encerrar árvores também no cancelamento/timeout normal,
sem prender a captura em pipes herdados; limites por SO e depois job model
recuperável. Não ampliar executores antes dos controles. ROADMAP é a fila;
essa decisão não cria cronograma paralelo.


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
