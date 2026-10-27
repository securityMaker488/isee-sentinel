# Executar e interpretar os testes

Use fixtures próprias/sintéticas e bancos isolados. Não aponte testes para banco
de cliente ou serviço PostgreSQL preexistente. Resultados consolidados ficam em
`VALIDATION_REPORT.md` e [PROJECT_STATE.md](PROJECT_STATE.md); executar os comandos
abaixo não foi presumido por escrever este guia.

## Verificações de desenvolvimento

Na raiz, após preparar as ferramentas conforme [DEVELOPMENT.md](DEVELOPMENT.md):

```text
npm run check
cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
python -m unittest discover -s workers/integrity -p test_*.py
python -m unittest discover -s workers/forensics -p test_*.py
python -m unittest discover -s workers/imports -p test_*.py
npm run test:repository
npm run verify:repository
```

No Linux, use `python3` se esse for o executável instalado. `npm run check`
executa TypeScript, build web e testes core/API. Os testes de API normalmente usam
PostgreSQL embarcado isolado. O scanner de repositório examina candidatos, índice
e histórico, mas não prova ausência universal de segredos.

Para uma alteração específica, execute primeiro os testes correspondentes:

```text
npx tsx --test apps/api/test/operations.test.ts
npx tsx --test apps/api/test/imports.test.ts
npx tsx --test apps/api/test/graph.test.ts
npx tsx --test packages/core/test/authorization.test.ts apps/api/test/authorization-manager.test.ts
```

Importações ZIP também precisam de testes do worker real e dos formatos hostis.
Um runner substituto comprova o contrato do adaptador, não a inspeção Python real.
O mesmo cuidado se aplica ao Nmap: testes de argumentos/parsing não são varreduras.

O teste `authorization-manager.test.ts` cobre o ciclo de rascunho, revisão por hash,
aprovação e revogação, integridade da comprovação cifrada, projeto/organização,
substituição de escopos e bloqueio de retorno ao legado. Também exercita os
perfis dos executores e limites por bytes/portas. `authorization.test.ts` verifica
a decisão pura do PolicyGate gerenciado. `target-manifest.test.ts` cobre
identidade exata, exclusões, normalização determinística e entradas hostis.
`lab.test.ts` cobre também revogação após criar o job e antes do despacho. Os testes dos módulos continuam
necessários: um perfil aprovado não substitui validação do formato ou executor.

## Navegador e agente real

Depois do build, abra dois terminais:

```text
npm run qa:server
```

```text
npm run qa:browser
```

QA usa `127.0.0.1:4311`, banco sintético e credenciais temporárias em `.sentinel/qa`.
O roteiro percorre ações reais do painel, preserva screenshots/relatórios e verifica
erros de navegador. O navegador deve estar instalado; o script aceita
`SENTINEL_BROWSER_PATH` e possui fallback para Edge no caminho verificado.
Se o roteiro incluir workers, configure `SENTINEL_PYTHON_PATH` no terminal do
servidor antes de iniciá-lo. Encerre o servidor ao terminar.

Com o mesmo servidor sintético ativo, execute o roteiro específico do Authorization
Manager:

```text
node scripts/browser-authorization-qa.cjs
```

Esse roteiro usa a tela **Autorizações** para registrar e revisar uma comprovação
sintética, aprovar e revogar, conferir downloads, verificar aplicação dos limites
e bloqueio de escopo legado. Inclui manifesto de IPs/portas/exclusões, exportação
e cadastro autorizado/negado, sem despachar Nmap. Também verifica apresentação móvel e erros do
navegador. Seus registros e screenshots ficam em `.sentinel/qa`; o comando não
pressupõe que o resultado seja aprovado. Não reutilize comprovação real de cliente
nessa base descartável.

`npm run verify:agent` usa o binário Rust compilado contra API temporária em
loopback para verificar transporte/baseline/divergência/revogação. Isso não
equivale à implantação de serviço ou monitoramento real no Debian.

## PostgreSQL nativo e restore

`SENTINEL_TEST_DATABASE_URL` e, quando usado pelo teste, `SENTINEL_TEST_RUNTIME_URL`
devem apontar apenas a bases/identidades de teste. Mantenha URLs em ambiente
privado, sem colar credenciais em comandos registrados. A identidade migradora
prepara o esquema; o servidor de teste usa os grants limitados quando configurado.

Para executar especificamente o Authorization Manager em PostgreSQL nativo,
configure `SENTINEL_AUTHORIZATION_TEST_DATABASE_URL` com uma base nova de teste
e a identidade migradora. Opcionalmente configure
`SENTINEL_AUTHORIZATION_TEST_RUNTIME_URL` para a mesma base com a identidade
restrita preparada conforme `ops/runtime-grants.sql`. O teste aplica migrações
(incluindo `009_assessment_authorizations.sql` e `010_target_manifests.sql`), cria fixtures sintéticas e, quando
a URL restrita é fornecida, aplica os grants antes de iniciar a API com essa
identidade. Execute:

```text
npx tsx --test apps/api/test/authorization-manager.test.ts
```

Sem essas variáveis o teste usa PostgreSQL embarcado isolado. A base nativa deve
ser exclusiva e descartável: as fixtures incluem fundador único e registros de
auditoria. Não execute testes concorrentes reutilizando a mesma base/identidade
quando houver preparação ou alteração de credenciais em curso.

Após backup/restauração em banco novo, `npm run verify:restore` compara tabelas
e auditoria usando `SENTINEL_TEST_DATABASE_URL` e `SENTINEL_RESTORE_DATABASE_URL`.
Ele não cria backup, não restaura e não revoga sessões restauradas. Pare gravações
para obter comparação consistente. Veja [BACKUP_RECOVERY.md](BACKUP_RECOVERY.md).

## Evidências e critérios de aceite

Registre versão/alteração, comando, ambiente, dados sintéticos, esperado/observado,
falhas, correções e limitações. Diferencie unitário, API com substituto, processo
real, navegador, PostgreSQL nativo e sistema operacional real. Um erro relevante
impede declarar o fluxo concluído. Cancelamento, recuperação, isolamento e recursos
devem ter casos próprios quando aplicáveis (§53 da V6.9).

A [CI](.github/workflows/ci.yml) prevê Windows e Ubuntu, Node 24, Python 3.11 e
Rust 1.98.1. Preparar o YAML não comprova execução de runner. Ubuntu não substitui
homologação Debian 13, e o workflow não executa testes ofensivos em redes externas.

Regressão do diagnóstico: `node --test scripts/executable-path.test.mjs` valida
ordem do PATH e preservação do nome de proxies como rustc/cargo. O caso de
dispatch por link simbólico POSIX roda no Ubuntu e é explicitamente ignorado
no Windows. `node scripts/doctor.mjs --require-ready` valida o ambiente local
preparado. A CI define o caminho do Python de teste para executar também os
casos positivos/negativos dos workers reais, em vez de ignorá-los.
