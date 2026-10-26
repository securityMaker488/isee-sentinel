# Referência dos comandos disponíveis

Execute a partir da raiz do repositório. Os comandos abaixo existem no projeto;
a CLI unificada `sentinel` descrita pela V6.9 ainda é planejada. Não há comandos
implementados `sentinel lab start`, `sentinel import url`, `sentinel assessment run`
ou `sentinel compare create`.

## Aplicação e administração local

| Comando | Efeito / condição |
| --- | --- |
| `npm run build` | Verifica tipos e gera o frontend |
| `npm start` | Inicia API e frontend compilado; verifica esquema sem migrá-lo |
| `npm run dev` | Inicia o mesmo servidor via tsx; não é um bypass de autenticação |
| `npm run bootstrap` | Aplica migrações e provisiona um único fundador em banco novo; exibe credenciais uma vez |
| `npm run db:migrate` | Aplica migrações/checksums com identidade apropriada e chave existente |
| `npm run operator:recover` | Recuperação interativa com código offline; troca credenciais e revoga sessões |
| `npm run operator:adopt` | Seleciona fundador em base antiga compatível mediante senha/TOTP |
| `npm run inventory` | Gera inventário local das dependências |

Bootstrap/recuperação/adopção são operações administrativas sensíveis. Use
terminal privado, banco dedicado e chave correta; nunca registre a saída com
credenciais em logs. Faça backup antes de migração/adopção. Não apague banco para
forçar provisionamento. Configuração: [DEPLOYMENT.md](DEPLOYMENT.md).

## Verificação e preparação

| Comando | Finalidade |
| --- | --- |
| `npm run typecheck` | TypeScript da API/core/web |
| `npm test` | Testes core/API |
| `npm run check` | Build e testes JavaScript |
| `npm run qa:server` | Servidor sintético isolado na porta 4311 |
| `npm run qa:browser` | Roteiro Playwright contra esse servidor |
| `npm run verify:agent` | Binário Rust → API temporária em loopback |
| `npm run verify:restore` | Compara bancos original/restaurado explicitamente configurados; não restaura |
| `npm run test:repository` | Testes do scanner de repositório |
| `npm run verify:repository` | Examina arquivos candidatos, índice e histórico; não publica |
| `node scripts/doctor.mjs --json` | Diagnóstico somente leitura, sem valores de segredos |
| `node scripts/doctor.mjs --require-ready` | Exige também dependências/builds locais presentes |

Wrappers: `scripts/doctor.ps1` (`-Json`, `-RequireReady`) e `scripts/doctor.sh`.
Setup: `scripts/setup-windows.ps1` (`-RunTests`) ou
`bash scripts/setup-debian.sh` (`--test`). Preparação não instala o sistema nem
cria serviço/banco operacional. [TESTING.md](TESTING.md) detalha ambientes e limites.

## Agente e workers

O binário `sentinel-agent` é construído pelo Cargo; no Windows possui extensão
`.exe`. Seus argumentos existentes incluem `--consent`, `--asset-id`, `--file`,
`--endpoint`, `--credential-file`, `--iterations`, `--interval-seconds` e a opção
restrita de laboratório `--allow-loopback-http`. Segredos ficam no arquivo privado,
nunca em argumento. O modo padrão observa uma vez e não instala serviço.
Exemplos e contrato: [README do agente](packages/endpoint-agent/README.md).

O worker `workers/forensics/analyze_artifact.py` aceita `--consent --file CAMINHO
--kind pcap|sqlite|plist`; opções SQLite são documentadas no
[guia forense](docs/FORENSE-WORKER.md). Ele não adquire dispositivos.
O validador `workers/integrity/validate_observation.py` valida observação exportada;
não autentica por si só um JSON offline nem envia telemetria.

O inspetor ZIP é invocado pelo importador com Python isolado de configuração
(`-I -B`), consentimento e arquivo temporário explícitos. Não há uma CLI Sentinel
de importação completa; veja [IMPORT_PIPELINE.md](IMPORT_PIPELINE.md).

Rotas HTTP documentadas no OpenAPI autenticado (`GET /api/openapi.json`) não
implicam comandos de terminal equivalentes. Clientes futuros precisam reutilizar
PolicyGate e contratos existentes, sem aceitar parâmetros arbitrários de shell.
