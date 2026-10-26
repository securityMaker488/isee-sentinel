# Sentinel Endpoint Agent — coleta e transporte autenticado

Agente Rust executado com consentimento explícito. Observa um arquivo local escolhido, produz JSON e pode enviar a observação ao coletor cadastrado. O modo padrão permanece uma única observação offline. O monitoramento exige quantidade e intervalo explícitos, e termina ao completar a quantidade.

## Construir e verificar

Na raiz do repositório:

```sh
cargo test --locked --manifest-path packages/endpoint-agent/Cargo.toml
cargo build --locked --release --manifest-path packages/endpoint-agent/Cargo.toml
python -m unittest discover -s workers/integrity -p 'test_*.py' -v
```

Rust/Cargo 1.98.1 é a referência testada no Windows e usada pelo diagnóstico/CI. O manifesto declara rust-version 1.85, mas esse piso não foi homologado com todas as dependências fixadas; `Cargo.lock` fixa as dependências. O build pode baixar crates. O agente usa RustCrypto SHA-256/HMAC, UUID v4 para nonces e reqwest com rustls para HTTPS. Os testes de transporte usam somente servidores temporários em loopback. A validação operacional Debian/Arch permanece separada dos testes executados no Windows.

## Uma observação offline

Use o UUID do ativo autorizado e um arquivo regular local de até 1 MiB:

```sh
packages/endpoint-agent/target/release/sentinel-agent --consent --asset-id 00000000-0000-4000-8000-000000000001 --file ./configuracao-autorizada.txt > observacao.ndjson
python workers/integrity/validate_observation.py --consent --file observacao.ndjson
```

Os identificadores dos exemplos são ilustrativos. No PowerShell use o executável `sentinel-agent.exe`. Para salvar UTF-8 sem depender da versão do PowerShell:

```powershell
$observation = & .\packages\endpoint-agent\target\release\sentinel-agent.exe --consent --asset-id 00000000-0000-4000-8000-000000000001 --file .\configuracao-autorizada.txt
if ($LASTEXITCODE -ne 0) { throw 'Observação não concluída' }
[IO.File]::WriteAllText((Join-Path (Get-Location) 'observacao.ndjson'), $observation + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
```

## Enviar e acompanhar um arquivo autorizado

Cadastre a identidade do agente para o ativo e escopo na plataforma. Salve a credencial retornada em um arquivo privado contendo somente `agentId` (UUID) e `secret` (64 caracteres hexadecimais, 32 bytes). Nunca coloque a chave em argumentos, logs, repositórios ou unidades de serviço. Em Unix o arquivo deve pertencer à conta que executa o agente e não pode conceder acesso a grupo ou outros usuários: modo `0600` ou `0400`. No Windows restrinja a ACL à conta de execução; esta versão verifica links, tipo e tamanho, mas não audita ACLs Windows.

Exemplo de dez observações, com espera de sessenta segundos entre a conclusão de uma e o início da próxima:

```sh
sentinel-agent --consent --asset-id 00000000-0000-4000-8000-000000000001 --file /srv/aplicacao/configuracao.txt --endpoint https://coletor.example --credential-file /home/sentinel/agent-credential.json --iterations 10 --interval-seconds 60
```

Sem `--iterations` e `--interval-seconds`, envia uma única observação. Para monitorar são obrigatórios os dois parâmetros: 1 a 10.000 iterações e intervalo de 10 a 86.400 segundos. O mesmo monitoramento finito funciona offline, emitindo uma linha por observação. O validador Python aceita um documento por arquivo, não um lote NDJSON.

`--endpoint` aceita uma origem HTTPS, com TLS validado, sem credenciais, caminho, query ou fragmento. HTTP de laboratório exige `--allow-loopback-http` e host literal `127.0.0.1` ou `localhost`; este último é resolvido explicitamente para `127.0.0.1`. Proxies automáticos e redirecionamentos são desativados. Não existe opção para ignorar certificado TLS.

Cada requisição tem timeout de dez segundos. Falha de conexão, 408, 429 e 5xx permitem no máximo três tentativas totais, com esperas de um e dois segundos. As tentativas preservam bytes e `observationId`, renovando timestamp e nonce. Os demais erros HTTP encerram a execução. Uma resposta 2xx confirma recebimento; o servidor deve deduplicar `observationId`. Não há fila persistente nem retenção automática de falhas: monitore o código de saída e reprocesse explicitamente quando necessário.

Ctrl-C interrompe as esperas; uma requisição em andamento pode levar até seu timeout. No Unix SIGTERM/SIGHUP também solicitam encerramento. Sucesso retorna código 0; erro, código 2; interrupção, código 130. stdout contém somente as observações concluídas (após aceitação do coletor no modo online); stderr contém erros fixos sem credencial ou resposta remota. O agente não interpreta respostas como comandos.

## Contrato AgentObservation v1

O corpo é um contrato distinto de `SecurityEvent`. O destino de agentes é `POST /agent/v1/observations`, com `Content-Type: application/vnd.sentinel.agent+json` e limite de transporte de 16 KiB.

| Campo | Conteúdo |
| --- | --- |
| `schemaVersion` | número `1` |
| `observationId` | identificador SHA-256 único por coleta, 64 hexadecimais minúsculos |
| `assetId` | UUID minúsculo informado explicitamente |
| `observedAtEpochMs` | relógio local, Unix em milissegundos |
| `source` / `type` | `sentinel-agent` / `integrity.observation` |
| `synthetic` | `false`, pois os bytes foram lidos |
| `host.os` / `host.architecture` | sistema e arquitetura do executável |
| `host.agentProcessId` / `host.agentVersion` | somente PID e versão do próprio agente |
| `file.pathLabel` | basename do arquivo |
| `file.pathId` | SHA-256 do caminho absoluto local canonicalizado, codificado como UTF-8 |
| `file.bytes` / `file.sha256` | quantidade de bytes efetivamente lidos e SHA-256 deles |

`file.pathId` distingue basenames iguais em diretórios diferentes e é obrigatório. Mover ou renomear o arquivo muda seu identificador; a baseline deve então ser aprovada para o novo caminho. O caminho completo não é transmitido, mas seu hash não é uma técnica de anonimização contra quem conhece caminhos candidatos. O schema v1 ainda em desenvolvimento passa a exigir esse campo; observações antigas sem ele precisam ser coletadas novamente.

O envio usa os headers `X-Sentinel-Agent` (UUID), `X-Sentinel-Timestamp` (segundos Unix decimais), `X-Sentinel-Nonce` (UUID v4) e `X-Sentinel-Signature` (HMAC-SHA256 em hexadecimal minúsculo). Decodifique `secret` de hex para 32 bytes antes de calcular HMAC. A mensagem assinada, sem newline final, é:

```text
{timestamp}\n{nonce}\nPOST\n/agent/v1/observations\n{sha256_dos_bytes_exatos_do_corpo_em_hex_minusculo}
```

O coletor verifica identidade, revogação, ativo, escopo autorizado, relógio dentro de 300 segundos e nonce não utilizado. A assinatura autentica a entrega; o JSON exportado isoladamente não contém essa prova. O validador Python só valida a estrutura offline. Baseline e alertas pertencem ao servidor; a primeira observação não deve virar baseline automaticamente.

## Limites e execução

A leitura exige arquivo regular de até 1 MiB e caminho local explícito. Segmentos `..`, links simbólicos e reparse points são rejeitados; Windows também recusa UNC, namespaces de dispositivo e alternate data streams. A abertura usa `O_NOFOLLOW | O_NONBLOCK` em Unix e `FILE_FLAG_OPEN_REPARSE_POINT` com compartilhamento somente de leitura no Windows, seguida de verificação do handle, tamanho e mtime. As mesmas proteções de caminho são aplicadas à credencial, limitada a 4 KiB. Chaves do JSON de credencial desconhecidas, repetidas ou ausentes são rejeitadas. Buffers de credencial e chave usam limpeza de memória ao serem descartados.

O agente não altera o arquivo, enumera processos, lê conteúdo de outros caminhos, varre redes, executa comandos ou instala serviço. Não há adaptador journald/ETW nesta versão. Ancestrais podem mudar entre verificação e abertura em um host comprometido; essas verificações não isolam o agente de um invasor já privilegiado. A observação descreve os bytes lidos, sem atestar a integridade integral do host.

Use uma conta própria sem privilégios, com acesso somente ao arquivo escolhido e à credencial. O binário não configura persistência. A execução e a política de reinício ficam sob controle explícito do operador.
