# Integrity worker — validação offline

Worker Python 3.11+, somente biblioteca padrão. Recebe um arquivo JSON ou uma única linha NDJSON com `AgentObservation` v1. Valida campos, versão, UUID, formatos SHA-256 e limites, incluindo `file.pathId` obrigatório. Não acessa o arquivo observado, recalcula o hash de origem, autentica o produtor, envia dados ou modifica arquivos.

```sh
python workers/integrity/validate_observation.py --consent --file observacao.ndjson
python -m unittest discover -s workers/integrity -p 'test_*.py' -v
```

Resultado válido informa `valid:true`, `contentHashVerified:false`, `sourceAuthenticated:false` e `integration:"offline_only"`. `valid` significa somente conformidade de estrutura. O transporte online do agente autentica a entrega ao servidor com headers HMAC; esses headers não fazem parte do JSON offline, e o worker não os verifica.

A entrada tem limite de 64 KiB, UTF-8 e campos conhecidos. Chaves JSON duplicadas, NaN, múltiplos registros, booleanos usados como números, paths no lugar de basename e tamanhos superiores ao agente são rejeitados. `file.pathId` deve ser SHA-256 hexadecimal minúsculo; o worker não deriva nem verifica o caminho de origem. Observações antigas sem esse campo precisam ser coletadas novamente. A API de agentes impõe seu próprio limite de corpo de 16 KiB.

Abertura somente leitura com bloqueio de seguimento do último componente, rejeição prévia de links/reparse points nos ancestrais e verificação de tamanho/mtime. No Windows, `ctypes` chama `CreateFileW` com `OPEN_REPARSE_POINT`; no Unix usa `O_NOFOLLOW`. As verificações não isolam o processo de alterações maliciosas de ancestrais em host comprometido.

O teste entre processos executa o binário Rust compilado contra um arquivo de teste temporário, compara o hash real e valida a observação. Não produz telemetria no banco ou painel. Se o agente ainda não foi compilado, o teste é explicitamente ignorado. O teste de symlink Unix é ignorado no Windows sem solicitar privilégios.

Consulte `packages/endpoint-agent/README.md` para o schema e o protocolo de envio. Baseline, escopo, deduplicação, revogação e alertas são responsabilidades do coletor da API.
