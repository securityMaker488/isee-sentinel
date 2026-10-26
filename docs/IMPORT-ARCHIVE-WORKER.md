# Inspetor ZIP 1.0

Contrato integrado e limites completos: [IMPORT_PIPELINE.md](../IMPORT_PIPELINE.md).
Implementação: `workers/imports/inspect_archive.py`, Python3.11+, somente biblioteca
padrão. Não instala dependências, extrai membros, executa código ou acessa rede.

CLI, sobre cópia autorizada:

```text
python -I -B workers/imports/inspect_archive.py --consent --file CAMINHO.zip
```

Saída JSON: `schemaVersion:1.0`, engine `Sentinel Import Inspector`, input com
SHA-256/tamanho/nome/unchanged, `quarantineOnly:true`, entradas com hash/tamanho,
tecnologias indicativas, sugestões de análises e limitações. Sugestões são dados;
não executam testes. Erros retornam código2 sem conteúdo dos membros.

ZIP Stored/Deflate canônico:16MiB recebidos,512 entradas,8MiB por entrada,
64MiB total e razão100. Recusa volumes, ZIP64, data descriptors, links/arquivos
especiais Unix, caminhos ambíguos, colisões Unicode/caixa, arquivos compactados
internos e estrutura inconsistente. Valida CRC e tamanho realmente descomprimido.
Identificação de compactados internos usa extensões/assinaturas reconhecidas;
não promete identificar todos os formatos, poliglotas ou conteúdo ofuscado.

O backend impõe45s e2MiB de saída. A CLI isolada não impõe esses limites de processo
por si só. Python `-I` não bloqueia syscalls nem rede como uma VM. A inspeção
prévia é um recorte experimental e não autoriza executar o pacote no host.

Testes: `python -m unittest discover -s workers/imports`. Fixture sintética
determinística: `fixture_project.py`; cópia base64 em fixtures/lab. O código
importado nesse exemplo é inerte e não é uma aplicação de ProofLab completa.
