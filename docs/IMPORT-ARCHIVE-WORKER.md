# Inspetor de arquivos 1.1

Contrato integrado e limites completos: [IMPORT_PIPELINE.md](../IMPORT_PIPELINE.md).
Implementação: `workers/imports/inspect_archive.py`, Python3.11+, somente biblioteca
padrão. Não instala dependências, extrai membros, executa código ou acessa rede.

CLI, sobre cópia autorizada:

```text
python -I -B workers/imports/inspect_archive.py --consent --format zip --file CAMINHO.zip
```

Saída JSON: `schemaVersion:1.0`, engine `Sentinel Import Inspector`, input com
SHA-256/tamanho/nome/formato/unchanged, `quarantineOnly:true`, entradas com hash/tamanho,
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

TAR e TAR.GZ usam `--format tar` e `--format tar.gz` explicitamente. Só USTAR
UTF-8 com arquivos regulares e diretórios: checksum de cabeçalho, campos octais,
prefixo/nome, padding nulo e pelo menos dois blocos finais nulos são verificados.
PAX, extensões GNU, sparse, números base-256, links e dispositivos são recusados.
Caminhos com `./` também são recusados pelo contrato portátil; não pressupor que
qualquer TAR gerado pelas opções padrão de outra ferramenta será aceito.

Gzip aceita um membro, verifica CRC/fim de stream e recusa concatenação/sobra.
A expansão é limitada antes de alocar todo o conteúdo: menor entre100 vezes o
original e `MAX_TOTAL + MAX_ENTRIES*1024 + 10240` bytes para estrutura TAR.
O limite64MiB continua sendo a soma de conteúdos, separada de cabeçalhos/padding.
Nenhum novo pacote Python foi adicionado. Testes TAR: `test_inspect_tar.py`.

Referências de implementação: [formato TAR/USTAR no manual GNU](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
e [descompressão limitada da biblioteca Python](https://docs.python.org/3/library/zlib.html#zlib.Decompress.decompress).


Desde o incremento V11, a API pode supervisionar este mesmo worker com
`SENTINEL_EXECUTION_PATH`. O parser não mudou: o Rust acrescenta contrato,
limites de processo, hashes e recibos, além de receber cancelamento por perda
de escopo. Não é sandbox nem permite outros executáveis/descendentes.
Configuração e limitações: [RUST-ENGINES.md](RUST-ENGINES.md).
