# Worker de perícia de artefatos — V6.6

`workers/forensics/analyze_artifact.py` inspeciona um arquivo indicado pelo
operador: PCAP/PCAPNG, SQLite ou plist XML/binário. É um worker Python portátil,
testado em desenvolvimento no Windows com Python 3.11.9. Usa somente a biblioteca
padrão e funciona com `python -I -B`. Python precisa incluir `sqlite3`, `plistlib`
e Expat. A homologação no Debian ainda é uma etapa separada.

O arquivo original é aberto somente para leitura e recebe SHA-256 antes e depois
da análise. A saída exige conteúdo e metadados estáveis durante a operação.
Não há busca por dados pessoais no computador, aquisição de disco/celular,
captura ao vivo, conexão de rede, descriptografia ou execução de conteúdo.

## Uso local

```powershell
python -I -B workers/forensics/analyze_artifact.py --consent --file "C:\caso\trafego.pcapng" --kind pcap
python -I -B workers/forensics/analyze_artifact.py --consent --file "C:\caso\export.sqlite" --kind sqlite
python -I -B workers/forensics/analyze_artifact.py --consent --file "C:\caso\export.sqlite" --kind sqlite --table "events"
python -I -B workers/forensics/analyze_artifact.py --consent --file "C:\caso\preferences.plist" --kind plist
```

Use caminhos da sua coleta autorizada. No Linux, os mesmos argumentos aceitam
caminhos locais POSIX. `--consent` é obrigatório. `--table` e `--include-values`
são exclusivos de SQLite. O comando escreve um único relatório JSON em stdout;
erros vão para stderr com código de saída 2, sem fragmentos do artefato ou caminho
completo. Código 0 confirma que a análise terminou e o original permaneceu igual
nas verificações realizadas.

## NetworkTrace: PCAP e PCAPNG

Implementado:

- PCAP 2.4 em little/big endian, com resolução de microssegundos ou nanossegundos.
- PCAPNG com seções em ambas as ordens de bytes, interfaces por seção, Enhanced
  Packet Blocks e Simple Packet Blocks. Interpreta resolução decimal/binária e
  deslocamento temporal da interface. Simple Packet Blocks permanecem sem data.
- Ethernet com até duas tags VLAN, IP bruto, link types IPv4/IPv6, TCP, UDP,
  ICMP/ICMPv6 e ARP Ethernet/IPv4.
- Agregação direcional por protocolo, endereços e portas: pacotes, bytes
  capturados/originais, primeiro/último instante e contagem de flags SYN/FIN/RST.
- Contadores explícitos para fragmentos, captura truncada, quadros não
  interpretados, blocos desconhecidos e fluxos omitidos pelo limite.

Não há montagem de sessões TCP, remontagem de fragmentos, validação de checksum,
interpretação de payload, DNS, descriptografia TLS ou afirmação de ataque.
Fragmentos não iniciais ficam em fluxos separados sem portas; até oito extensões
IPv6 são percorridas. Tipos de enlace não suportados entram no contador
`unsupportedOrMalformedPackets`. Blocos PCAPNG legados do tipo Packet Block são
rejeitados explicitamente; exporte Enhanced Packet Blocks.

Os endereços e portas vêm apenas do arquivo enviado. Datas usam UTC com até nove
casas decimais; resoluções menores que um nanossegundo são truncadas para essa
precisão. O worker não verifica o relógio do equipamento que fez a captura.

## DiskLab/MobileScope: SQLite exportado

O worker cria um snapshot temporário privado dos bytes já lidos. SQLite abre
esse snapshot por URI com `mode=ro&immutable=1`. Isso impede que o motor SQLite
reabra o caminho original ou misture arquivos WAL/SHM/journal existentes ao lado
do artefato. O snapshot é removido ao término normal.

A conexão aplica `query_only=ON`, `trusted_schema=OFF`, extensões desabilitadas,
limites de tamanho/colunas, orçamento de instruções e tempo. Um autorizador nega
operações por padrão e permite somente as leituras internas necessárias.
Identificadores de tabela/coluna vêm do esquema e são escapados como
identificadores SQL; o nome indicado em `--table` precisa corresponder a uma
tabela comum existente. Nenhum SQL informado pelo operador é executado.

O relatório fornece tabelas, colunas, tipos declarados, chaves e contagem de
linhas. Views, gatilhos e tabelas virtuais não são executados; colunas geradas ou
ocultas não entram na seleção de valores. `--table` adiciona hashes de até 1.000
linhas, em ordem de percurso sem garantia de ordenação. O indicador
`rowsTruncated` informa se há linhas adicionais.

Por padrão, o relatório de linhas inclui apenas número ordinal e hash dos valores
tipados. Com a opção local explícita `--include-values`, inclui escalares e os
primeiros 1.024 caracteres de textos, indicando cortes. Blobs continuam como
tamanho e hash. Essa opção pode revelar informações sensíveis da tabela e não
faz parte da integração API inicial. Nomes de tabelas e colunas são metadados
visíveis em ambos os modos.

Use um export consistente, fechado e completo do banco principal. O worker não
faz merge de WAL, não recupera registros apagados e não garante consistência de
uma cópia obtida de um aplicativo ativo. A biblioteca SQLite do Python precisa
ser mantida atualizada; o relatório registra `sqliteRuntime`.

## MobileScope/DeepTrace: plist exportado

O parser padrão `plistlib` lê XML e binário após verificações estruturais. XML
rejeita entidades declaradas, elementos não suportados, chaves duplicadas e
profundidade excessiva. O cabeçalho/trailer binário é limitado antes do parsing;
a árvore final é verificada contra profundidade, número de nós e ciclos.

Somente valores tipados como datetime no plist entram na linha do tempo. Números
e strings que se parecem com datas não são convertidos por suposição. A saída
normaliza UTC e identifica a posição ordinal do valor no arquivo. Chaves de
dicionário, strings e dados binários não são copiados ao relatório.

O timestamp informa que existe um datetime naquela posição; não prova que um
evento específico ocorreu. Referências UID de NSKeyedArchiver não são resolvidas.
O worker não acessa dispositivos, backups de contas ou dados criptografados.

## Contrato de saída

```json
{
  "schemaVersion": "1.0",
  "engine": "Sentinel Offline Forensics",
  "engineVersion": "1.0.0",
  "kind": "pcap",
  "input": {
    "name": "capture.pcap",
    "sha256": "digest-hexadecimal-do-arquivo-original",
    "bytes": 1234,
    "unchanged": true
  },
  "summary": "Resumo calculado a partir do artefato.",
  "metrics": {},
  "flows": [],
  "limitations": []
}
```

`flows` existe para PCAP/PCAPNG. SQLite fornece `tables` e `rows`. Plist fornece
`timeline` com `occurredAt`, `eventType`, `source`, `location` e `evidenceHash`.
O nome é somente o basename original; o relatório não contém o caminho completo.
O hash do artefato permanece necessário para interpretar posições ordinais.

Limites:

| Recurso | Limite |
|---|---:|
| Arquivo original | 16 MiB |
| Relatório JSON | 4 MiB |
| Pacotes | 100.000 |
| Fluxos retidos | 4.096; excedentes contados |
| Blocos PCAPNG | 200.000 |
| Interfaces por seção | 256 |
| Objetos do esquema SQLite | 256 |
| Colunas por tabela SQLite | 64 |
| Linhas exportadas | 1.000 |
| Operações aproximadas da VM SQLite | 1.000.000 / 5 segundos |
| Nós plist | 50.000 |
| Profundidade plist | 48 |
| Datetimes plist | 2.000 |

Limites de arquivo, pacote, estrutura, tempo e saída geram erro explícito. Somente
os limites documentados de fluxos, linhas e prefixos de texto permitem corte,
sempre com indicador. Links simbólicos, reparse points, caminhos de rede/device
Windows, alternate data streams e caminhos contendo `..` são recusados. O Windows
abre o original com compartilhamento de leitura, impedindo escrita/remoção
simultânea por aberturas normais enquanto o handle está ativo.

## Validação realizada

**16 testes sintéticos passaram no Windows/Python 3.11.9**, cobrindo:
endian/precisão PCAP; PCAPNG multi-section, resolução, offset e ausência de data;
VLAN, TCP, ARP, IPv6, fragmentos; tamanhos inválidos; overflow de fluxos; esquema,
seleção de tabela e negação de escrita SQLite; 1.000 linhas e ausência de sidecars;
plist XML/binário, datas reais, redação, entidades e duplicatas; hashes e execução
isolada do CLI. Nenhum teste varreu a rede ou leu dados pessoais reais.

```powershell
python -I -B -m unittest discover -s workers/forensics -p test_analyze_artifact.py -v
```

Esses testes comprovam as funções delimitadas acima em desenvolvimento, não uma
certificação de ferramenta pericial, operação EDR ou homologação Linux.

## Fontes primárias

- [Formato PCAP, libpcap](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap-savefile.manfile.in).
- [PCAPNG, draft IETF de setembro de 2026](https://www.ietf.org/ietf-ftp/internet-drafts/draft-ietf-opsawg-pcapng-06.html).
- [URI SQLite e modo imutável](https://www.sqlite.org/uri.html),
  [autorizador SQLite](https://www.sqlite.org/c3ref/set_authorizer.html) e
  [trusted_schema](https://www.sqlite.org/pragma.html#pragma_trusted_schema).
- [sqlite3 no Python](https://docs.python.org/3/library/sqlite3.html) e
  [plistlib no Python](https://docs.python.org/3/library/plistlib.html).

As referências fundamentam formatos e interfaces. A cobertura implementada é
expressamente a descrita neste documento, não toda a especificação desses formatos.
