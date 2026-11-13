# Universal Import Lab — inspeção ZIP/TAR/TAR.GZ em quarentena

Implementação experimental ampliada em02/11/2026: API, painel e inspetor Python.
O original é preservado cifrado; os membros são examinados em memória sem
extração para o sistema de arquivos, execução ou consulta de rede. A inspeção
concluída mantém `quarantineOnly: true`; não existe ação de liberar ou iniciar a
aplicação. Identificação de tecnologia é indicativa, não certificação de segurança.

## Fluxo disponível

1. Escolher ativo autorizado no painel **Universal Import Lab**. Para registrar
   o projeto, associá-lo previamente ao ativo: a importação herda esse vínculo.
2. Selecionar o formato real e enviar ZIP, TAR ou TAR.GZ de até16MiB. O backend verifica `scan` e `evidence.import`, sessão,
   contexto e CSRF, além do base64 canônico.
3. Criar job `import.zip`, `import.tar` ou `import.tar.gz`, referência ao ativo/projeto e evidência original com
   SHA-256/AES-GCM. Os bytes permanecem preservados se a inspeção posterior falhar.
4. Preparar arquivo temporário exclusivo, iniciar diretamente ou pelo supervisor
   Rust opcional o Python confiável configurado
   em `SENTINEL_PYTHON_PATH` com `-I -B`, sem shell e com ambiente reduzido.
5. Inspecionar estrutura, caminhos, metadados, tamanhos, CRC e conteúdo limitado;
   calcular hashes de membros e indicar tecnologias/testes compatíveis pelo nome
   de arquivos reconhecidos. Não instalar dependências do projeto importado.
6. Validar schema do relatório, formato/hash/tamanho do original e indicação de integridade;
   armazenar relatório ou código de falha, auditar e remover a cópia temporária.
7. Consultar histórico e baixar o registro JSON. Original e relatório continuam
   associados à empresa autenticada.

Projeto ausente no ativo produz `projectId: null` no recorte atual. Planos exigem projeto e podem executar `archive.inspect` com o contexto exato
da revisão em `assessment`. O fluxo avulso permanece disponível, sem vínculo
retroativo. Regras e limites: [planos](docs/ASSESSMENT-PLANS.md).

## Formatos e limites

| Controle | Implementado |
| --- | --- |
| Formatos | ZIP Stored/Deflate; TAR USTAR regular/diretório; TAR.GZ com um membro gzip |
| Original recebido | Até 16 MiB; corpo HTTP até 24 MiB por causa de base64/JSON |
| Entradas | Até 512 |
| Membro descomprimido | Até 8 MiB |
| Soma descomprimida | Até 64 MiB |
| Razão de expansão | Até100 por membro ZIP; TAR.GZ até100 vezes o original, incluindo estrutura TAR |
| Processo | Timeout externo de 45 segundos; saída até 2 MiB |
| Concorrência | Uma inspeção ativa por banco, com bloqueio local e registro persistido |

São recusados: caminhos absolutos/traversal, segmentos ambíguos, separadores e
nomes inseguros entre Windows/Linux, colisões por caixa/normalização Unicode,
links/arquivos especiais, ZIP criptografado, ZIP64, volumes múltiplos, data
descriptors, métodos de compressão não suportados, arquivos aninhados e registros
inconsistentes. Tamanhos declarados não bastam: conteúdo expandido e CRC também
são verificados. Esses controles não provam ausência de vulnerabilidades no parser.

TAR exige USTAR UTF-8, campos octais, cabeçalhos com checksum, padding nulo e
dois blocos finais nulos. Recusa PAX/GNU/sparse/base-256, links e dispositivos.
O formato é explícito: extensão do nome não decide o parser. Gzip recusa múltiplos
membros e limita a estrutura expandida a64MiB +512*1024 +10240 bytes, além da
razão100. Detalhes: [worker](docs/IMPORT-ARCHIVE-WORKER.md).

## Contrato HTTP

| Método e rota | Contrato |
| --- | --- |
| `GET /api/imports/status` | Configuração, formatos aceitos, tamanho/tempo, `quarantineOnly`, `executionAvailable:false`, `networkAccess:false`, `supervisor`, `authorizationCancellation` |
| `POST /api/imports` | `{assetId,name,format,contentBase64,assessment?}`; exige ambos os escopos |
| `GET /api/imports` | Últimas 100 execuções da empresa, estado, ativo/projeto, evidência e erro |
| `GET /api/imports/:id` | Relatório/estado e vínculo da evidência; leitura auditada |
| `POST /api/jobs/:id/cancel` | Cancelamento por requerimento de um job em execução; exige as mesmas operações e o mesmo escopo vigente que autorizaram o job |

Sucesso retorna `id`, `assetId`, `projectId`, `evidenceId`, `status`,
`format`, `quarantineOnly`, `report` e contexto `assessment` quando enviado. O relatório usa `schemaVersion:"1.0"` e engine
`Sentinel Import Inspector`; inclui `input`, `entries` e limitações. A migração
`008_import_quarantine.sql` adiciona `import_runs` e `import_execution_lock`.
A012 preserva identidade/mandato/hash; a013 amplia formatos. Migrações anteriores
não foram modificadas. O backend revalida a autorização exata na preservação,
antes do worker e na aceitação do resultado. Falha mantém o original ligado ao
plano quando enviado. Com `SENTINEL_EXECUTION_PATH` configurado, a API também
revalida durante a execução e cancela o filho ao detectar perda de autorização.
Sem Rust, a revalidação anterior/posterior não interrompe o processo iniciado.
Contrato/limites: [supervisor](docs/RUST-ENGINES.md). O recibo validado aparece em
`report.execution` e auditoria, inclusive falhas posteriores ao início do worker.

`configured:true` verifica presença de caminho absoluto de Python, não todos os
requisitos operacionais. Ausência de configuração retorna `PYTHON_UNAVAILABLE`;
concorrência retorna `IMPORT_BUSY`; entrada/saída inválida, timeout e integridade
geram códigos próprios. Falhas depois da preservação mantêm a evidência.

O cancelamento por requerimento (`POST /api/jobs/:id/cancel`, migração014) grava
`jobs.cancel_requested_at`/`cancel_requested_by`, audita `job.cancel_requested`
e sinaliza o motor em execução. O job termina `cancelled`, com
`error_code=IMPORT_CANCELLED`, e a requisição que originou a importação recebe
409 `IMPORT_CANCELLED`. O original em quarentena permanece cifrado e
verificável; o lock de execução é liberado. Com o supervisor Rust, a árvore do
worker é encerrada na hora; sem ele, o pedido fica registrado e a inspeção
termina na fronteira seguinte. O registro de execução em memória vale para o
processo que executa o job: não há cancelamento entre processos nem fila
distribuída. Reexecução automática e fila central completa seguem ausentes.

## Verificação e limites de confiança

Testes dirigidos disponíveis:

```text
python -m unittest discover -s workers/imports
npx tsx --test apps/api/test/imports.test.ts
```

Em02/11 passaram24 testes do worker no incremento TAR e14 de API no incremento
Rust, também no PostgreSQL com
runtime restrito. Incluem Python real nos três formatos, bytes divergentes,
revogação, falhas, vínculo ao plano e limpeza. A evidência final de versão/ambiente e o resultado do roteiro de painel
pertencem a `VALIDATION_REPORT.md`; essa contagem não representa homologação de
clientes, Debian ou isolamento de VM.

`-I -B` reduz influência da configuração Python; não cria isolamento de sistema
operacional. `networkAccess:false` significa que este fluxo não implementa acesso
à rede, não que exista firewall/VM já homologado. O diretório temporário contém
somente a cópia do arquivo recebido e é removido no término normal; não há garantia de sobrescrita
física dos bytes ou limpeza após falha elétrica. A evidência cifrada tem retenção
separada e permanece no banco.

Não implementados neste módulo: URL/Git, EXE/MSI/DEB/RPM/AppImage/ELF como
aplicações executáveis, APK/AAB/IPA, extração/instalação, ambientes QEMU/KVM,
execução de testes sugeridos ou ProofLab completo. A inspeção pode sugerir análise,
mas não a executa automaticamente. Próximos passos: [ROADMAP.md](ROADMAP.md).

Fontes locais: [API](apps/api/src/imports.ts),
[inspetor](workers/imports/inspect_archive.py),
[teste API](apps/api/test/imports.test.ts),
[teste do worker](workers/imports/test_inspect_archive.py),
[autorização](AUTHORIZATION_POLICY.md) e [segurança de laboratório](LAB_SAFETY.md).
