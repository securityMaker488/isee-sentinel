# Universal Import Lab — recorte ZIP em quarentena

Implementação experimental de 26/10/2026: API, painel e inspetor Python de ZIP.
O original é preservado cifrado; os membros são examinados em memória sem
extração para o sistema de arquivos, execução ou consulta de rede. A inspeção
concluída mantém `quarantineOnly: true`; não existe ação de liberar ou iniciar a
aplicação. Identificação de tecnologia é indicativa, não certificação de segurança.

## Fluxo disponível

1. Escolher ativo autorizado no painel **Universal Import Lab**. Para registrar
   o projeto, associá-lo previamente ao ativo: a importação herda esse vínculo.
2. Enviar ZIP de até 16 MiB. O backend verifica `scan` e `evidence.import`, sessão,
   contexto e CSRF, além do base64 canônico.
3. Criar job `import.zip`, referência ao ativo/projeto e evidência original com
   SHA-256/AES-GCM. Os bytes permanecem preservados se a inspeção posterior falhar.
4. Preparar arquivo temporário exclusivo, iniciar o Python confiável configurado
   em `SENTINEL_PYTHON_PATH` com `-I -B`, sem shell e com ambiente reduzido.
5. Inspecionar estrutura, caminhos, metadados, tamanhos, CRC e conteúdo limitado;
   calcular hashes de membros e indicar tecnologias/testes compatíveis pelo nome
   de arquivos reconhecidos. Não instalar dependências do projeto importado.
6. Validar schema do relatório, hash/tamanho do original e indicação de integridade;
   armazenar relatório ou código de falha, auditar e remover a cópia temporária.
7. Consultar histórico e baixar o registro JSON. Original e relatório continuam
   associados à empresa autenticada.

Projeto ausente no ativo produz `projectId: null` no recorte atual. A exigência
formal de avaliação/plano por projeto da V6.9 ainda precisa ser ampliada; não
presumir que um vínculo opcional entrega todo o Authorization Manager.

## Formatos e limites

| Controle | Implementado |
| --- | --- |
| Formato | ZIP canônico, compressão Stored ou Deflate |
| Original recebido | Até 16 MiB; corpo HTTP até 24 MiB por causa de base64/JSON |
| Entradas | Até 512 |
| Membro descomprimido | Até 8 MiB |
| Soma descomprimida | Até 64 MiB |
| Razão de expansão | Até 100 por membro |
| Processo | Timeout externo de 45 segundos; saída até 2 MiB |
| Concorrência | Uma inspeção ativa por banco, com bloqueio local e registro persistido |

São recusados: caminhos absolutos/traversal, segmentos ambíguos, separadores e
nomes inseguros entre Windows/Linux, colisões por caixa/normalização Unicode,
links/arquivos especiais, ZIP criptografado, ZIP64, volumes múltiplos, data
descriptors, métodos de compressão não suportados, arquivos aninhados e registros
inconsistentes. Tamanhos declarados não bastam: conteúdo expandido e CRC também
são verificados. Esses controles não provam ausência de vulnerabilidades no parser.

## Contrato HTTP

| Método e rota | Contrato |
| --- | --- |
| `GET /api/imports/status` | Configuração, formato ZIP, tamanho/tempo, `quarantineOnly`, `executionAvailable:false`, `networkAccess:false` |
| `POST /api/imports` | `{assetId,name,format:"zip",contentBase64}`; exige ambos os escopos |
| `GET /api/imports` | Últimas 100 execuções da empresa, estado, ativo/projeto, evidência e erro |
| `GET /api/imports/:id` | Relatório/estado e vínculo da evidência; leitura auditada |

Sucesso retorna `id`, `assetId`, `projectId`, `evidenceId`, `status`,
`quarantineOnly` e `report`. O relatório usa `schemaVersion:"1.0"` e engine
`Sentinel Import Inspector`; inclui `input`, `entries` e limitações. A migração
`008_import_quarantine.sql` adiciona `import_runs` e `import_execution_lock`.

`configured:true` verifica presença de caminho absoluto de Python, não todos os
requisitos operacionais. Ausência de configuração retorna `PYTHON_UNAVAILABLE`;
concorrência retorna `IMPORT_BUSY`; entrada/saída inválida, timeout e integridade
geram códigos próprios. Falhas depois da preservação mantêm a evidência. Não há
cancelamento pelo painel, reexecução automática ou fila central completa.

## Verificação e limites de confiança

Testes dirigidos disponíveis:

```text
python -m unittest discover -s workers/imports -p test_inspect_archive.py
npx tsx --test apps/api/test/imports.test.ts
```

Foram comunicados no desenvolvimento Windows 12 testes de worker e 6 de API,
incluindo processo Python real com ZIP positivo de projeto e recusa de ZIP
malformado. A evidência final de versão/ambiente e o resultado do roteiro de painel
pertencem a `VALIDATION_REPORT.md`; essa contagem não representa homologação de
clientes, Debian ou isolamento de VM.

`-I -B` reduz influência da configuração Python; não cria isolamento de sistema
operacional. `networkAccess:false` significa que este fluxo não implementa acesso
à rede, não que exista firewall/VM já homologado. O diretório temporário contém
somente a cópia ZIP e é removido no término normal; não há garantia de sobrescrita
física dos bytes ou limpeza após falha elétrica. A evidência cifrada tem retenção
separada e permanece no banco.

Não implementados neste módulo: URL/Git/TAR.GZ, EXE/MSI/DEB/RPM/AppImage/ELF como
aplicações executáveis, APK/AAB/IPA, extração/instalação, ambientes QEMU/KVM,
execução de testes sugeridos ou ProofLab completo. A inspeção pode sugerir análise,
mas não a executa automaticamente. Próximos passos: [ROADMAP.md](ROADMAP.md).

Fontes locais: [API](apps/api/src/imports.ts),
[inspetor](workers/imports/inspect_archive.py),
[teste API](apps/api/test/imports.test.ts),
[teste do worker](workers/imports/test_inspect_archive.py),
[autorização](AUTHORIZATION_POLICY.md) e [segurança de laboratório](LAB_SAFETY.md).
