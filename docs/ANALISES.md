# Análises de artefatos — implementação V6.6

O painel **Análises especializadas** executa análises determinísticas de arquivos
enviados pelo operador. Cada execução salva o original cifrado no EvidenceChain,
seu SHA-256, o relatório e a trilha de auditoria da empresa em contexto. Exige um
ativo cadastrado e autorizações vigentes para `scan` e `evidence.import`.

Esta implementação corresponde a fatias testadas em desenvolvimento (**M3**).
Não representa a totalidade de um produto de SCA, EDR, scanner de vulnerabilidades,
análise dinâmica de malware ou perícia de discos/celulares. A homologação no Debian
e os testes operacionais permanecem separados. As prioridades e dependências do
portfólio estão na matriz V6.6 da raiz.

## Capacidades implementadas

| Tipo no painel | Entrada suportada | Análise real | Limites específicos |
|---|---|---|---|
| Dependências / SecureBuild | `package-lock.json` v2/v3 | Origem HTTP, integridade forte declarada, scripts de instalação, Git sem commit completo | Não baixa pacotes, resolve versões, consulta CVEs ou confirma o conteúdo instalado |
| Dependências / SecureBuild | CycloneDX JSON 1.4–1.6 | Inventário, ausência de versão, presença de SHA-256/SHA-512 | Não verifica os hashes contra arquivos; componentes filhos não são percorridos como um grafo |
| Rede / Nmap | XML Nmap | Hosts, portas detalhadas, portas abertas e observações de serviços obtidas por probe | Não executa Nmap/NSE, não resolve nomes, não interpreta scripts nem `extraports`; porta aberta não é vulnerabilidade |
| Rede / HAR | HAR 1.2 | HTTP, credenciais no export, parâmetros de segredo em URL, CORS inválido, cookie HTTPS sem Secure | Não reproduz requisições, captura tráfego ou analisa corpos; não confirma exploração |
| Qualquer categoria | SARIF 2.1.0 | Importa resultados, nível padrão da regra, separa resultados de terceiros e omite pass/notApplicable/supressões aceitas | Sem reexecução, resolução de referências externas, aplicação de fixes ou equivalência de severidade com CVSS |
| IdentityGuard | `sentinel.identity.v1` | Contas ativas sem MFA declarada; inatividade superior a 90 dias conforme a data observada | Depende do export; contas de serviço exigem interpretação; sem consulta/alteração de diretório |
| CloudShield | Política IAM, configuração S3 ou `sentinel.cloud.v1` | Declarações amplas, principal curinga, complemento de ações/recursos, controles S3 explicitamente desabilitados | Não calcula permissões efetivas, avalia todos os Conditions, SCPs ou consulta nuvem |
| AI Security | `sentinel.ai.v1` | Ferramentas com escrita/execução sem aprovação, rede sem destinos declarados, retenção sem redação e credenciais literais | Não executa modelos ou ferramentas, nem testa resistência a prompt injection |
| MalwareLens | Binário encapsulado em JSON ou script textual | SHA-256, entropia, metadados ELF, tabela PE limitada, seção PE W+X/alta entropia, três padrões lexicais em scripts | Sem execução, descompactação, assinatura digital, reputação, antivírus ou veredito de malícia |
| DeepTrace | `sentinel.timeline.v1` | Validação UTC, ordenação estável, hashes dos eventos, contagem de duplicatas preservadas | Não adquire discos/celulares, recupera apagados ou valida relógios/autenticidade da origem |

Os achados contêm regra, severidade, confiança, localização dentro do original,
recomendação, hash da evidência e procedência (`local_rule` ou `imported_tool`).
O relatório evita copiar mensagens, snippets, contas, URLs, cabeçalhos, cookies e
valores de credenciais. Nomes do artefato e identificadores de tipo/fonte da linha
do tempo são metadados visíveis: não use segredos nesses campos.

## Uso do painel

1. Selecione a empresa e o ativo autorizado.
2. Em **Análises especializadas**, escolha o tipo e selecione um arquivo ou cole
   o conteúdo exportado. A tela informa os formatos aceitos.
3. Para PE/ELF ou outro binário, escolha MalwareLens e marque **Tratar arquivo
   como binário** antes de selecionar o arquivo. O navegador cria um envelope
   Base64; não abre nem executa o conteúdo.
4. Envie em **Analisar e preservar evidência**. Revise métricas, achados,
   procedência e limites. Ausência de achados não comprova segurança.
5. Use **Baixar relatório da análise** para obter o relatório com a referência
   da evidência e contexto autorizado. O histórico é separado por empresa.

O formulário não inicia ferramentas de rede. A importação Nmap/SARIF descreve
saídas obtidas anteriormente dentro de um escopo autorizado. A execução controlada
de ferramentas pertence ao módulo AttackLab e tem controles próprios.

## Formatos dos exports normalizados

Os exemplos abaixo descrevem a estrutura. Substitua-os por dados da coleta.
Datas aceitas usam UTC explícito (`Z`) e são validadas como datas reais.

### Identidades

```json
{
  "format": "sentinel.identity.v1",
  "observedAt": "2026-10-24T00:00:00Z",
  "accounts": [
    {
      "id": "identificador-da-conta",
      "enabled": true,
      "privileged": false,
      "mfaEnabled": true,
      "lastLoginAt": "2026-10-23T00:00:00Z"
    }
  ]
}
```

`enabled`, `privileged` e `mfaEnabled` precisam ser booleanos; valores como
`"false"` são rejeitados. IDs devem ser únicos e não vazios. `lastLoginAt` pode
estar ausente/nulo; nesse caso a inatividade não é inferida. A data do último login
não pode superar `observedAt`. O motor não usa a data atual para alterar resultados.

### Configuração de IA

```json
{
  "format": "sentinel.ai.v1",
  "tools": [
    {
      "name": "consulta",
      "enabled": true,
      "requiresApproval": true,
      "capabilities": ["read", "network"],
      "allowedHosts": ["api.example.test"]
    }
  ],
  "dataRetention": { "storesPrompts": false, "redactionEnabled": true },
  "credentials": { "apiKey": "env:API_KEY" }
}
```

Capacidades reconhecidas: `read`, `write`, `execute`, `network`, sem duplicatas.
`dataRetention` e `credentials` são opcionais. Referências de credenciais aceitas:
`env:NOME`, `${NOME}` ou `secret-ref:caminho`. O analisador não resolve referências.
Valor literal gera indicação para revisão; não é validado junto ao provedor.

### Cloud

Pode ser enviada diretamente uma política IAM com `Statement` ou a resposta S3:

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

Para um inventário normalizado, use
`{"format":"sentinel.cloud.v1","policies":[...],"buckets":[...]}`.
Cada bucket precisa conter `PublicAccessBlockConfiguration`. Uma política de
confiança com `Principal` pode omitir o recurso implícito. Declarações `Deny`
não são acusadas como concessões; tampouco são usadas para afirmar que outras
declarações são inofensivas. Condições reduzem a confiança do resultado e exigem
revisão contextual. Um controle S3 desligado não prova que o bucket seja público.

### Linha do tempo

```json
{
  "format": "sentinel.timeline.v1",
  "events": [
    {
      "occurredAt": "2026-10-24T00:00:00Z",
      "eventType": "file.write",
      "source": "coleta-autorizada",
      "message": "Descrição opcional preservada apenas no original."
    }
  ]
}
```

`eventType` e `source` devem ser identificadores de até 100 caracteres,
começando com letra e contendo letras, números, ponto, hífen ou sublinhado.
Um `sha256` opcional de referência precisa ter 64 dígitos hexadecimais minúsculos;
o motor não acessa o arquivo referenciado. O hash de cada evento inclui todos os
campos recebidos. Eventos idênticos são contados, mas não excluídos. A tela mostra
os primeiros 100; o relatório conserva até 2.000 eventos.

### Binário

```json
{
  "format": "sentinel.binary.v1",
  "encoding": "base64",
  "data": "BASE64_CANONICO_DO_ARQUIVO"
}
```

O original preservado é o envelope UTF-8. O relatório registra separadamente o
SHA-256 do envelope e o SHA-256 dos bytes decodificados. Base64 inválido,
não canônico ou cabeçalho PE/ELF truncado é rejeitado. A entropia alta e flags
W+X podem ocorrer em programas legítimos. Scripts textuais verificam apenas
PowerShell com comando codificado, avaliação de conteúdo codificado e download
encaminhado a shell; comentários e exemplos podem coincidir com esses padrões.

## Contrato e limites

`analyzeArtifact({name, mediaType, content, kind})` é exportado por
`@sentinel/core` e retorna `ArtifactAnalysisReport`. Entradas inválidas lançam
`ArtifactAnalysisError` com código `INVALID_ARTIFACT` e mensagens sem trechos do
conteúdo. O nome é um rótulo, nunca um caminho aberto pelo motor.

Rotas integradas:

- `POST /api/analyses`: corpo `{assetId, kind, name, mediaType, content}`;
  exige sessão, CSRF e os dois escopos vigentes.
- `GET /api/analyses`: últimas 100 execuções da empresa.
- `GET /api/analyses/:id`: relatório registrado e referência da evidência.
- `GET /api/reports/analysis/:id`: relatório de exportação com contexto e
  verificação da evidência.

Limites atuais: 1 MiB em UTF-8 por artefato, 48 níveis e 50.000 tokens/elementos
estruturais, até 2.000 registros por coleção, 500 achados e 2.000 eventos de linha
do tempo. O envelope aumenta o tamanho de binários em aproximadamente um terço;
o arquivo binário precisa ficar abaixo de 768 KiB. Nomes têm até 240 caracteres.
O MIME deve ser `tipo/subtipo`, sem parâmetros. Conteúdo com NUL é rejeitado
fora do envelope binário.

Limites excedidos são erros explícitos, sem truncamento silencioso de achados.
JSON rejeita chaves duplicadas, inclusive chaves equivalentes escritas com escapes.
XML usa `saxes` sem acesso externo; aceita o `<!DOCTYPE nmaprun>` inerte emitido
pelo Nmap e rejeita subconjuntos DTD, entidades externas e declarações internas.
Instruções XSL não são avaliadas. O parser nunca abre URLs, caminhos ou referências.

## Verificação executada

`packages/core/test/analysis.test.ts` contém **17 testes** que passaram no ambiente
Windows de desenvolvimento: casos positivos e negativos, tamanho/profundidade,
JSON ambíguo, DTD/entidades, supressão SARIF, segredos omitidos, datas impossíveis,
limites PE e hashes estáveis. Os **34 testes do core** e o typecheck da interface
também passaram nesta implementação. A integração API e o fluxo de navegador
possuem verificações próprias registradas no documento geral de validação.

## Referências e dependência

- [Formato package-lock do npm](https://docs.npmjs.com/files/package-lock.json/):
  campos `packages`, `resolved`, `integrity` e `hasInstallScript`.
- [Saída XML do Nmap](https://nmap.org/book/output-formats-xml-output.html):
  estados de portas, serviço, método e confiança de identificação.
- [SARIF 2.1.0, OASIS](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html):
  resultados, regras, níveis e procedência importada.
- [Rascunho HAR 1.2](https://w3c.github.io/web-performance/specs/HAR/Overview.html):
  entradas, requisições, respostas e cabeçalhos.
- [Principal em políticas IAM, AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
  e [Resource em políticas IAM, AWS](https://docs.aws.amazon.com/us_en/IAM/latest/UserGuide/reference_policies_elements_resource.html):
  curingas exigem interpretação de política e contexto.
- [saxes](https://github.com/lddubeau/saxes), versão fixada 6.0.0, licença ISC:
  parser XML sem carregador de entidades externas. A dependência e sua transitiva
  constam do lockfile e do inventário gerado do projeto.

Formatos `sentinel.*.v1` são contratos deste projeto, não formatos nativos de
provedores. Sua existência não implica integração automática com esses provedores.
