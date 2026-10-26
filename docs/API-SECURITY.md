# Auditoria de configuração de API

O módulo `packages/core/src/api-audit.ts` exporta `analyzeOpenApi(content, report)`. Recebe o texto JSON de um documento OpenAPI 3.0.x ou 3.1.x e acrescenta achados, métricas e limitações a um `ArtifactAnalysisReport` existente. A integração com a plataforma usa o tipo de análise `api`; este módulo não implementa rotas HTTP próprias.

A análise é passiva e limitada ao documento fornecido. Não consulta a API descrita, não resolve DNS, não acessa arquivos, não baixa referências e não executa conteúdo. Não identifica BOLA/BFLA, SSRF, exploração, injeção, rate limiting ou configuração efetiva de produção. Esses resultados exigem outros controles e validação autorizada.

## Interpretação de autenticação

O requisito global `security` é herdado pelas operações que não declaram uma substituição. Quando a operação declara `security`, ela substitui a definição global: `[]` remove os requisitos, e uma alternativa `{}` permite acesso anônimo. As entradas de um array são alternativas **OR**; vários esquemas dentro do mesmo objeto devem ser satisfeitos juntos, em **AND**. Isso segue os objetos [Operation e Security Requirement da especificação OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html#security-requirement-object).

Uma lista OAuth2/OpenID de scopes vazia pode ser válida e não significa acesso anônimo. O mapa de scopes de um fluxo OAuth2 também pode ser vazio. Em OpenAPI 3.0, requisitos de outros tipos de esquema exigem arrays vazios; em 3.1, esses arrays podem representar papéis. O módulo respeita essa diferença entre [OpenAPI 3.0.4](https://spec.openapis.org/oas/v3.0.4.html#security-requirement-object) e [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html#security-requirement-object).

Operações sem qualquer declaração aplicável recebem um resultado informativo separado das operações explicitamente anônimas. Esquemas desconhecidos geram uma inconsistência de contrato; não são interpretados como ausência de autenticação. Uma operação pública pode ser intencional. O relatório pede revisão de intenção e implementação, sem declarar uma vulnerabilidade de acesso indevido.

## Regras implementadas

| Regra | Evidência no documento | Interpretação |
| --- | --- | --- |
| `API-ANONYMOUS-001` | `security: []` efetivo ou alternativa `{}` | Operação explicitamente pública ou com alternativa anônima; informativo |
| `API-SECURITY-UNSPECIFIED-001` | Sem `security` global ou local aplicável | Documentação de segurança ausente; informativo |
| `API-SCHEME-UNKNOWN-001` | Requisito cita nome não declarado | Inconsistência de contrato |
| `API-QUERY-KEY-001` | `apiKey` com `in: query` | Revise transporte de credenciais em URLs e retenção em logs |
| `API-SERVER-HTTP-001` | URL absoluta de servidor declara HTTP | Transporte sem TLS declarado, sem confirmação de implantação |
| `API-AUTH-HTTP-001` | URL OAuth/OpenID declara HTTP | Endpoint de autenticação sem TLS declarado |
| `API-URL-SCHEME-001` | Protocolo fora de HTTP/HTTPS | Revisão complementar; URL não consultada |
| `API-OAUTH-FLOW-001` | Esquema OAuth2 sem fluxo documentado | Lacuna de documentação; informativo |
| `API-OAUTH-SCOPE-001` | Requisito cita scope ausente dos fluxos locais | Inconsistência entre requisito e descrição do provedor |
| `API-SERVER-VARIABLE-001` | Servidor usa variáveis | Somente defaults analisados; alternativas precisam de revisão |
| `API-BODY-SCHEMA-001` | Media type de requestBody sem schema | Entrada não descrita por schema |
| `API-BODY-FREEFORM-001` | Schema booleano `true` em 3.1 | Aceita qualquer valor no contrato |
| `API-BODY-TYPE-001` | Schema simples sem tipo, enum ou const aplicável | Tipo de entrada não explicitado; informativo |
| `API-STRING-LIMIT-001` | String sem maxLength ou conjunto finito | Revise tamanho permitido de strings |
| `API-ARRAY-LIMIT-001` | Array sem maxItems ou restrição finita reconhecida | Revise quantidade permitida de itens |
| `API-OBJECT-LIMIT-001` | Objeto permite propriedades adicionais sem maxProperties | Revise quantidade e conteúdo das propriedades |
| `API-REFERENCE-001` | Referência/composição/dialeto fora da resolução suportada | Trecho explicitamente não concluído; revisão complementar |

Os achados de limites são verificações de configuração, não provas de consumo ilimitado de recursos. Um proxy, gateway ou aplicação pode impor limites que não estão no OpenAPI. Inversamente, declarar `maxLength`, `maxItems` ou `maxProperties` não comprova que o serviço os aplica. Strings e coleções com valores finitos por `enum`/`const` reconhecidos não recebem alertas apenas por falta desses campos. Propriedades `readOnly: true` são ignoradas na análise de corpo de requisição.

## Referências e cobertura

Referências locais simples em JSON Pointer são resolvidas em memória, incluindo escapes `~0`/`~1` e fragmentos percent-encoded. O resolver usa somente propriedades próprias do documento. Referências externas, âncoras, ponteiros ausentes, ciclos ou `$ref` com campos adicionais que mudariam a interpretação recebem `API-REFERENCE-001`. Nenhuma referência é carregada da rede ou do disco.

Schemas simples de `requestBody` podem conter propriedades e itens aninhados. Composições `allOf`/`anyOf`/`oneOf`, condicionais, schemas recursivos, padrões de propriedades e dialetos customizados são sinalizados para revisão. O módulo não tenta inferir limites de uma composição que poderia alterá-los. Não é um validador completo OpenAPI nem JSON Schema; valida apenas as estruturas necessárias às verificações realizadas.

Parâmetros de query/header/path, schemas de resposta, callbacks e webhooks não recebem análise profunda de entrada nesta versão. Callbacks e webhooks presentes são sinalizados. Componentes sem utilização em operações podem não ser percorridos. Esta cobertura deve acompanhar o resultado; uma API sem achados não está certificada como segura.

Todos os servidores declarados são inspecionados, inclusive servidores globais que alguma operação pode substituir. URLs relativas ou dependentes de base não são classificadas como HTTP sem TLS. Variáveis de servidor usam os valores padrão, validados contra enums quando presentes; não há expansão combinatória. A identificação de HTTP descreve o contrato, não mede o transporte efetivo.

## Proteção de dados e limites

Os relatórios não copiam URLs, parâmetros, nomes de esquemas, scopes, caminhos, exemplos ou conteúdos de credenciais. As localizações usam índices da ordem original do documento, como `/paths/#2/post/security` e `/components/securitySchemes/#1`. A ordem é a de inserção no JSON. O operador consulta o artefato original cifrado para identificar o item correspondente. Referências locais podem exigir seguir o ponteiro no original.

Cada achado usa o helper de evidência existente para gerar hash SHA-256 e identificador determinístico. Isso permite relacionar o resultado aos bytes/documento analisados sem inserir os valores sensíveis no relatório. Hashes não tornam valores previsíveis anônimos e não comprovam a autenticidade do documento enviado.

Aplicam-se os limites comuns: 1 MiB de texto, profundidade de JSON 48, cinquenta mil tokens estruturais, até duas mil entradas por coleção e quinhentos achados. O resolvedor limita cadeias locais a 32 referências e a auditoria limita o trabalho expandido. Limites excedidos geram erro explícito; resultados não são silenciosamente truncados. Chaves JSON duplicadas e estruturas relevantes malformadas são rejeitadas. Erros não reproduzem os valores recebidos.

## Verificação

```sh
npx tsx --test packages/core/test/api-audit.test.ts
```

Os testes cobrem herança e substituição de segurança, AND/OR, acesso anônimo explícito, esquemas desconhecidos, diferenças 3.0/3.1, scopes vazios válidos, URLs HTTP/relativas/parametrizadas, referências locais e externas, ciclos, limites de schema, composições, dialetos, redaction, limites de processamento e determinismo. Nenhum teste consulta uma API real.
