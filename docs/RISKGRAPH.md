# RiskGraph — relações registradas e risco estático

API `GET /api/graph` e tela **RiskGraph** estão conectadas. O módulo consulta os
registros da empresa autenticada e apresenta relações existentes no banco; não
descobre rede nem infere caminhos de exploração. Implementação em
[graph.ts](../apps/api/src/graph.ts) e
[RiskGraphView.tsx](../apps/web/src/RiskGraphView.tsx).

## Dados representados

Nós: empresa, projetos, ativos, última análise SecureBuild de cada ativo, achados
dessas análises, incidentes, alertas, análises de artefato, planos de correção e
referências de evidência. Ligações indicam pertencimento, origem do achado,
evidência de suporte, vínculo com caso ou original/proposta de correção.

O retorno contém `nodes`, `edges`, `truncated`, `counts` e `limitations`.
Cada nó tem identificador tipado, rótulo, tipo, metadados e ativo quando aplicável;
arestas têm origem/destino/relação. Não há conteúdo de arquivo descriptografado
nessa consulta, nem verificação de hash de evidência durante a construção do grafo.

O painel permite filtrar por tipo/ativo, selecionar nós e inspecionar metadados;
mantém ancestrais necessários ao contexto. Atualizar consulta o backend novamente.
A troca de organização deve descartar o grafo anterior e respostas atrasadas.

## Limites e risco

Máximos globais: 200 nós e 500 ligações. Há também limites por categoria, incluindo
20 projetos, 40 ativos, 30 achados e 30 evidências. Projetos/ativos usam ordem de
nome/ID; registros operacionais priorizam os recentes. `truncated:true` indica
que limites cortaram o recorte. Filtros do painel operam sobre esse recorte, não
sobre todos os registros históricos do banco.

O risco de um ativo considera somente os achados da sua última execução
SecureBuild, usando o cálculo estático existente. Só é calculado quando todos
os achados dessa execução estão incluídos. Dados ausentes/incompletos deixam
risco `unknown`; não se interpreta ausência de achados como proteção global.
Análises especializadas, exposição de rede, criticidade contextual completa e
explorabilidade não compõem automaticamente esse score.

Um plano `verified` no grafo refere-se à verificação da cópia de laboratório;
não comprova remediação do host. Arestas não provam acesso, propagação, ataque
possível ou causalidade entre eventos. Alertas sintéticos permanecem identificados.

## Verificação

```text
npx tsx --test apps/api/test/graph.test.ts
```

Há cinco testes dirigidos aprovados registrados pela integração do módulo,
cobrindo o recorte da implementação. Resultado consolidado de API/painel,
isolamento e versão testada fica em `../VALIDATION_REPORT.md` e
[PROJECT_STATE.md](../PROJECT_STATE.md). Isso não homologa o grafo como motor
de caminhos de ataque nem análise de risco empresarial completa.

Próximas ampliações devem definir proveniência, semântica e incerteza de cada
novo vínculo antes de desenhá-lo; veja [roadmap](../ROADMAP.md).
