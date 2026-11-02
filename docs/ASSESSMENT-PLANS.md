# Planos de avaliação versionados

O plano reúne objetivo, projeto, etapas e uma referência exata à autorização
revisada. Não concede novas permissões: cada execução continua dependente do
PolicyGate, da vigência e dos limites da autorização original.

## Modelo e fluxo

1. Criar projeto/ativos e revisar uma autorização no Authorization Manager.
2. Criar um plano com nome, objetivo e etapas selecionadas dos perfis existentes.
   Cada etapa identifica um ativo. Inventário exige também endereço e portas
   permitidos pelo manifesto; exclusões continuam prevalecendo.
3. Preservar a revisão, seu SHA-256 canônico e o hash do pedido autorizado.
4. Para alterar o plano, criar outra revisão indicando o hash da revisão anterior.
   Revisões antigas permanecem disponíveis; uma atualização concorrente exige
   recarregar o histórico antes de tentar novamente.
5. Executar a análise estática ou inspeção de arquivo de uma etapa selecionada. O backend verifica a
   revisão exata e a autorização vigente e registra o vínculo com o job, o scan
   e as evidências preservadas. Resultados não são anexados retroativamente.
6. Consultar o histórico e exportar os metadados do plano e dos resultados.
   O download de originais continua submetido às permissões de evidências.

`static.scan` e `archive.inspect` possuem execução integrada ao plano.
Os demais perfis podem compor o planejamento; seus executores próprios não
recebem automaticamente vínculos com planos. Isso aparece no catálogo e na UI.
Um plano não transforma serviço descoberto em vulnerabilidade confirmada.

## Contrato HTTP

Todas as rotas usam sessão autenticada e contexto de organização. Mutações exigem
CSRF. O catálogo informa limites e suporte real de execução por perfil.

| Método / rota | Uso |
|---|---|
| GET `/api/assessment-plans/catalog` | Perfis existentes e suporte de execução pelo plano |
| GET `/api/assessment-plans` | Lista limitada, com referência à revisão mais recente |
| POST `/api/assessment-plans` | Plano e primeira revisão |
| GET `/api/assessment-plans/:id` | Revisões preservadas e resultados vinculados |
| POST `/api/assessment-plans/:id/revisions` | Nova revisão com `parentHash` |
| POST `/api/scans` | Análise estática existente, com contexto opcional `assessment` |
| POST `/api/imports` | Inspeção ZIP/TAR/TAR.GZ, com o mesmo contexto opcional `assessment` |

A criação usa `name`, `projectId`, `mandateId`, `authorizationRequestHash`,
`objective` e `steps`. Cada etapa contém `id`, `name`, `assetId`, `profile` e,
quando aplicável, `address` e `ports`. Revisões posteriores mantêm nome/projeto e
recebem os demais campos mais `parentHash`. Há até 25 etapas e 100 revisões.

O detalhe retorna os 100 resultados mais recentes do plano e indica
`resultsTruncated` quando existem anteriores. A UI e a exportação exibem esse
limite; ausência de uma revisão nesse recorte não comprova falta de execução.
Consulta e exportação paginadas de todo o histórico continuam pendentes.

O contexto de execução é `{planId, revisionId, revisionHash, stepId}`. O frontend
envia a identidade exata da revisão consultada, sem aceitar que o servidor a
substitua silenciosamente pela mais recente. Uma revisão histórica só pode ser
executada enquanto seu próprio mandato continua válido e autoriza aquele ativo.

## Fronteiras de segurança e continuidade

O banco conserva as referências de organização/projeto/autorização e impede
alterações e exclusões do histórico do plano. Os eventos de criação, revisão e
execução alimentam a auditoria existente. Hashes detectam divergências, mas não
constituem proteção absoluta contra um administrador de banco malicioso.

A autorização não é reaberta nem duplicada pelo plano. Revogação, substituição,
expiração e mudança de contexto impedem novas execuções vinculadas. Não se
atribui aprovação retroativa a resultados antigos. A ausência de achados não
atesta segurança integral.

Fila recuperável, retries, execução em lote, pausa, quotas acumuladas e
cancelamento geral de processos continuam pendentes; archive.inspect tem
cancelamento supervisionado opcional descrito abaixo. O plano não agenda
ações de rede nem instala serviços. A análise estática examina somente os
arquivos fornecidos e não executa seu conteúdo.

Validação efetivamente realizada: [VALIDATION_REPORT.md](../VALIDATION_REPORT.md).
Ponto único de retomada: [PROJECT_STATE.md](../PROJECT_STATE.md). O próximo
incremento deve preservar estes vínculos ao ampliar os importadores.

## Inspeção vinculada ao plano — 02/11/2026

O envio carrega a revisão exata, etapa, formato explícito e arquivo. A mesma
transação preserva job, original cifrado e vínculos ao plano. A migração012
conserva mandato/hash no registro de importação, com identidade imutável e FKs
por organização/ativo. Importações anteriores permanecem históricas, sem
atribuição retroativa de autorização ou plano. A migração013 amplia formatos.

A autorização é revalidada na preservação, imediatamente antes de chamar o
worker e antes de aceitar o relatório. Revogação/expiração/substituição detectada
impede despacho ou conclusão. A aprovação não pode ser trocada silenciosamente.
Falhas após a quarentena preservam job/original vinculados; o painel atualiza o
resultado e oferece o registro JSON. Importação avulsa não é anexada a um plano.

O worker externo não participa da transação SQL. O resultado só é aceito após
nova validação. Com supervisor Rust configurado, a API revalida o mesmo mandato/
hash durante a execução e fecha o pipe ao detectar revogação/expiração; o filho
é encerrado antes do recibo cancelled. Sem Rust, revogação não mata processo já
iniciado. Nenhum caminho promete interrupção atômica entre validação/criação.
Recuperação e cancelamento geral continuam pendentes; docs/RUST-ENGINES.md
detalha limites. O job guarda failed/SCOPE_REQUIRED e a auditoria guarda o
recibo cancelled, preservando original e vínculo ao plano.
