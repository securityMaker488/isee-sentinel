# AttackLab Evidence Fusion — auditoria dirigida e plano incremental

Registro de 26/10/2026. Complemento ao guia V6.9 e ao preparo multiplataforma;
não substitui a ordem geral de [ROADMAP.md](../ROADMAP.md). O pedido mais recente
determina começar pela auditoria e pelo plano. Este documento registra essa
entrega; não declara implementados os módulos propostos abaixo.

A inspeção partiu de [PROJECT_STATE.md](../PROJECT_STATE.md), das interfaces
afetadas e das migrações existentes, sem reiniciar a revisão integral do projeto.
Não foram executadas ferramentas externas ou novas suítes nesta auditoria.
Os testes anteriores estão em [VALIDATION_REPORT.md](../VALIDATION_REPORT.md).

## Base existente e lacuna prioritária

O Authorization Manager já preserva responsável, comprovação cifrada, projeto,
ativos, vigência, modo/risco, perfis e limites. A aprovação explícita verifica o
hash revisado, substitui os escopos anteriores e impede retorno ao fluxo legado.
São componentes reais em [authorization-manager.ts](../apps/api/src/authorization-manager.ts),
[policy.ts](../apps/api/src/policy.ts), [authorization.ts](../packages/core/src/authorization.ts)
e [migração 009](../apps/api/migrations/009_assessment_authorizations.sql).

O [adaptador Nmap](../apps/api/src/lab.ts) aceita um IPv4 privado ou loopback
literal cadastrado, até 16 portas TCP, duração máxima de 40 s e uma execução por
instância/banco mediante trava. Usa argumentos estruturados e `shell:false`;
preserva XML cifrado, job e auditoria. A configuração do caminho não comprova
presença, versão, licença ou funcionamento do binário. Nmap real ainda não foi
homologado. A [migração 006](../apps/api/migrations/006_lab.sql) torna o cadastro
de alvo imutável.

**Lacuna prioritária do novo requisito:** o mandato aprovado vincula ativo,
perfil e portas, mas não incorpora o endereço exato do alvo nem exclusões no
`requestHash`. O administrador pode cadastrar outro IPv4 privado/loopback para
o mesmo ativo após a aprovação. A imutabilidade desse cadastro não demonstra
que o endereço constava do consentimento revisado. Antes de ampliar os executores
ativos, o endereço precisa constar de um manifesto aprovado e ser revalidado
antes de cada despacho. Endereço privado não é prova de autorização ou isolamento.

O [parser Nmap](../packages/core/src/artifact-network.ts) fornece contagens e
achados informativos por índice de host. Ainda não produz um inventário
estruturado suficiente de endereço/serviço para comparação confiável entre
avaliações. Porta aberta já é apresentada como observação, não como exploração.

## Fases do complemento

| Fase | Estado real e fontes reutilizáveis | Lacuna e próximo resultado | Critério de aceite |
|---|---|---|---|
| 1 — Auditoria do repositório | Auditoria dirigida registrada neste documento; checkpoint, política, AttackLab, grafo, eventos, relatórios e migrações inspecionados | Manter rastreabilidade do complemento e decisões junto do roadmap | Separar código existente, teste registrado e proposta; nenhuma capacidade inferida apenas de tela ou catálogo |
| 2 — Núcleo seguro | Authorization Manager/API/UI, MFA/CSRF, SQL parametrizado, evidências e auditoria; migrações 001–009 | Operação com manifesto revisado de alvos/exclusões, vínculo ao mandato, cancelamento e limites de execução efetivamente aplicáveis | Endereço divergente/excluído, mandato revogado/expirado, alteração de projeto e parâmetros não aprovados bloqueados antes do executor; transições e concorrência testadas |
| 3 — Adaptadores | Nmap limitado; importação passiva NmapXML/HAR/SARIF e análise offline | Inventário de adaptadores com estados reais; primeiro importador offline de Gobuster; demais integrações separadas | Original preservado e hash, parser limitado, alvo validado, versão/proveniência declaradas; nenhuma chamada de rede ou shell na importação; execução Nmap real homologada separadamente |
| 4 — Evidence Fusion | UUIDs, hashes, evidências cifradas, auditoria, relatórios e RiskGraph persistido | Relação operação→teste→observação→evidência→alerta→achado→correção→reteste, timeline e comparação | Vínculos verificáveis na mesma organização/ativo/operação, original e transformações rastreáveis, comparação com entradas compatíveis, truncamento/paginação explícitos |
| 5 — Blue/Purple Validation | Eventos restritos, deduplicação por ID externo, correlação de falhas de autenticação, FIM e classificação de falso positivo | Importação delimitada Suricata/Sigma, catálogo de metadados Atomic/MITRE, requisitos/riscos e resultados manuais | Regra, versão, fonte e evidência vinculadas; atividade esperada comparada a alertas observados; métricas com denominador conhecido; comandos de cenários não executados por importar metadados |
| 6 — Segurança e validação | Suítes de política/API, PostgreSQL restrito, navegador e restore disponíveis | Casos próprios de alvos/exclusões, cancelamento, limites, integridade, comparação, desempenho e isolamento | Positivos/negativos e falhas reproduzíveis; operação offline comprovada no recorte; homologação Linux/Kali e limites medidos registrados separadamente |

As fases 2–6 estão parcialmente cobertas por componentes reutilizáveis, mas o
novo módulo completo ainda não existe. RustScan, Gobuster executável, Katana,
OpenVPN, Netcat, Suricata, Sigma, YARA, Auditd, Lynis, LinPEAS e Atomic Red Team
não têm integrações operacionais entregues por este incremento.

## Decisões arquiteturais

1. **Reutilizar a autorização existente.** Criar uma operação/avaliação que
   referencie o mandato aprovado, sua revisão e a empresa/projeto. Não criar um
   segundo fluxo paralelo de consentimento. Acrescentar manifesto imutável de
   alvos e exclusões, com revisão explícita e hash. Mudança de alvo, risco ou
   limites exige nova versão aprovada. Exclusão prevalece sobre inclusão.
2. **Persistir vínculos verificáveis.** Usar novas migrações 010 ou posteriores,
   conforme a próxima versão disponível; nunca editar 001–009 já aplicadas.
   Preferir chaves estrangeiras compostas por organização e vínculos tipados a
   uma tabela genérica de IDs sem integridade referencial. Reutilizar `jobs`,
   `evidence`, `artifact_analyses`, `alerts`, `remediation_plans` e revisões.
3. **Não atribuir consentimento retroativo.** Resultados históricos sem operação
   permanecem identificados como tais. Associação manual posterior deve ser
   auditada e não afirmar que o mandato existia no momento da coleta. Separar
   horário declarado pelo arquivo, horário de recebimento e execução comprovada.
4. **Aplicar apenas limites implementados.** Os atuais bytes/portas, timeout e
   trava não equivalem a cotas de taxa, CPU, RAM ou disco. Cada campo novo deve
   ter aplicação e teste no executor. Revogação de permissão e interrupção de
   processo são estados distintos; cancelamento emergencial exige supervisão
   real e recuperação consistente de job/trava.
5. **Normalizar observações antes de inferir achados.** Um resultado precisa
   registrar fonte, ferramenta/versão declarada ou verificada, parâmetros,
   parser/versão, horário, alvo, evidência e localização no original. Comparações
   devem usar identidade estável do alvo/serviço, não índice de host ou ordem de
   linhas. Ausência em uma entrada parcial não prova correção.
6. **Estender o grafo existente.** [graph.ts](../apps/api/src/graph.ts) já relaciona
   empresa/projeto/ativo, análise, evidência, achado, incidente, alerta e correção.
   Acrescentar mandato, alvo, execução, observação e reteste sem inferir caminhos
   exploráveis. Preservar limites de 200 nós e 500 arestas e aviso de truncamento; criar
   consultas por operação para não misturar avaliações. A timeline deve usar os
   mesmos registros de origem e tipos de relação.

## Primeiro incremento proposto

O próximo trabalho específico deste complemento é o contrato e a persistência
da operação com manifesto de alvos revisado, seguidos da aplicação dessa relação
ao cadastro/despacho do Nmap existente. Começar pelo único IPv4 literal e portas
já suportados evita anunciar suporte prematuro a domínios, CIDRs ou aplicações.
Qualquer expansão deve definir normalização, resolução e limites próprios.

Depois desse núcleo, implementar importação **offline** de resultados Gobuster:

- Escolher e documentar um formato e modos suportados; não presumir que todas as
  versões e saídas da ferramenta sejam equivalentes.
- Preservar os bytes originais cifrados com SHA-256, limites de tamanho/linhas e
  vínculo à operação/ativo. Rejeitar estrutura malformada e alvo fora do manifesto.
- Produzir observações de descoberta, com referência à linha/registro original.
  Não visitar URLs, resolver DNS, seguir redirecionamentos ou executar comandos.
- Minimizar segredos em prévias e relatórios, mantendo originais sob acesso
  restrito. Versionar o parser e registrar dados de ferramenta não verificados
  como declarações de origem.
- Testar entradas válidas, inválidas, excessivas, duplicadas, sensíveis e de
  outra organização, além de provar ausência de despacho de processo/rede.

Esse incremento é uma proposta concreta, não um importador já disponível.

## Semântica de evidência e validação Purple

| Classificação | Significado exigido |
|---|---|
| Configuração/serviço observado | Registro fornecido ou coletado em um instante; não comprova exploração |
| Risco potencial | Interpretação fundamentada, com regra, confiança, contexto e limitações |
| Vulnerabilidade confirmada | Evidência e método de confirmação explícitos em escopo autorizado; nunca promoção automática por nome de serviço |
| Correção recomendada | Ação proposta e seu motivo; não significa mudança aplicada |
| Reteste realizado | Execução identificada, vinculada à avaliação anterior, método/entradas comparáveis e resultado observado |

O [esquema atual de eventos](../packages/core/src/events.ts) cobre uma lista curta
de tipos, e a correlação da API trata falhas de autenticação e integridade de
arquivo. Não é um motor genérico Suricata/Sigma. As integrações devem acrescentar
esquemas e regras versionados, deduplicação e rastreio de evidência sem apagar os
originais. Mapeamento MITRE exige justificativa técnica e versão da referência.

O início de Purple Validation deve importar apenas metadados de cenários,
requisitos/riscos e expectativas; associar regras e registrar resultados de
execuções manuais autorizadas. Importar uma definição Atomic não autoriza nem
executa seu conteúdo. Cobertura deve indicar quais cenários/técnicas foram
realmente testados e quais alertas eram esperados; não apresentar um percentual
de proteção global ou de cobertura de todo MITRE a partir desse recorte.

## Windows, Debian e ordem geral

Contratos, migrações, parsers offline, APIs, interface, grafos, relatórios e testes
de política podem avançar no Windows. Eles não devem ser adiados apenas pela
ausência do Debian. Este plano se encaixa nas fases 1/4/6/7/8 da V6.9 e não remove
a fila de Universal Import Lab, ProofLab e retestes do roadmap principal.

Serviço Linux, auditoria de permissões/SUID/SGID, Auditd/Suricata reais,
QEMU/KVM/Kali, snapshots e isolamento de rede exigem validação no ambiente de
destino. Rede libvirt sem saída para internet pode continuar alcançando o host;
é necessário demonstrar a separação dos serviços do Debian principal. Cenários
ativos adicionais só devem ser habilitados após os controles correspondentes.

Não instalar serviços pesados permanentes na Kali de 4 GB, alterar Windows,
partições, bootloader ou firmware como parte deste plano. O preparo do repositório
privado e uma CI Ubuntu não constituem homologação Debian ou do laboratório.
