# Autorização, contexto e limites de execução

O Sentinel começa com um único fundador humano. Clientes são organizações,
projetos e ativos, sem conta pública ou acesso próprio ao painel. Papel de usuário
e identidade de serviço são distintos. As verificações residem no servidor, não
apenas em botões ocultos. Referência: [segurança](SECURITY.md).

## Contexto autenticado

Login exige senha e TOTP; sessão usa cookie protegido e tempo de validade.
Mutações da API humana exigem origem esperada e token CSRF. O servidor obtém
organização/operador da sessão; corpo de requisição não concede permissão.
A troca de empresa verifica vínculo do fundador e renova CSRF. Um UUID conhecido
não concede acesso a registros de outra organização.

Ativos declaram `lab`, `staging` ou `production`. Projeto pode estar associado ao
ativo. Essa associação não equivale ainda a uma avaliação formal completa da V6.9.
O escopo corrente registra ativo, ambiente, operações, referência, início/fim e
revogação. Referência textual é declaração do operador; o aplicativo não confirma
automaticamente a autoridade de quem assinou um contrato.

## Regras por operação

| Operação | Requisito implementado |
| --- | --- |
| Ler metadados, casos, resultados e grafo | Sessão válida e mesma organização; campos sensíveis possuem restrições específicas |
| Criar organização/projeto/ativo e autorizações | Administrador |
| Executar análise estática | Administrador/analista e autorização `scan` vigente para o ativo/ambiente |
| Importar evidência | Administrador/analista e `evidence.import` vigente |
| Análises especializadas, perícia e ZIP | Autorizações `scan` e `evidence.import` vigentes; limites próprios de entrada/worker |
| Ingerir eventos pela API humana | `event.ingest` vigente; evento sintético exige ativo `lab` |
| Criar/revogar identidade do agente | Administrador; criação exige `event.ingest` para o ativo |
| Receber observação do agente | HMAC válido, identidade/ativo corretos, validade/revogação/escopo, timestamp, nonce e deduplicação |
| Aprovar baseline de integridade | Administrador; observação do contexto autorizado, sem aprovação automática da primeira coleta |
| Acrescentar nota, vincular evidência ou alterar estado do caso | Administrador; vínculo de evidência exige também o mesmo ativo |
| Criar/aprovar/aplicar/verificar/restaurar plano SecureFix | Administrador, ativo `lab` e ambos os escopos vigentes em cada transição; alvo é cópia armazenada |
| Baixar conteúdo de evidência / ler configuração de plano | Administrador/analista; leitura auditada, respeitando organização |
| Executar adaptador Nmap | Ativo de laboratório, alvo cadastrado e autorização válida; limites fixos de endereço/portas/tempo |
| Resposta crítica, remediação ou recuperação do host | Executor crítico indisponível; não permitido pela política atual |

Os papéis `admin`, `analyst` e `viewer` existem no modelo e nos testes. Isso não
significa que administração multiusuário ou equipes esteja entregue na edição
privada. A CLI administrativa local exige acesso ao banco/chave e não é uma
API pública de redefinição de senha.

## Consentimento e mudança de escopo

Antes de cadastrar autorização, confirmar responsável, empresa, ativos, métodos,
limites, período e ambiente. Disponibilidade pública ou endereço privado não
comprovam consentimento. Mudança significativa de alvo, risco ou ambiente exige
nova revisão/aprovação. A expansão V6.9 do Authorization Manager — documentos de
autoridade, aprovações por projeto e catálogo formal de testes — permanece parcial.

Revogação impede novas operações autorizadas pelo escopo. Não presumir que ela
interrompa instantaneamente todo subprocesso já iniciado; o adaptador Nmap tem
limite de tempo, mas não implementa esse cancelamento imediato. Consultar o
contrato de cada executor e preservar histórico de tentativas/erros.

LAB, ASSESSMENT e PRODUCTION REMEDIATION são modos previstos pela V6.9. O
controle implementado combina ambiente do ativo, operações e limites de módulos;
não existe um seletor global que autorize qualquer ação em produção.

Procedimentos: [laboratório](LAB_SAFETY.md), [AttackLab](docs/ATTACKLAB.md),
[remediação](REMEDIATION_WORKFLOW.md), [importação](IMPORT_PIPELINE.md).
