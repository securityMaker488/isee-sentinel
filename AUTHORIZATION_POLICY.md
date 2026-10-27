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

Ativos declaram `lab`, `staging` ou `production`. O fluxo legado registra ativo,
ambiente, operações, referência, início/fim e revogação. O Authorization Manager
exige também projeto, responsável, finalidade, comprovação de autoridade, perfis
e limites revisados. O aplicativo preserva a declaração e sua evidência; não
confirma automaticamente a autoridade de quem assinou um contrato.

## Authorization Manager

A tela **Autorizações** implementa o ciclo `draft` → `approved` → `revoked`.
Um rascunho também pode ser revogado antes da aprovação. Administradores criam,
aprovam e revogam; administradores/analistas podem consultar os detalhes privados.
O papel `viewer` recebe apenas metadados. Identidade, organização e CSRF são
verificados em todas as mutações.

1. Selecionar um projeto e de um a dez ativos já vinculados a ele na mesma
   organização. Informar responsável, função, empresa, finalidade, canal/referência
   de autoridade e arquivo comprobatório de até 1 MiB. Dados privados e arquivo
   ficam cifrados; hashes permitem verificar sua integridade.
2. Selecionar explicitamente os perfis, modo `lab` ou `assessment`, risco `low`
   ou `moderate`, período e limites. O término deve estar no futuro e em até 31
   dias; a janela não pode exceder 31 dias. O rascunho não libera execução nem
   altera escopos existentes.
3. Abrir e revisar o registro, sua comprovação, ativos e limites. A aprovação
   envia o `requestHash` revisado e a declaração explícita `attested: true`.
   O servidor confere novamente os hashes, bytes preservados, vínculo de projeto,
   ambiente e validade antes de aprovar. Conteúdo inconsistente é rejeitado.
4. A aprovação revoga **todos os escopos anteriores dos ativos selecionados**,
   inclusive escopos de outras autorizações gerenciadas. Cria novos escopos
   vinculados ao registro e muda esses ativos para `authorization_mode=managed`.
   A operação ocorre em uma transação e registra o que foi substituído.
5. A revogação exige motivo, preserva o histórico e revoga os escopos desse
   registro. O motivo fica cifrado; a trilha de auditoria registra seu hash.

Os termos do rascunho são imutáveis no banco. Mudanças de responsável, projeto,
ativos, ambiente, modo, risco, perfis ou limites exigem um novo rascunho e nova
aprovação; criar esse novo rascunho não substitui a autorização vigente. Aprovar
uma autorização com início futuro substitui os escopos anteriores imediatamente,
mas só permite executar a partir do início declarado.

Ativos existentes permanecem no fluxo legado até a primeira aprovação gerenciada.
Depois disso, o modo gerenciado permanece mesmo após expiração ou revogação:
a API não oferece retorno ao legado, criação de escopo legado é negada e uma
linha antiga restaurada não serve como alternativa de autorização. O projeto
atual do ativo também precisa corresponder ao projeto aprovado. Um registro
antigo pode continuar com estado `approved` enquanto seus escopos já foram
substituídos; o detalhe informa a revogação por ativo e a execução depende dos
escopos ainda vigentes.

## Perfis e limites aplicados

### Manifesto revisado de alvos

O perfil `lab.inventory` exige `targetManifest` versão1, com `targets`
(`assetId`, IPv4 literal `address`, `ports`) e `exclusions` (`address`). Até100
alvos e100 exclusões; de1 a16 portas únicas por alvo, contidas em `allowedPorts`.
Somente IPv4 privado RFC1918 ou loopback, sem DNS, CIDR, URL ou resolução implícita.
Cada ativo selecionado para inventário precisa constar do manifesto. Exclusões
bloqueiam o endereço em todos os ativos do pedido, inclusive quando ele consta
explicitamente dos alvos. A tela Autorizações mostra os termos antes da aprovação.

Manifesto normalizado integra `requestHash` esquema2 e fica imutável na migração010.
Pedidos sem manifesto preservam hash esquema1. Registros antigos continuam legíveis,
mas escopos legados e aprovações antigas sem manifesto não permitem cadastrar ou
executar alvos de rede. É necessário criar e revisar novo pedido; não há consentimento
retroativo. Os demais perfis conservam sua política existente.

Cadastro e despacho conferem par ativo/endereço, portas reais, exclusões, projeto,
empresa, revisão e vigência. Após adquirir o job, revalidam a mesma autorização
antes de despachar; substituição/revogação nesse intervalo impede o processo.
O histórico do scan preserva `mandateId` e `authorizationRequestHash`, com vínculos
no banco à organização/ativo/mandato e proteção contra alterações. Scans históricos
podem ter esses campos nulos. Isso não conclui o plano geral de avaliação nem a
orquestração/cancelamento de processos já iniciados.

Para ativos gerenciados, o servidor exige simultaneamente a operação básica
autorizada e o perfil específico do executor. Permitir `scan` em um analisador
não libera outros executores que compartilhem essa operação. O perfil é definido
pelo código do executor; não é uma opção arbitrária enviada pelo cliente.

| Perfil implementado | Operações básicas | Entrada e teto próprio |
| --- | --- | --- |
| `static.scan` | `scan` | Soma dos bytes UTF-8 dos arquivos; 1 MiB |
| `artifact.analyze` | `scan`, `evidence.import` | Conteúdo UTF-8; 1 MiB |
| `archive.inspect` | `scan`, `evidence.import` | ZIP decodificado; 16 MiB, worker de até 45 s |
| `forensic.analyze` | `scan`, `evidence.import` | Arquivo decodificado; 16 MiB, worker de até 60 s |
| `evidence.import` | `evidence.import` | Conteúdo decodificado; 1 MiB |
| `events.ingest` | `event.ingest` | Objeto do evento serializado; 1 MiB |
| `agent.observe` | `event.ingest` | Bytes exatos da mensagem assinada; 16 KiB |
| `lab.inventory` | `scan` | De uma a 16 portas TCP explicitamente aprovadas; até 40 s |
| `lab.remediate` | `scan`, `evidence.import` | Cópia SSH em UTF-8; 256 KiB |

O limite aprovado `maxInputBytes`, entre 1 byte e 16 MiB, reduz o teto do executor:
vale o menor dos dois. É um limite por entrada, não uma cota acumulada. No agente,
ele mede a mensagem recebida; o limite próprio de leitura do arquivo continua
separado. SecureFix revalida original, revisão corrente e conteúdo a aplicar ou
restaurar conforme a etapa. A preparação de cadastro de alvo/agente valida o
perfil; a execução posterior confere novamente autorização e entrada real.

Inventário exige `allowedPorts` e risco `moderate`; cada execução deve usar somente
portas desse conjunto. Os demais perfis aceitam risco `low`. Os dois perfis `lab.*`
exigem modo `lab` e ativo de laboratório. O modo `lab` exige ambiente `lab` em
todos os ativos; `assessment` permite os perfis sem restrição exclusiva de
laboratório, respeitando as demais regras do executor.

Timeouts e concorrência continuam fixos por executor; não são limites livremente
configuráveis do contrato. O catálogo contém somente os executores implementados
e rejeita perfis/campos não suportados. Não há perfil de remediação do host ou
seletor global que libere operações críticas em produção.

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
| Aprovar baseline de integridade | Administrador; observação do contexto autorizado e agente ativo; ativo gerenciado também exige perfil `agent.observe` vigente, sem aprovação automática da primeira coleta |
| Acrescentar nota, vincular evidência ou alterar estado do caso | Administrador; vínculo de evidência exige também o mesmo ativo |
| Criar/aprovar/aplicar/verificar/restaurar plano SecureFix | Administrador, ativo `lab` e ambos os escopos vigentes em cada transição; alvo é cópia armazenada |
| Baixar conteúdo de evidência / ler configuração de plano | Administrador/analista; leitura auditada, respeitando organização |
| Executar adaptador Nmap | Ativo lab, alvo cadastrado, mandato e manifesto aprovados para endereço/portas, exclusões respeitadas, vigência cobrindo40s |
| Resposta crítica, remediação ou recuperação do host | Executor crítico indisponível; não permitido pela política atual |

Os papéis `admin`, `analyst` e `viewer` existem no modelo e nos testes. Isso não
significa que administração multiusuário ou equipes esteja entregue na edição
privada. A CLI administrativa local exige acesso ao banco/chave e não é uma
API pública de redefinição de senha.

Todas as operações de execução acima também exigem o perfil e limites
correspondentes quando o ativo está em modo gerenciado. A lista não concede
execução a partir de acesso de leitura.

## Consentimento e revogação

Antes de cadastrar autorização, confirmar responsável, empresa, ativos, métodos,
limites, período e ambiente. Disponibilidade pública ou endereço privado não
comprovam consentimento. Mudança significativa de alvo, risco ou ambiente exige
nova revisão/aprovação. O recorte entregue cobre autoridade documentada, projeto,
perfis implementados e limites. Plano completo de avaliação, catálogo amplo de
testes e orquestração geral de jobs permanecem pendentes na V6.9.

Revogação impede novas operações autorizadas pelo escopo. Não presumir que ela
interrompa instantaneamente um subprocesso já iniciado. Nmap, ZIP e perícia
revalidam antes de iniciar o processo e mantêm seus timeouts fixos; esse fluxo
não implementa cancelamento imediato de um processo em andamento. Consultar o
contrato de cada executor e preservar histórico de tentativas/erros. O modo
PRODUCTION REMEDIATION previsto na V6.9 continua indisponível.

Procedimentos: [laboratório](LAB_SAFETY.md), [AttackLab](docs/ATTACKLAB.md),
[remediação](REMEDIATION_WORKFLOW.md), [importação](IMPORT_PIPELINE.md).
