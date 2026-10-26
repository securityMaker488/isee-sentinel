# Investigação, SecureFix e recuperação de artefatos

Implementado em 24/10/2026. As rotas usam a sessão do fundador, MFA no login,
CSRF e separação por organização já existentes. Nenhuma rota executa comandos
no host, reinicia serviços ou instala persistência.

## Investigação de incidentes

- `GET /api/incidents/:id/case`: estado, últimas 100 notas, evidências vinculadas,
  eventos originais e últimas 100 entradas de auditoria do incidente.
- `POST /api/incidents/:id/notes` com `{ "body": "Observação da investigação" }`:
  acrescenta nota de até 8.000 caracteres. A nota é cifrada com AES-GCM e inclui
  SHA-256; a auditoria guarda somente seu identificador e hash.
- `POST /api/incidents/:id/evidence` com `{ "evidenceId": "UUID" }`: vincula uma
  evidência existente do mesmo ativo e organização, de forma idempotente.
- `POST /api/incidents/:id/status` com `{ "status": "investigating" }`: registra
  a transição e preserva o estado anterior na auditoria.

Transições: `open → investigating/closed`, `investigating → open/resolved`,
`resolved → investigating/closed`, `closed → investigating`. Resolver um caso
não comprova que a ameaça foi eliminada: é uma classificação do operador.
Alterações exigem administrador. Notas e vínculos são imutáveis para o usuário
runtime do banco; uma correção deve ser acrescentada como nova nota.

## SecureFix: cópia de configuração no laboratório

O alvo retornado pela API é sempre `stored_lab_artifact`. Este fluxo altera uma
cópia cifrada armazenada no Sentinel e mantém o original para recuperação.
Não altera `/etc/ssh/sshd_config` nem qualquer outro arquivo do computador.
Não representa um executor de remediação em produção ou um backup completo
do sistema. As operações de alto impacto do PolicyGate continuam bloqueadas.

`POST /api/remediations` recebe `assetId`, `name` e `content`. O ativo deve ser
de laboratório e possuir autorizações vigentes para `scan` e `evidence.import`.
O texto tem limite de 256 KiB. O transformador suporta apenas as diretivas SSH
explícitas `PermitRootLogin` e `PasswordAuthentication`, definindo-as como `no`.
As duas precisam existir sem duplicatas. `Match`, `Include`, sintaxe ambígua,
valores desconhecidos e diretivas ausentes resultam em `manual_review`, sem
alterar o conteúdo. Uma entrada já conforme recebe `no_change`.

Original e proposta são preservados como evidências distintas e cifradas.
`GET /api/remediations` retorna metadados sem conteúdo. O detalhe
`GET /api/remediations/:id` retorna original, proposta, patch unificado e
histórico de hashes somente para analista ou administrador; essa leitura
também é auditada. A interface deve exibir a limitação retornada pela API.

| Ação POST | Estado anterior | Resultado |
| --- | --- | --- |
| `/:id/approve` | `proposed` | `approved`, aprovação explícita registrada |
| `/:id/apply` | `approved` | `applied`, nova revisão da cópia cifrada |
| `/:id/verify` | `applied` | `verified`, hash conferido e dois controles SSH estáticos aprovados |
| `/:id/rollback` | `applied` ou `verified` | `rolled_back`, nova revisão com os bytes originais |

O prefixo da tabela é `/api/remediations`. Cada transição exige administrador,
ativo de laboratório e as duas autorizações ainda vigentes. Estados repetidos
ou fora de ordem são rejeitados com HTTP 409. As linhas do banco são bloqueadas
durante a transação, impedindo transições concorrentes sobre o mesmo plano.
O banco mantém histórico cifrado imutável: importação, aplicação e recuperação.
Uma nova tentativa depois de rollback deve gerar um novo plano.

A verificação comprova os dois controles no texto armazenado, sem executar
`sshd -t` e sem presumir acesso alternativo por chave. Outros achados do scanner
são retornados em `remainingFindings`; o estado `verified` não declara ausência
de vulnerabilidades. Aprovar configurações SSH para um host real exigirá futura
validação no Debian, acesso de recuperação e um executor dedicado com política.

## Evidência de desenvolvimento

Os testes automatizados `apps/api/test/operations.test.ts` exercitam autenticação,
CSRF, papéis, separação por organização, escopos revogados, recusa de produção,
recusa de configurações ambíguas, ordem das etapas, aplicação da cópia,
verificação, recuperação por hash, notas cifradas e histórico imutável.
A homologação no Debian e os testes operacionais ficam pendentes.

A migração `004_operations.sql` adiciona as tabelas de notas, vínculos, planos
e revisões. Aplicar com a identidade de migração e conceder somente as permissões
runtime descritas em `ops/runtime-grants.sql`; o servidor não executa migrações
automaticamente.
