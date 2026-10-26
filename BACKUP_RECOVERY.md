# Backup e recuperação

Procedimento nativo e separação de papéis: docs/OPERACAO.md. Pare gravações antes de comparar backup e restore; use banco novo dedicado, nunca sobrescreva o original. Preserve chave mestra e configuração por canal protegido separado.

A ferramenta `npm run verify:restore` compara agora todas as tabelas públicas e o conjunto de tabelas, incluindo novos agentes, observações, casos, análises, correções e migrações. Também verifica as cadeias de auditoria. Requer URLs explícitas de bancos isolados. Não executa restauração nem altera dados.

Uma restauração antiga também restaura credenciais, sessões e revogações antigas. Antes de permitir acesso operacional, invalide sessões, revogue/renove credenciais de agente e confira escopos e relógio por procedimento controlado. A ferramenta de comparação não executa isso automaticamente.

O restore nativo anterior comparou 14 tabelas da versão anterior. Esse resultado não valida automaticamente as novas tabelas. Novo teste nativo completo e homologação Debian precisam ser registrados no VALIDATION_REPORT.md.

Rollback de SecureFix restaura somente a versão original do artefato cifrado, verificando hash. Não equivale a backup/restore do sistema, recuperação de disco ou reinício de serviço.
