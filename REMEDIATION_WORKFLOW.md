# Correção e recuperação de cópias de laboratório

O fluxo atual SecureFix opera sobre `stored_lab_artifact`: uma cópia cifrada de
configuração SSH dentro do banco. Nenhuma etapa modifica o host, instala pacote,
reinicia SSH ou altera produção. A expansão V6.9 para código, Git, dependências,
infraestrutura e comparação entre versões continua pendente.

## Usar o fluxo disponível

1. Cadastrar ativo `lab` e autorizações vigentes `scan` e `evidence.import`.
2. Em **Investigar e corrigir → SecureFix**, enviar o texto SSH e um nome de artefato.
3. Revisar original, proposta, patch e hashes. `PermitRootLogin` e
   `PasswordAuthentication` precisam estar explícitos, com valores reconhecidos.
4. Confirmar a revisão e aprovar a proposta. Original e proposta permanecem
   evidências cifradas distintas, imutáveis para a identidade runtime.
5. Aplicar à cópia: uma nova revisão cifrada é criada. Verificar confere seu hash
   e os dois controles SSH estáticos.
6. Restaurar a cópia original se necessário: nova revisão preserva os bytes e
   hash originais. O histórico anterior permanece disponível.

Conteúdo máximo: 256 KiB. `Match`, `Include`, diretivas alvo repetidas/ausentes,
valores desconhecidos ou sintaxe ambígua exigem `manual_review`, sem alteração
automática. Configuração já conforme recebe `no_change`.

| Estado | Próxima ação permitida |
| --- | --- |
| `proposed` | Aprovar |
| `approved` | Aplicar à cópia |
| `applied` | Verificar ou restaurar original |
| `verified` | Restaurar original |
| `rolled_back` | Criar novo plano para outra tentativa |
| `manual_review` / `no_change` | Sem aplicação automática por este plano |

Cada mutação exige administrador e relê os escopos. Transições fora de ordem
falham; operações sobre o mesmo plano são serializadas no banco. Conteúdo completo
do plano exige analista/administrador; a leitura também é auditada.

## Significado do resultado

`verified` significa somente que o texto armazenado passou nos dois controles
SSH e na verificação de hash. Não executa `sshd -t`, não comprova que o serviço usa
esse arquivo, não valida acesso alternativo e não declara ausência de outros
achados. A API retorna achados remanescentes da verificação estática quando houver.

Rollback de cópia não substitui backup/restauração do sistema. Reteste profissional
exige cenário comparável e confirmação da falha corrigida; desaparecer de um
scanner não basta. Produção requer futura integração específica com revisão,
backup, testes, aprovação e recuperação comprovada.

API, tabelas e testes: [operações de defesa](docs/OPERACOES-DEFESA.md).
Política: [AUTHORIZATION_POLICY.md](AUTHORIZATION_POLICY.md).
Recuperação de instância: [BACKUP_RECOVERY.md](BACKUP_RECOVERY.md).
