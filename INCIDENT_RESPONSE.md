# Investigação e resposta

Fluxo disponível em desenvolvimento: evento aceito → regra → alerta/incidente → triagem → notas → vínculo de evidência do mesmo ativo → relatório JSON. Eventos sintéticos permanecem identificados. Referência de integridade é aprovada separadamente; divergência não prova malware.

Estados do caso: aberto, em investigação, resolvido e fechado. Transições inválidas são rejeitadas. Resolver um caso registra a decisão; não comprova que o host foi recuperado.

Autonomia V6.6: nível 0 observa; nível 1 recomenda; nível 2 exige política pré-autorizada e reversibilidade; nível 3 exige aprovação específica. Executor de ação crítica continua bloqueado. SecureFix atua somente em artefato armazenado e não é contenção do endpoint.

A investigação deve registrar hipótese, evidência, impacto, decisão, responsável, horário e reteste. O relatório declara ausência de reteste quando não há resultado registrado. Não preencher conclusão causal automaticamente. Consulte docs/OPERACOES-DEFESA.md para APIs e limites.
