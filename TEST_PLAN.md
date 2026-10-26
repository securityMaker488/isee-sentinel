# Plano de validação V6.9

Histórico executado: docs/VALIDATION.md. Resultado desta alteração: VALIDATION_REPORT.md.

| Área | Casos obrigatórios | Evidência |
|---|---|---|
| Agente | HMAC adulterado, nonce repetido, retry idempotente, ativo errado, escopo/credencial revogados, baseline e mudança | apps/api/test/agents.test.ts; scripts/verify-agent.ts com binário Rust real |
| Análises | positivo/negativo, esquema inválido, limites, redação, XML hostil, bytes truncados, isolamento | packages/core/test e testes API |
| Casos | notas cifradas, evidência do mesmo ativo, isolamento, transição inválida e relatório | apps/api/test/operations.test.ts e agents.test.ts |
| Correção | original intacto, Match/Include/duplicação ambíguos, aprovação, aplicação, verificação, rollback | operations.test.ts |
| Laboratório | alvo único, IPv4 permitido, escopo, argumentos fixos, tempo/tamanho, ausência da ferramenta | lab.test.ts com runner substituto; nenhuma varredura real nesta sessão |
| Interface | fluxo real de sessão, cadastro, análise, correção, relatório, troca de empresa, tela estreita, console | QA browser com banco sintético |
| Banco | migração repetível, runtime restrito, integridade e restore completo | PostgreSQL dedicado; sem tocar serviço preexistente |
| Debian | instalação, permissões de arquivo, systemd, TLS, recursos, integração real | Pendente em máquina Debian autorizada |

Não confundir teste injetado de adaptador com execução do Nmap instalado. Performance sustentada, fuzzing ampliado, recuperação de falha elétrica e revisão independente seguem pendentes. Testes de desenvolvimento essenciais corrigem regressões; a homologação operacional fica para depois, como solicitado.
