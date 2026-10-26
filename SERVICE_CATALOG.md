# Catálogo de serviços apoiados pelo Sentinel

I.See Cybersecurity é a divisão de serviços; Sentinel é a ferramenta interna.
Este catálogo de 26/10/2026 orienta o desenvolvimento e o planejamento de escopo.
Não declara serviços liberados comercialmente nem substituição de ferramentas
profissionais. Nenhuma liberação para clientes é comprovada por este documento.

| Necessidade do cliente | Apoio atual para estudo/validação interna | Entrega possível no recorte | O que falta para ampliar o serviço |
| --- | --- | --- | --- |
| Revisar configuração de aplicação | Baseline SecureBuild e análises offline | Achados com regras, hashes, limitações e relatório JSON | Revisão humana, cobertura ampla, reteste comparável e homologação |
| Revisar contrato de API | Análise estática OpenAPI | Inconsistências e pontos de revisão documentados | Testes autorizados da implementação e lógica de negócios |
| Investigar alerta | Casos, notas, eventos e evidências | Histórico de investigação e relatório estruturado | Procedimentos operacionais e capacidade de resposta no alvo |
| Acompanhar mudança em arquivo | Agente Rust autenticado e baseline aprovada | Observações e alerta de divergência | Implantação/homologação no cliente e supervisão contínua |
| Preparar correção de configuração | SecureFix em cópia SSH | Proposta, patch, hashes, aprovação e recuperação da cópia | Implantação real, acesso de recuperação e validação do serviço |
| Examinar tráfego/export forense | HAR/Nmap XML, PCAP/PCAPNG, SQLite/plist | Metadados, fluxos/timeline e hashes nos formatos suportados | Aquisição, contexto pericial, cobertura especializada e validação da metodologia |
| Inventariar portas de laboratório | Adaptador Nmap opcional e limitado | Saída preservada e análise normalizada | Autorização específica, versão/licença e execução real homologadas |
| Revisar exports de cloud/identidade/IA | Analisadores JSON delimitados | Indícios de configuração e recomendações | Conectores oficiais, semântica completa e validação no ambiente |

Pentest abrangente, Red Team, MDR/SOC contínuo, recuperação de sistemas,
perícia de dispositivos, segurança industrial, GRC/LGPD, continuidade, treinamento
de equipes e vCISO pertencem ao portfólio planejado. Cada serviço exige escopo,
competência operacional, ferramentas/ambiente compatíveis e aprovação de liberação
antes de ser oferecido como capacidade estabelecida.

Para planejar um trabalho: cadastrar organização/projeto/ativos; registrar
responsável, autorização, métodos/limites e ambiente; selecionar somente testes
implementados; preservar evidências; revisar resultados e riscos residuais; definir
correção/reteste e relatório. Não confundir acesso público com consentimento.

Critérios e limites: [autorização](AUTHORIZATION_POLICY.md),
[módulos](MODULE_CATALOG.md), [roadmap](ROADMAP.md),
[segurança de laboratório](LAB_SAFETY.md) e [testes](TESTING.md).
