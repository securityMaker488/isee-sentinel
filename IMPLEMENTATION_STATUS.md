# Estado de implementação e critérios de leitura

Referência de 26/10/2026. O ponto exato de execução está em
[PROJECT_STATE.md](PROJECT_STATE.md); resultados finais pertencem a
`VALIDATION_REPORT.md`. Este índice evita transformar uma lista de módulos em
declaração de prontidão. A plataforma completa ainda não está concluída.

| Área | Estado do recorte | Próximo critério de avanço |
| --- | --- | --- |
| Fundação e evidências | Authorization Manager por projeto, prova cifrada, aprovação, perfis/limites, migração009 e restore validados no Windows | Plano de avaliação, catálogo amplo e homologação operacional |
| Agente de integridade | Transporte autenticado e FIM conectados | Validar no Debian e ampliar telemetria; não classificar como EDR/XDR completo |
| SOC/casos/SecureFix | Fluxos conectados; correção restrita a cópia de laboratório | Consolidar E2E e restore; resposta real do host continua indisponível |
| Análises/OpenAPI | Análises offline e auditoria estática de contrato implementadas | Cobertura adicional, comparabilidade de reteste e verificação de falsos positivos |
| RiskGraph | API e tela conectadas; consulta de relações persistidas | Consolidar navegação/E2E e ampliar fontes com semântica explicitamente definida |
| Perícia Python/API | Análise delimitada de exports e testes de integração disponíveis | Consolidar UI/restore; aquisição de dispositivos e imagens permanece ausente |
| Universal Import Lab | ZIP/quarentena implementados, testes dirigidos incluindo Python real; experimental | Consolidar UI e recuperação; sem extração, execução ou homologação de clientes |
| AttackLab/Nmap | Adaptador limitado implementado; testes de contrato usam substituto | Instalação/versionamento/licenciamento e execução autorizada reais |
| Windows/Debian | Desenvolvimento Windows, setup/doctor e CI preparados | CI efetivamente executada e homologação Debian; preservar Windows |
| ProofLab/Enterprise | Requisitos e ordem de implementação definidos | Fluxo demonstrável completo, isolamento/recuperação, revisão independente e liberação |

Não há conversão automática entre M0–M6 históricos, estados do §45 da V6.9 e
classificações de liberação do §53.13. “Testado” se refere ao recorte, ambiente e
cenário documentados. Passar uma análise de configuração não valida o host nem
autoriza prestar todos os serviços do catálogo.

Antes de promover um recurso, registrar: implementação e interfaces conectadas,
entradas/permissões verificadas, falhas/limites definidos, testes relevantes,
limitações e evidências vinculadas à versão. Qualquer conflito com a matriz deve
ser resolvido pelos registros reais, sem apagar o histórico.

Documentos complementares: [catálogo](MODULE_CATALOG.md),
[serviços](SERVICE_CATALOG.md), [roadmap](ROADMAP.md),
[testes](TESTING.md) e [precedência dos prompts](docs/PROMPTS-REGISTRY.md).
