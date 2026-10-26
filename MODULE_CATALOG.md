# Catálogo dos módulos implementados e planejados

Atualizado em 26/10/2026 para a especificação V6.9. O catálogo descreve entradas,
saídas e limites de componentes reais. Não significa liberação comercial.
Estado de retomada: [PROJECT_STATE.md](PROJECT_STATE.md). Cobertura estratégica:
[matriz do portfólio](PORTFOLIO_CAPABILITY_MATRIX.md). Sequência: [ROADMAP.md](ROADMAP.md).

| Componente | Entrada → comportamento disponível | Limite principal / referência |
| --- | --- | --- |
| Command Center e fundação | Fundador com MFA → organizações, projetos, ativos, escopos e auditoria | Operador único, sem cadastro público ou portal de clientes; [autorização](AUTHORIZATION_POLICY.md) |
| EvidenceChain | Artefato autorizado → original cifrado, SHA-256, metadados, acesso auditado | Hash não comprova origem ou veracidade; chave e banco precisam de custódia; [recuperação](BACKUP_RECOVERY.md) |
| Universal Import Lab | ZIP autorizado → preservação, job e inspeção em quarentena | Experimental, com testes dirigidos; sem extração, execução, URL/Git ou liberação automática; [pipeline](IMPORT_PIPELINE.md) |
| SecureBuild baseline | Arquivos de configuração/código textual → achados estáticos e relatório | Não é SAST interprocedural ou DAST; [operação](docs/OPERACAO.md) |
| Análises especializadas | Artefatos npm/CycloneDX, SARIF, HAR/Nmap XML, IAM/S3, identidades e IA → resultados delimitados | Sem feed CVE atualizado, conectores cloud/AD ou teste de modelos; [analisadores](docs/ANALISES.md) |
| Auditoria de API | Documento OpenAPI JSON 3.0/3.1 → revisão estática de contrato | Não consulta endpoints nem comprova BOLA/BFLA, SSRF ou aplicação efetiva dos limites; [regras](docs/API-SECURITY.md) |
| Endpoint Agent / IntegrityWatch | Arquivo explícito → observação Rust autenticada, baseline aprovada e divergência | Monitoramento finito de arquivo, sem EDR completo, comandos remotos ou instalação de serviço; [agente](packages/endpoint-agent/README.md) |
| SOC / Detection Engine | Eventos e observações → correlação, alerta e incidente | Regras limitadas; simulação identificada não prova contenção; [resposta](INCIDENT_RESPONSE.md) |
| ResponseGrid / investigação | Incidente → notas cifradas, evidências, estados e relatório JSON | Classificar caso como resolvido não elimina ameaça; [operações](docs/OPERACOES-DEFESA.md) |
| SecureFix | Configuração SSH importada → proposta, aprovação, revisão, verificação e rollback | Altera cópia cifrada no banco, nunca host/serviço; [fluxo](REMEDIATION_WORKFLOW.md) |
| RiskGraph | Registros da empresa → nós, vínculos e risco estático limitado | Relação registrada não é caminho explorável; [grafo](docs/RISKGRAPH.md) |
| AttackLab | Alvo IPv4 de laboratório e portas permitidas → adaptador Nmap opcional | Sem NSE/exploração; licença, instalação e execução real separadas; [adaptador](docs/ATTACKLAB.md) |
| Perícia offline | PCAP/PCAPNG, SQLite e plist autorizados → hashes, metadados, fluxos ou timeline | Sem captura ao vivo, aquisição de discos/celulares ou recuperação de apagados; [worker](docs/FORENSE-WORKER.md) |
| BarrierMatrix | Resultados disponíveis → estado evidenciado de controles em 14 camadas | Camada representada não implica proteção ativa |
| Preparação/validação | Fonte e fixtures → builds, testes, doctor, CI preparada e verificação de repositório | CI configurada não é execução comprovada; [testes](TESTING.md), [implantação](DEPLOYMENT.md) |

ProofLab completo, ResilienceLab, fila central de jobs, CLI unificada,
contenção/recuperação do host, telemetria EDR/XDR ampliada, aquisição forense,
análise dinâmica, inteligência online, IoT/OT, GRC, equipes e serviços gerenciados
continuam como evolução. Sua presença na especificação não cria uma função no
produto. Um componente parcial pode ser útil sem satisfazer todo o módulo V6.9.

Novos módulos precisam declarar contrato/versionamento, dependências, licença,
autorização, limites, comportamento de falha, testes e evidências antes de integrar
o painel. As obrigações completas estão em [evolução V6.9](docs/EVOLUCAO-V6.9.md).
