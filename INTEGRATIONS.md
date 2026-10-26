# Integration Framework — registro inicial

Cada adaptador deve declarar origem, versão, licença, compatibilidade, permissões, offline, custo, entrada/saída, limites e testes antes de ser ativado. O inventário central está em PORTFOLIO_CAPABILITY_MATRIX.md e docs/portfolio-capabilities.json.

| Integração | Tipo | Contrato | Dependência / limite |
|---|---|---|---|
| Sentinel Agent 0.1.0 + transporte v1 | Operating System Adapter nativo | AgentObservation v1 → POST /agent/v1/observations assinado | Rust/reqwest/rustls; leitura de arquivo explícito, nenhuma execução remota |
| Artifact Analysis 1.0 | Native Engine | texto/JSON/XML ≤1MiB → findings/facts/timeline + hashes | parsers locais; dados de referência fornecidos, sem feed CVE atual |
| SARIF 2.1.0 | Importação de padrão aberto | runs/results → achados com provenance imported_tool | importação não valida precisão do scanner de origem |
| CycloneDX/npm lock | Importação de padrão/formato | inventário → análise limitada de higiene | não substitui OSV/SCA completo |
| Nmap XML | Importador + Laboratory Adapter opcional | XML → serviços/achados; runner limitado → XML preservado | Nmap externo, não distribuído; versão/licença requerem registro do operador |
| Case/SecureFix | Native Engine | caso e cópia de configuração → histórico/revisões/relatório | não altera host nem serviço |
| Forensics Python 1.0 | Worker local | PCAP/PCAPNG/SQLite/plist → relatório com hash | Python3.11+, stdlib,16MiB,60s; sem aquisição |
| Import Inspector 1.0 | Worker local | ZIP em quarentena → membros e tecnologias indicativas | Python3.11+, stdlib,16MiB,45s; sem extração/execução |
| OpenAPI 3.0/3.1 JSON | Native Engine | contrato de API → auditoria estática | referências locais limitadas; sem acesso externo |
| Demais referências V6.6 | Planejadas | Sem contrato operacional ainda | Autopsy/TSK, ALEAPP/iLEAPP, YARA/Volatility/Ghidra, Zeek/TShark e serviços online não instalados |

Ferramentas comerciais são referências funcionais. Não presumir licença de uso, API pública, acesso ou redistribuição. Integrações futuras gratuitas também exigem revisão da edição e licença. Não há conectores obrigatórios pagos.
