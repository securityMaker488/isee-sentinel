# Fontes, dependências e licenças

Consulta: 23/10/2026. As fontes abaixo são oficiais. Versão publicada, versão instalada e compatibilidade testada são fatos distintos. O lockfile registra versões resolvidas; `docs/generated/dependencies.json`, gerado por `npm run inventory`, registra metadados locais. Nenhuma integração opcional está automaticamente aprovada para redistribuição.

## Plataforma e referências de segurança

| Tema | Informação verificada | Uso no projeto |
|---|---|---|
| [Debian 13 trixie](https://www.debian.org/releases/trixie/) | Debian 13 é a linha stable; página oficial consultada registra 13.7 e ciclo de suporte | Alvo principal com KDE Plasma; instalação/migração ainda não executada |
| [Node oficial](https://nodejs.org/en/blog/release) | Release 24.22.1 LTS de 21/10/2026 | Linha 24 para o projeto; sessão executou 24.21.0, atualização do runtime é pendente |
| [Pacote Node no Debian trixie](https://packages.debian.org/trixie/nodejs) | Pacote publicado consultado pertence à linha 20 | `apt install nodejs` sozinho não atende `engines` do projeto; usar distribuição oficial Node 24 verificada e caminho explícito, sem misturar repositórios Debian/Ubuntu |
| [Fastify LTS](https://fastify.dev/docs/latest/Reference/LTS/) | Linha 5 com fim de suporte ainda não definido na tabela consultada | Confirmar versão resolvida no lockfile e manter atualizações testadas |
| [PostgreSQL versionamento](https://www.postgresql.org/support/versioning/) | Linhas major têm ciclo de suporte de cinco anos; usar minor atual da linha | Homologar banco dedicado; não inferir minor só pelo nome do serviço |
| [PGlite](https://pglite.dev/docs/about) | PostgreSQL WASM, persistência local e uso em desenvolvimento/testes | Banco isolado sem servidor para desenvolvimento; não comprova operação distribuída |
| [ASVS](https://asvs.owasp.org/) | 5.0.0, publicado em 30/05/2025 | Rastreabilidade por identificador versionado; não há alegação de certificação |
| [NIST SP 800-61 Rev.3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Publicação final de abril de 2025, alinhada a CSF 2.0 | Processo futuro de resposta e recuperação |
| [OWASP GenAI](https://genai.owasp.org/llm-top-10/) | Top 10 publicado 2025 | Backlog AI Security e autonomia restrita |
| [systemd.exec](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html) | Diretivas de ambiente, isolamento e acesso a arquivos | Exemplo de serviço; precisa validação no Debian real |
| [NVIDIA Pascal](https://developer.nvidia.com/blog/nvidia-transitions-fully-towards-open-source-gpu-kernel-modules/) | Pascal não é compatível com NVIDIA Open GPU Kernel Modules | Não selecionar automaticamente a variante open para GTX 1050 |
| [NVIDIA legado Unix](https://nvidia.custhelp.com/app/answers/detail/a_id/3142/) | 580 é a última família Linux que suporta Pascal | Família suportada não prova disponibilidade/compatibilidade do pacote Debian; verificar kernel, GPU PCI ID e advisories antes de instalar |

A consulta direta à Wiki Debian de NVIDIA foi bloqueada por 403; não foi usado conteúdo inacessível para recomendar uma instalação. Não foi instalado driver nem alterado o boot. A aceleração GPU não é necessária para esta fundação.

## Dependências centrais: licença declarada nas fontes oficiais

| Componente | Licença identificada | Fonte |
|---|---|---|
| Node.js | MIT no núcleo; distribuição contém componentes com outros avisos | [LICENSE Node](https://github.com/nodejs/node/blob/main/LICENSE) |
| Fastify | MIT | [LICENSE Fastify](https://github.com/fastify/fastify/blob/main/LICENSE) |
| React | MIT | [LICENSE React](https://github.com/react/react/blob/main/LICENSE) |
| Vite | MIT | [LICENSE Vite](https://raw.githubusercontent.com/vitejs/vite/main/LICENSE) |
| TypeScript | Apache-2.0 | [LICENSE TypeScript](https://raw.githubusercontent.com/microsoft/TypeScript/main/LICENSE.txt) |
| `pg` | MIT | [LICENSE node-postgres](https://github.com/brianc/node-postgres/blob/master/LICENSE) |
| PostgreSQL | PostgreSQL License | [Licença PostgreSQL](https://www.postgresql.org/about/licence/) |
| PGlite | Apache-2.0 e avisos PostgreSQL; preservar ambos os arquivos distribuídos | [LICENSE PGlite](https://raw.githubusercontent.com/electric-sql/pglite/main/LICENSE), [POSTGRES-LICENSE](https://github.com/electric-sql/pglite/blob/main/POSTGRES-LICENSE) |
| `@node-rs/argon2` | MIT no repositório; revisar avisos das dependências nativas no pacote efetivo | [LICENSE node-rs](https://raw.githubusercontent.com/napi-rs/node-rs/main/LICENSE) |
| `otpauth` | MIT | [LICENSE OTPAuth](https://github.com/hectorm/otpauth/blob/master/LICENSE.md) |

Esta tabela confirma declarações upstream, não substitui os avisos da versão empacotada. Plugins Fastify, Tailwind, dependências transitivas e binários nativos devem ser conferidos no inventário e nos arquivos LICENSE/NOTICE efetivamente distribuídos. MIT e PostgreSQL exigem preservar avisos aplicáveis; Apache-2.0 também exige cumprir condições de redistribuição e notices quando presentes. Não há parecer jurídico ou autorização irrestrita para qualquer modelo comercial.

O código original do Sentinel e sua experiência podem seguir a estratégia proprietária da I.See; isso não altera direitos de terceiros. Antes de distribuição, gerar SBOM CycloneDX ou formato equivalente, coletar LICENSE/NOTICE, revisar transições de licença e registrar obrigações por componente/edição. Um resultado zero de `npm audit` cobre apenas advisories retornados naquele momento, sem garantir ausência de falhas.

## Integrações opcionais do prompt

Todas permanecem planejadas e fora do executável inicial. Não são dependências da inicialização. Antes de conectar, registrar versão/hash, procedência, licença do motor e das regras/datasets, modo de invocação, permissões, limites e teste em fixture própria.

| Ferramenta / grupo | Uso previsto | Situação de licença e integração |
|---|---|---|
| Wazuh, Suricata, Zeek, Sigma | DefenseFlow/Detection Engine | Avaliação por componente e versão pendente; [arquitetura Wazuh oficial](https://documentation.wazuh.com/current/getting-started/index.html) confirma componentes separados |
| Wireshark, tcpdump, bibliotecas PCAP | NetworkTrace | Seleção, permissões de captura e revisão de redistribuição pendentes |
| Nmap | Inventário de exposição autorizado | NPSL possui condições específicas para produto proprietário; não embutir presumindo GPL genérica. [Fonte oficial NPSL](https://nmap.org/npsl/) |
| OWASP ZAP | DAST autorizado | Avaliação de versão, addons e licença pendente |
| Trivy, OSV-Scanner, Gitleaks | Dependências, imagens e segredos | Avaliação de versão, bancos, regras e atualização offline pendente |
| Semgrep | SAST | CE é LGPL2.1; regras mantidas no semgrep-rules seguem licença distinta com restrições para produto concorrente/SaaS. Não incorporar regras sem análise. [Licenciamento oficial](https://docs.semgrep.dev/licensing) |
| Autopsy, The Sleuth Kit | DiskLab | Formatos, componentes e licença por versão pendentes |
| Volatility3, Ghidra, YARA | DeepTrace/MalwareLens | Licença, plugins/regras e isolamento pendentes |
| ALEAPP, iLEAPP | MobileScope | Formatos, plugins e licença por versão pendentes |
| MITRE Caldera | AttackLab | Versão, plugins, licença e rede isolada pendentes |
| DFIR-IRIS | ResponseGrid | Modelo de integração e licença por versão pendentes |
| OpenSSL | CryptoGuard/TLS | Licença e compatibilidade da versão distribuída pendentes |
| AWS, Azure, GCP, AD e LDAP | CloudShield/IdentityGuard | APIs de leitura, escopo, custos e termos pendentes; não conectados |

Não foram reproduzidos códigos fechados nem removidos avisos. Ferramentas comerciais de perícia permanecem referências de requisitos, sem alegação de equivalência.
