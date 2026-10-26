# Modelo de ameaças e limites de segurança

Escopo: fundação local 0.1 adaptada à V6.3, 23/10/2026. Protegemos identidade do fundador, organizações/projetos privados, autorizações, evidências, eventos, achados e sua rastreabilidade. O host e o administrador do banco são parte da base de confiança; a fundação não resiste a comprometimento pleno desses administradores. Um único operador não elimina isolamento por organização nem controles de execução.

| Ameaça / fronteira | Controle da fundação | Risco remanescente / teste necessário |
|---|---|---|
| Visitante tenta acessar dados sem autenticação | Autenticação no backend e sessão opaca | Testar todas as rotas novas, respostas de erro e URLs alternativas |
| Senha obtida ou adivinhada | Argon2id, MFA obrigatório, limites de tentativas | Phishing e furto do autenticador permanecem riscos; WebAuthn planejado; recuperação exige código offline secreto |
| Replay de TOTP ou sessão | Contador TOTP usado persistido; expiração/revogação de sessão | Avaliar relógio e concorrência PostgreSQL; host comprometido pode capturar segredo |
| Site externo induz ação autenticada | Cookie HttpOnly/SameSite, token CSRF e origem validada nas mutações | Verificar proxy/origin ao habilitar HTTPS; XSS no mesmo origin continua relevante |
| Contexto/identificador trocado para outra empresa | Organização da sessão, vínculo explícito do fundador, checagem de recurso, consultas filtradas e FKs compostas | Não há RLS; bug em nova query ainda pode romper isolamento; testar troca de contexto e sessão/CSRF |
| Analista executa fora do contrato ou prazo | PolicyGate verifica operação conhecida, ativo, ambiente e autorização válida | Referência de autorização não verifica assinatura jurídica do contrato; revisão humana necessária |
| Caminho enviado tenta sair da raiz ou executar programa | Caminhos lógicos validados; conteúdo é dado, sem leitura arbitrária nem execução | Parsers externos futuros precisam sandbox, quotas e proteção contra arquivos compactados maliciosos |
| Payload induz consumo excessivo | Quotas de arquivo/pacote, limite HTTP e executor limitado | Carga sustentada e concorrência precisam medição; não há proteção contra DDoS volumétrico |
| Injeção SQL ou mass assignment | SQL parametrizado, esquemas de entrada, campos definidos explicitamente | Testes negativos e revisão de novos endpoints; parâmetro SQL não resolve autorização |
| URL de documento tenta alcançar rede interna | A fundação não busca URLs enviadas nem executa webhooks | SSRF precisa teste e política de egress quando conectores forem adicionados |
| Segredos vazam em achados/logs | Regras relatam tipo/localização sem reproduzir segredo; evidência cifrada | Originais podem conter segredos e continuam sensíveis; controlar exportação e backups |
| Alguém altera evidência | SHA-256 dos bytes, AES-256-GCM, registro de custódia e proteção contra mutações ordinárias | DBA/host pode burlar triggers e reescrever cadeia; sem ancoragem externa ou carimbo confiável |
| Falha depois de iniciar análise | Job SQL com estado explícito e interrupção reportada | Não há retry/lease distribuído; recuperar por reexecução rastreada, sem declarar sucesso silencioso |
| Evento forjado cria incidente enganoso | Payload validado, origem declarada e sintéticos separados | Origem declarada não é sensor autenticado. Separar timestamp recebido do informado |
| Dependência ou pacote nativo comprometido | Lockfile, inventário e instalação com scripts desabilitados | Atualizações, avisos e proveniência precisam revisão contínua; ausência de CVE reportada não é garantia |
| Prompt injection em artefato | Sem LLM ou executor de ferramentas de IA conectado | Quando implementado: dado não é instrução, argumentos tipados e PolicyGate independente |
| Ransomware ou perda da chave | Plano de backup separado da chave e restore isolado | Rotação, cópia offline, teste de restauração e RPO/RTO ainda precisam homologação |
| Roubo ou replay de código de recuperação | Código aleatório, hash no banco, consumo e rotação transacional, revogação de sessões | O portador do código pode recuperar o operador via CLI; guardar offline separado do banco/host |

## Propriedades e limites concretos

Argon2id usa 19 MiB, custo de tempo 2 e paralelismo 1 na fundação. Esses parâmetros devem ser calibrados no host de operação sob carga. A chave de 32 bytes para AES-256-GCM fica fora do banco, por variável de ambiente ou arquivo local privado. O uso de criptografia de aplicação não criptografa todos os metadados do banco nem substitui criptografia de disco.

O cookie seguro é obrigatório para origem HTTPS. A execução HTTP é restrita a loopback para desenvolvimento; não expor o servidor à LAN ou internet por túnel público. Produção exige TLS e homologação explícita. Nunca registrar senhas, TOTP, URI de provisionamento, cookies, chave mestra ou corpos brutos de evidência em logs operacionais.

O cadastro de autorização é uma declaração operacional do administrador. A plataforma não consegue determinar sozinha se ele tem direitos legais sobre o ativo. Autorizações precisam de referência rastreável e prazo; arquivos de clientes exigem controle de acesso e retenção. A versão não executa pentest remoto, coleta invasiva, retaliação, bypass de celular nem amostras de malware.

## Rastreabilidade a referências

ASVS 5.0.0 é a base de requisitos web; usar identificador com versão, por exemplo `v5.0.0-1.2.5` para prevenção de injeção de comandos. Nesta fatia, o critério de projeto é não criar executor de comandos a partir de arquivos enviados. A conformidade exige mapear e testar cada requisito aplicável, não apenas citar o padrão. [ASVS oficial](https://asvs.owasp.org/).

O planejamento de resposta segue NIST SP 800-61 Rev.3, publicado em abril de 2025, alinhado à gestão de risco do CSF 2.0. ResponseGrid futuro deve registrar preparação, detecção, resposta, recuperação e melhoria; um incidente no banco não comprova esse processo inteiro. [Publicação NIST](https://csrc.nist.gov/pubs/sp/800/61/r3/final).

Para IA, o backlog parte de LLM01:2025 (prompt injection), LLM02:2025 (divulgação sensível), LLM05:2025 (tratamento de saída), LLM06:2025 (autonomia excessiva) e LLM10:2025 (consumo sem limites). Não há avaliação de conformidade LLM porque o módulo ainda está planejado. [OWASP GenAI Top 10](https://genai.owasp.org/llm-top-10/).

WSTG, API Security Top 10, MASVS, NIST CSF 2.0/SP 800-207, ATT&CK, D3FEND, CWE, CVE, CVSS, EPSS, CISA KEV, Sigma, YARA, STIX/TAXII, CycloneDX e SARIF estão previstos no backlog de rastreabilidade. Versões e identificadores devem ser fixados na entrega que os utilizar; não se afirma integração ou conformidade atual.
