# Curso do operador — do fundamento à engenharia avançada

O curso progride por prática demonstrada, sem pular fundamentos. V6.5 reorganiza a trilha em 21 tópicos; preserva conteúdo da V6.3 e acrescenta Podman/KVM. Cada aula segue: explicação, conceitos, exemplo, exercício autorizado, comandos comentados, resultado esperado, avaliação e conexão com o Sentinel. Nesta entrega, a trilha está planejada e a aula 1 está completa; as demais aulas ainda serão desenvolvidas. Não se afirma que o aluno já dominou os tópicos.

| Ordem | Tópico | Competência e relação com o produto | Entrega prática futura |
|---|---|---|---|
|1 | Fundamentos de computação | Hardware, processo, arquivo, memória, usuário, rede e limites de confiança | Inventário somente leitura e distinção entre observado/inferido |
|2 | Debian Linux | Terminal, filesystem, permissões, pacotes, systemd e KDE | Homologar ambiente sem alterar partições |
|3 | Terminal e Bash | Comandos, argumentos, pipes, permissões e erros | Diagnóstico somente leitura comentado |
|4 | Redes | IP, TCP/UDP, DNS, TLS, roteamento e segmentação | Desenhar rede isolada do AttackLab |
|5 | Python | Tipos, arquivos, erros, testes e subprocessos seguros | Parser de fixture local com limites |
|6 | TypeScript | Tipos, validação runtime, async e API | Contrato de evento v1 e cliente tipado |
|7 | Rust | Ownership, Result, parsing e APIs nativas | Protótipo de agente sem privilégios |
|8 | Programação segura | AppSec, autorização, injeção, segredos e dependências | Fixture vulnerável/corrigida e teste negativo de PolicyGate |
|9 | Blue Team | Telemetria, hipótese, regra, alerta e triagem | Correlacionar eventos sintéticos |
|10 | Red Team autorizado | Escopo, regras de engajamento e teste controlado | Plano de exercício de lab, sem alvo externo |
|11 | Purple Team | Objetivo defensivo, observação e reteste | Medir cenário sintético e lacunas |
|12 | Podman | Rootless, imagens, volumes, rede e quotas | Desenhar perfil mínimo para worker inerte |
|13 | Virtualização KVM | Kernel separado, libvirt, redes e snapshots | Verificar isolamento e recuperação da VM de lab |
|14 | Forense digital | Preservação, hash, cópia de trabalho e timeline | Registrar artefato sintético e verificar hash |
|15 | Engenharia reversa legítima | Formatos, assembly básico e análise documentada | Analisar binário didático próprio |
|16 | Análise de malware | Estática, indicadores e contenção de laboratório | Analisar fixture inerte; nenhuma amostra no host |
|17 | Criptografia | Hash, cifra, autenticação, chaves e TLS | Distinguir integridade, sigilo e autenticidade |
|18 | Cloud Security | IAM, rede, storage e responsabilidade | Modelo de leitura mínima, sem conta paga obrigatória |
|19 | Identity Security | Identidades humanas/serviço, MFA e privilégios | Inventário autorizado de identidade |
|20 | Segurança de IA | Prompt injection, ferramentas, dados e autonomia | Testar autorização independente do modelo |
|21 | Engenharia do Sentinel | AppSec avançado, AutoDefense, Self-Healing, testes, SLO, licenças e recuperação | Capstone: workflow autorizado, rollback, evidência e maturidade M0–M6 |

## Aula 1 — entender a máquina antes de operá-la

**Objetivo:** ao terminar, você deverá explicar o que o Sentinel utiliza do computador, coletar informações básicas sem modificá-lo e distinguir fatos observados de hipóteses. Duração sugerida: 45–60 min, sem obrigação de avançar por tempo. Pré-requisito: conseguir abrir um terminal. Não é necessário instalar Debian para fazer a variante Windows.

### Explicação

Um computador combina recursos físicos e programas. A CPU executa instruções. A RAM guarda dados de trabalho de processos enquanto eles executam. O armazenamento mantém arquivos mesmo após desligar. A GPU acelera operações para as quais existem software e driver compatíveis; sua presença não garante que qualquer modelo de IA caiba ou funcione nela.

O sistema operacional administra esses recursos e controla acesso. Um processo é uma execução de programa; várias instâncias do mesmo programa são processos distintos. O navegador é um processo que conversa com a API do Sentinel. A API valida a sessão, avalia a autorização e consulta o banco. O usuário do sistema que executa a API determina quais arquivos e recursos ela pode acessar; autenticação na aplicação não substitui permissões do sistema operacional.

Arquivo é uma sequência de bytes com nome e metadados. Uma pasta organiza nomes. Um caminho aponta para um local dentro de um sistema de arquivos. Um disco físico pode conter várias partições; um volume como `C:` representa um espaço lógico. Portanto, observar 239 GB no volume C não prova que o SSD físico tem 239 GB. O SSD 480 GB declarado e o volume observado podem coexistir sem contradição, mas ainda precisamos do inventário do layout para explicar essa diferença.

RAM livre também é uma fotografia do momento. Ela muda ao abrir o navegador ou uma VM. Se uma VM reservar 4 GiB em uma máquina com cerca de 6 GiB livres, a margem restante pode ser pequena para host, API e banco. Essa observação orienta a medição; não é motivo para alterar memória ou desligar serviços automaticamente.

### Conceitos que precisam ficar claros

| Conceito | Explicação | Exemplo no Sentinel |
|---|---|---|
| Programa / processo | Arquivos de software / execução desses arquivos | `node` executa o backend |
| Memória / armazenamento | Trabalho volátil / persistência | Buffer de upload / evidência no banco |
| Usuário / privilégio | Identidade do sistema / ações permitidas | Serviço sem administrador permanente |
| Autenticação / autorização | Provar identidade / decidir a ação permitida | TOTP / PolicyGate para o ativo |
| Localhost | Interface de rede do próprio computador | `127.0.0.1:4310` não é um site público |
| Porta | Identificador lógico de um serviço de rede | 4310 identifica a API/painel local |
| Observação / inferência | Dado medido / conclusão que depende de premissas | Versão retornada / compatibilidade presumida |
| Integridade / confidencialidade | Detectar alteração / restringir leitura | SHA-256 / AES-GCM e permissões |

Um hash igual ajuda a comparar bytes. Ele não prova quem criou um arquivo, se seu conteúdo é verdadeiro ou se é seguro executar. Não abra arquivos desconhecidos apenas porque o hash foi calculado.

### Exemplo de raciocínio

O comando de versão devolve `v24.21.0`. A observação é: o executável encontrado pelo terminal declarou essa versão. Não é possível concluir só disso que o serviço systemd usará o mesmo caminho ou que a versão é a atualização mais recente. Para o serviço, confira o caminho explícito e sua versão. Para atualização, consulte a fonte oficial e reteste.

O diagnóstico diz virtualização habilitada no firmware. Isso permite considerar uma VM, mas não comprova `/dev/kvm`, permissões do usuário, libvirt funcional ou rede isolada. Cada afirmação precisa da evidência correspondente.

### Exercício prático somente leitura

Escolha a variante do sistema em que você está. Execute uma linha de cada vez e explique em voz alta o que ela observa. Não use `sudo`, não instale pacotes e não copie comandos de formatação/particionamento. Escreva suas respostas em uma nota pessoal; não é preciso compartilhar nomes de arquivos, seriais ou segredos.

No Debian/Linux:

```bash
# Mostra a pasta atual; nao muda de diretorio.
pwd
# Mostra identificacao da distribuicao; apenas leitura do arquivo.
cat /etc/os-release
# Mostra kernel e arquitetura, sem hostname.
uname -srmo
# Mostra CPU e recursos declarados; nao e teste de desempenho.
lscpu
# Mostra memoria atual; a unidade exibida deve acompanhar o numero.
free -h
# Mostra espaco do filesystem atual, sem listar arquivos pessoais.
df -h .
# Mostra a localizacao do executavel Node, se estiver no PATH.
command -v node
# Mostra a versao do runtime encontrado, se estiver instalado.
node --version
```

No Windows/PowerShell acessível nesta sessão:

```powershell
# Mostra a pasta atual.
Get-Location
# Le somente nome e versao do sistema, sem coletar numero de serie.
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version
# Le CPU e contagem de nucleos/processadores logicos.
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
# Mostra capacidade e espaco livre de C:, que e volume logico.
Get-Volume -DriveLetter C | Select-Object DriveLetter, Size, SizeRemaining
# Identifica o executavel usado pelo terminal.
Get-Command node | Select-Object Source
# Consulta a versao; nao atualiza o programa.
node --version
```

Se um comando não existir, registre `indisponível` e avance para a próxima observação. Erro de permissão não autoriza elevar privilégios sem entender a necessidade. O diagnóstico agregado `bash scripts/diagnose-linux.sh` poderá ser usado no Debian após você compreender as observações individuais.

### Resultado esperado

Uma tabela sua com sistema/versão, CPU, memória quando disponível, volume e espaço livre, caminho/versão Node, data e fonte de cada dado. Não há números fixos a reproduzir: suas observações podem diferir da sessão. Use três estados: **observado**, **declarado** e **não verificado**. Exemplo: `SSD 480 GB — declarado pelo operador`; `volume C: 239.345.352.704 bytes — observado`; `Debian instalado — não verificado`.

Desenhe ainda o fluxo `navegador → API → PolicyGate → banco`. Marque onde ocorre autenticação e onde a autorização de ativo é avaliada. Não acrescente IA ou agente de endpoint ativo ao desenho da versão entregue.

### Avaliação

Responda sem consultar a tabela de conceitos:

1. Qual a diferença entre RAM e SSD? O que muda ao desligar?
2. Por que tamanho de C não determina a capacidade física do SSD?
3. Um TOTP válido autoriza qualquer ação em qualquer ativo? Justifique.
4. Um hash comprova que um arquivo é seguro? O que ele ajuda a verificar?
5. A API usar loopback significa que qualquer programa local é confiável?
6. Node instalado no terminal prova que systemd executará a mesma versão?
7. Cite uma observação, uma informação declarada e uma hipótese ainda não verificada da sua coleta.
8. Por que não ligar várias VMs apenas por existir suporte à virtualização?

Critério de conclusão: explicar corretamente os oito conceitos, produzir a tabela com fontes/unidades e identificar pelo menos três limites da coleta. Se houver dificuldade, refaça o exemplo antes da aula 2. Não há avaliação automática ou nota já atribuída.

Gabarito resumido: RAM é trabalho volátil, SSD persiste; C é volume lógico; MFA autentica e PolicyGate autoriza; hash compara integridade, sem provar segurança; loopback reduz exposição mas não transforma processo local em confiável; systemd usa caminho/ambiente próprios; observação precisa de fonte e hipótese precisa teste; virtualização consome CPU/RAM/disco e exige isolamento de rede.

### Relação com o produto e próxima aula

O diagnóstico alimenta System Health e decisões de capacidade. Permissões sustentam a identidade de serviço; autenticação e autorização sustentam PolicyGate; bytes e integridade sustentam EvidenceChain; separação entre observado e presumido sustenta todos os relatórios. Na aula 2, esses fundamentos serão aplicados a diretórios, permissões e serviços do Debian. Nenhuma instalação ou migração faz parte desta aula.
