# AttackLab — verificação TCP em laboratório autorizado

O adaptador implementa uma execução controlada de Nmap para um único endereço IPv4 cadastrado e até dezesseis portas TCP escolhidas. O ativo deve pertencer à organização ativa e ao ambiente `lab`, com autorização `scan` vigente. O resultado é analisado pelo parser de artefatos existente, com evidência XML cifrada, histórico de jobs e cadeia de auditoria. Uma porta aberta é um resultado de conectividade; não comprova vulnerabilidade nem exploração.

## Dependência externa e licença

O repositório não inclui, instala ou baixa o executável Nmap. O operador deve obter uma instalação oficial, verificar sua licença e configurar `SENTINEL_NMAP_PATH` com o caminho absoluto do binário confiável (`nmap` no Unix, `nmap.exe` no Windows). O adaptador não procura executáveis no PATH e não recebe esse caminho pela API.

A licença oficial é a **Nmap Public Source License**, com termos específicos para incorporação e utilização em produtos proprietários; uma integração comercial pode exigir licença **Nmap OEM**. Instalar um binário separadamente não demonstra por si só que a integração proprietária está licenciada. A liberação comercial desta integração depende dessa revisão, e nenhuma licença de Nmap/Npcap é concedida por este projeto. Consulte a [licença oficial NPSL](https://nmap.org/npsl/) e o [programa Nmap OEM](https://nmap.org/oem/). No Windows, verifique também os termos dos componentes da instalação utilizada.

`GET /api/lab/status` informa se o caminho foi configurado de forma aceitável, sem divulgar seu valor. `configured:true` não significa binário presente, versão confirmada, licença aprovada ou teste operacional concluído. A resposta mantém `versionVerified:false`; a versão do Nmap não é consultada automaticamente. Executável ausente, sem acesso ou configuração inválida retorna `503 NMAP_UNAVAILABLE` quando a execução é solicitada.

## Configuração e execução explícita

Use uma conta de serviço própria sem privilégios, com permissão de executar o binário oficial e acesso ao banco necessário. Em Unix o adaptador real recusa UID efetivo zero, binário simbólico, bits setuid/setgid ou arquivo gravável por grupo/outros. A instalação e seus diretórios devem permanecer sob controle administrativo. No Windows a conta deve ser sem privilégios e as ACLs do executável devem impedir alteração por usuários não autorizados; o adaptador não audita todas as ACLs do sistema.

Exemplos de configuração de caminho, que não executam uma varredura:

```sh
export SENTINEL_NMAP_PATH=/usr/bin/nmap
```

```powershell
$env:SENTINEL_NMAP_PATH = 'C:\Program Files (x86)\Nmap\nmap.exe'
```

Antes de executar, o administrador cadastra um alvo com `assetId`, `address` e `name`. São aceitos endereços literais em `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` e `127.0.0.0/8`, sempre como um único IPv4. Domínios, URLs, IPv6, endereços públicos, link-local, CIDR, intervalos, listas, notações numéricas alternativas e opções de linha de comando são rejeitados. A relação entre organização, ativo e endereço fica imutável no banco. Estar em faixa privada não comprova autorização: o operador deve conferir que aquele endereço identifica o equipamento autorizado, especialmente após alterações de rede ou DHCP.

O pedido de execução contém somente `targetId` e `ports`, de 1 a 16 inteiros únicos entre 1 e 65535. O backend relê a autorização imediatamente antes de iniciar o processo. Ela precisa continuar válida pelos próximos quarenta segundos. A autorização é verificada no início de cada execução; este adaptador não implementa cancelamento imediato de um processo já iniciado se o operador revogar o escopo durante a execução.

## Operação efetiva do processo

O executor usa `execFile`, sem shell, sem terminal visível e sem entrada interativa. Os argumentos são construídos pelo servidor:

```text
--unprivileged --disable-arp-ping -sT -Pn -n --max-retries 1 --host-timeout 30s -p <portas_ordenadas> -oX - <IPv4_cadastrado>
```

O modo [`-sT` usa conexões TCP do sistema operacional](https://nmap.org/book/man-port-scanning-techniques.html). As opções [`-Pn`, `-n` e `--disable-arp-ping`](https://nmap.org/book/man-host-discovery.html) evitam descoberta adicional e resolução DNS pelo Nmap. `--disable-arp-ping` é explícito porque `-Pn` sozinho ainda pode fazer descoberta ARP local. A opção [`--unprivileged`](https://nmap.org/book/man-misc-options.html) instrui o Nmap a não assumir capacidade de raw sockets. A pilha de rede do próprio sistema continua responsável por conexão e resolução de vizinhança normais.

São fixados [uma repetição máxima e trinta segundos por host](https://nmap.org/book/man-performance.html). O processo tem limite externo de quarenta segundos, encerramento com `SIGKILL` quando necessário e limite de 1 MiB para cada fluxo de saída. [`-oX -` direciona o XML para stdout](https://nmap.org/book/man-output.html), sem pedir arquivo de saída no host. Não existem parâmetros para NSE, scripts, exploração, detecção de versão, detecção de sistema operacional, UDP, credenciais de alvo, shell, elevação ou argumentos adicionais.

O processo recebe um ambiente mínimo com localidade e `NMAP_UNPRIVILEGED=1`; chaves mestras, senhas do banco e configurações de sessão não são herdadas. No Windows são preservadas somente as variáveis de sistema e temporárias necessárias ao processo. O Nmap usa seus arquivos de dados e bibliotecas da instalação confiável. O adaptador não transforma uma instalação comprometida do scanner em uma instalação confiável.

## Evidência, estado e concorrência

Cada pedido aceito cria um job `lab_nmap` e uma linha de histórico. stdout, inclusive quando parcial ou inválido, é limitado a 1 MiB, cifrado com o mecanismo AES-GCM de evidências da plataforma e identificado por SHA-256. stderr e mensagens brutas de erro do subprocesso não são devolvidos ao navegador nem copiados para a auditoria. Erros retornam códigos estáveis; o histórico vincula eventual evidência parcial.

Saída válida passa por `analyzeArtifact(kind:'network')`, gera uma análise em `artifact_analyses` e encerra o job como `completed`. Falha de execução, timeout, limite de saída, UTF-8 inválido ou XML rejeitado encerra como `failed`, sem apresentar uma análise concluída. A entrada XML é tratada como dado não confiável pelo parser; não executa comandos, XSL, entidades externas ou conteúdo recebido do alvo.

Há somente uma execução ativa de laboratório por banco, além de bloqueio local no processo. O slot de execução tem lease de 120 segundos, maior que o timeout de quarenta segundos. Pedidos concorrentes recebem `409 LAB_BUSY`. O slot é liberado no bloco final mesmo após falha de parsing. No próximo pedido, um lease vencido marca o job anterior como `interrupted`, registra `LEASE_EXPIRED` e permite nova execução. Jobs já marcados como interrompidos pelo startup também liberam o slot no próximo pedido. Uma resposta tardia que perdeu o lease não pode ser publicada como concluída. Não há reinício automático da varredura.

Eventos `lab.target_registered`, `lab.started`, `lab.output_preserved`, `lab.completed`, `lab.failed` e `lab.interrupted` integram a cadeia de auditoria. O histórico é isolado por organização e pode vincular `analysisId` ao relatório de análise já existente.

## Contrato HTTP

| Método e rota | Entrada ou resultado |
| --- | --- |
| `GET /api/lab/status` | `configured`, `pathConfigured`, `adapter`, `mode`, `maxPorts`, `requiresEnvironment`, `versionVerified` |
| `GET /api/lab/targets` | `items` com `id`, `assetId`, `address`, `name`, `createdAt` |
| `POST /api/lab/targets` | `{assetId,address,name}`; exige administrador |
| `GET /api/lab/scans` | `items` com `id`, `targetId`, `assetId`, `ports`, `status`, `createdAt`, `completedAt`, `evidenceId`, `analysisId`, `summary`, `findingCount`, `errorCode` |
| `POST /api/lab/scans` | `{targetId,ports}`; resposta de sucesso contém resumo e `report` |

As rotas usam sessão, MFA de login, verificação de origem, CSRF e PolicyGate existentes. Nenhum endpoint aceita uma identidade enviada no corpo como autorização.

## Migração e permissões mínimas

A migração `006_lab.sql` cria `lab_targets`, `lab_scans` e `lab_execution_lock`. Para a identidade da aplicação, além das permissões já existentes de jobs, evidências, análises e auditoria:

```sql
GRANT SELECT, INSERT ON lab_targets TO sentinel_app;
GRANT SELECT, INSERT ON lab_scans TO sentinel_app;
GRANT UPDATE(evidence_id,analysis_id,error_code) ON lab_scans TO sentinel_app;
GRANT SELECT, INSERT, DELETE ON lab_execution_lock TO sentinel_app;
GRANT UPDATE(job_id) ON lab_execution_lock TO sentinel_app;
```

O grant de atualização do lock é necessário para `SELECT FOR UPDATE`; seu `job_id` não é alterado em operação normal. Alvos são imutáveis e a aplicação não recebe permissão de modificá-los. A execução de migrações pertence à identidade administrativa de migração.

## Verificação realizada e pendências

```sh
npx tsx --test apps/api/test/lab.test.ts
```

Os testes usam um runner injetado e um banco temporário: validam endereços, portas, argumentos fixos, RBAC, escopo, contexto organizacional, preservação cifrada, análise, falhas, concorrência, lease e auditoria. Nenhum teste inicia Nmap ou faz varredura de rede. A homologação operacional exige a instalação oficial licenciada, um alvo de laboratório de propriedade/autorização confirmada e a verificação dos resultados nessa instalação. Não há equivalência declarada com plataformas comerciais de exploração ou pentest.
