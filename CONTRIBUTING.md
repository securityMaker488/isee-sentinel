# Desenvolvimento e contribuições internas

I.See Sentinel é software proprietário da I.See Technologies. Este guia organiza
contribuições internas autorizadas; não concede licença pública ou autorização
para publicar o repositório. Consulte [LICENSE](LICENSE) e [LICENSES.md](LICENSES.md).

## Retomar e delimitar

Leia [AGENTS.md](AGENTS.md), [PROJECT_STATE.md](PROJECT_STATE.md) e a fase relevante
do [ROADMAP.md](ROADMAP.md). Continue do ponto registrado, sem reler todos os
prompts ou revisar novamente blocos grandes já examinados. Inspecione contratos,
dependências e arquivos afetados pelo incremento; preserve código funcional.
Registre riscos e o critério de aceite antes de introduzir um novo executor.

Use branch de tarefa quando o histórico estiver preparado. Confira `git status`
e preserve alterações não sincronizadas antes de atualizar uma branch. Não use
reset destrutivo, force-push, troca de remoto ou publicação para contornar conflito.
[GITHUB-PRIVATE.md](GITHUB-PRIVATE.md) descreve a preparação do remoto privado.

## Implementar

- API: consultas parametrizadas, schemas limitados, contexto da sessão e
  PolicyGate; não confiar em organização/papel fornecidos no corpo.
- Core: análise determinística de dados, sem subprocessos, rede, disco ou
  execução de conteúdo analisado. Integrações têm adaptadores separados.
- Agentes/workers: entradas explícitas, consentimento, identidade apropriada,
  limites de recursos, erros estáveis e limpeza. Sem shell remoto ou persistência
  silenciosa.
- Banco: migração nova para evolução; não modificar checksums de migrações já
  aplicadas. Atualizar runtime-grants com o menor privilégio necessário.
- UI: comportamento real, rótulos acessíveis, estados de erro/carregamento,
  isolamento ao trocar de empresa e indicação clara de dados sintéticos.
- Dependências: justificar finalidade, licença e versão; revisar lockfiles.
  Não introduzir serviços pagos ou Docker como exigência do núcleo.

## Verificar e registrar

Execute testes relacionados e depois a verificação integrada necessária para a
mudança, conforme [TESTING.md](TESTING.md). Distingua processo real de substituto,
Windows de Debian, build de teste funcional e fixture de operação profissional.
Corrija falhas relevantes antes de declarar conclusão; registre testes pendentes.

Antes do commit, revise arquivos novos/alterados, rode `npm run verify:repository`
e confira o diff. Adicione apenas caminhos revisados, confira `git diff --cached`
e execute novamente a verificação de repositório. Ela não elimina a necessidade
de revisão humana. Nunca versionar `.env`, credenciais, chaves, bancos, resultados
com dados reais ou diretórios de runtime.

Atualize documentos do módulo e os registros centrais de estado/validação com
evidência, limitações, processos temporários ainda ativos e próximo passo. Uma
mudança de documentação não deve promover maturidade de código por si só.
Push somente para remoto privado conferido e explicitamente autorizado.

Para reportar falhas de segurança, siga [SECURITY.md](SECURITY.md). Não inserir
segredos ou dados de clientes em issues, commits, screenshots ou logs.
