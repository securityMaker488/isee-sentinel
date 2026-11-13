# GitHub — preparação, sincronização e publicação

Repositório: [securityMaker488/isee-sentinel](https://github.com/securityMaker488/isee-sentinel).
Criado em 26/10/2026 por solicitação do operador. A visibilidade foi **privada**
até 13/11/2026 e passou a **pública** por decisão do titular, no mesmo dia, sob
GNU AGPL-3.0 — a licença dos projetos de referência usados como estudo de
conceitos. `origin` aponta para `https://github.com/securityMaker488/isee-sentinel.git`.

Git local usa `main` e o Git Credential Manager já instalado. O operador autorizou
o vínculo OAuth da conta pelo fluxo oficial do GitHub. Credenciais ficam no
gerenciador do sistema, fora do código; não colocar tokens na URL nem no Git.
O GitHub CLI está disponível para conferir e sincronizar o remoto.

Para conferir se fonte local e remoto estão sincronizados:
```text
git fetch origin
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
```
Os dois hashes devem coincidir após o envio. Falha de autenticação ou CI deve
ser registrada, nunca inferida como sucesso. A etapa Debian começa somente após
concluir ou registrar explicitamente as pendências Windows de PROJECT_STATE.md.

## Publicação de 13/11/2026

Antes de tornar o repositório público, o titular autorizou e o trabalho executou:

1. **Backup privado e verificável** de todos os commits originais, em espelho
   local fora do repositório, com manifesto por commit e `sha256` do manifesto.
   O espelho preserva a história completa, inclusive o registro interno de
   pesquisa que não é publicado.
2. **Auditoria de atribuição**: nenhum código de terceiros incorporado, nenhum
   cabeçalho de copyright alheio, nenhum diretório vendorizado. Avisos de licença
   de terceiros permanecem em [LICENSES.md](LICENSES.md) e nos inventários em
   `docs/generated/`.
3. **Redação do capítulo de referência** da especificação V11 e dos documentos
   que apontavam para ele, para que a identificação dos projetos estudados e as
   URLs não sejam publicadas. O `sha256` original do anexo e o `sha256`
   redigido ficam registrados em `docs/PROMPT-COVERAGE.json`, preservando a
   cadeia de custódia.
4. **Reescrita do histórico** para remover o registro interno de pesquisa e as
   menções aos projetos estudados também nos commits antigos. A reescrita é
   local até a aprovação do titular: nada foi enviado ao remoto nesta etapa.

Consequências conhecidas da reescrita: os hashes de commit mudam, e o remoto
precisa ser atualizado com `--force-with-lease` (o repositório nunca foi
público, portanto nenhum clone de terceiros é afetado). O histórico reescrito
passa a ser a referência oficial de continuidade; o espelho privado guarda a
série anterior.

## Referência para outra instalação ou conta

O repositório acima já existe; não recriá-lo. Os comandos abaixo são referência
para uma nova instalação previamente autorizada.

Instale GitHub CLI pelo canal oficial, autentique e escolha a conta correta:
```text
gh auth login
gh auth status
npm run verify:repository
git status
git diff --cached
```

Depois do commit local revisado, se nenhum remoto existir:
```text
gh repo create DONO/isee-sentinel --public --source . --remote origin
gh repo view DONO/isee-sentinel --json nameWithOwner,visibility
```
Confirme PUBLIC e o dono correto antes do primeiro envio:
```text
npm run verify:repository
git push -u origin main
```
Substitua DONO pela conta/organização real. Não altere um origin já existente
automaticamente e não use force-push sem autorização específica e registrada. A
opção `--public` e o vínculo `--source/--remote` constam no
[manual oficial de criação](https://cli.github.com/manual/gh_repo_create).

Se o repositório já existir, confira-o antes de configurar um remoto; preserve
todo histórico existente. Clonar uma cópia nova e comparar é preferível a
sobrescrever conteúdo. O primeiro push não deve incluir bancos, chaves,
credenciais ou arquivos de autenticação. A verificação local é uma camada de
prevenção, não prova de ausência de todo segredo possível.

## Memória que acompanha o código

Versionar AGENTS.md, PROJECT_STATE.md, arquitetura, roadmap, matriz, documentação,
scripts, migrações, lockfiles e testes. Ignorar dados operacionais e saídas de QA.
Revise também histórico anterior antes de qualquer envio, pois apagar um segredo
apenas da versão atual não o remove dos commits anteriores.
