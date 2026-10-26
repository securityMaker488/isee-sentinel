# GitHub privado — preparação e sincronização

Repositório: [securityMaker488/isee-sentinel](https://github.com/securityMaker488/isee-sentinel).
Criado em26/10/2026 por solicitação do operador; visibilidade **privada** confirmada
nas configurações do GitHub. O código é proprietário da I.See Technologies.
`origin` aponta para `https://github.com/securityMaker488/isee-sentinel.git`.

Git local usa main e o Git Credential Manager já instalado. O operador autorizou
o vínculo OAuth da conta pelo fluxo oficial do GitHub. Credenciais ficam no
gerenciador do sistema, fora do código; não colocar tokens na URL nem no Git.
GitHub CLI é opcional e não estava instalado durante a preparação.

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

## Referência para outra instalação ou conta

O repositório acima já existe; não recriá-lo. Os comandos de criação abaixo são
referência para uma nova instalação previamente autorizada.

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
gh repo create DONO/isee-sentinel --private --source . --remote origin
gh repo view DONO/isee-sentinel --json nameWithOwner,visibility
```
Confirme PRIVATE e o dono correto antes do primeiro envio:
```text
npm run verify:repository
git push -u origin main
```
Substitua DONO pela conta/organização real. Não crie um repositório público, não
altere um origin já existente automaticamente e não use force-push. A opção
--private e o vínculo --source/--remote constam no
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
