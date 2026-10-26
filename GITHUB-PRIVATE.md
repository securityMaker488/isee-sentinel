# GitHub privado — preparação e sincronização

Nome previsto: isee-sentinel. Nenhum repositório remoto, publicação ou push deve
ser presumido. O código é proprietário da I.See Technologies. Este guia fornece
o procedimento ao operador; não executa publicação.

No diagnóstico atual, Git local existe, main está inicializada e há identidade
de commit configurada. GitHub CLI não foi localizado e não há remoto origin.
Não foram buscados tokens em arquivos pessoais.

## Criar o privado, quando o operador decidir sincronizar

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
