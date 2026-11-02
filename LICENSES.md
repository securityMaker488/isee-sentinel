# Licenças e procedência

O código original do Sentinel permanece proprietário; consulte LICENSE. Não são copiados componentes proprietários das ferramentas de referência.

Inventário JavaScript gerado por `npm run inventory`: docs/generated/dependencies.json. A nova dependência saxes 6.0.0 declara ISC no pacote instalado; é um parser XML utilizado para importação delimitada com rejeição de DTD. xmlchars é dependência transitiva. Manter os avisos distribuídos pelos pacotes.

Rust: Cargo.toml e Cargo.lock fixam reqwest/rustls, HMAC/SHA256 e dependências. Cargo.lock não é um parecer de licenciamento: uma revisão completa de avisos e redistribuição continua necessária antes de publicação comercial.

Nmap não está embutido no pacote nem foi instalado por esta alteração. O adaptador requer executável fornecido/configurado pelo operador, com licença e versão conferidas. Consulte docs/ATTACKLAB.md para as fontes oficiais verificadas do adaptador.

Demais produtos citados na matriz não foram integrados. Seus nomes identificam referências funcionais; licenças e APIs precisam ser avaliadas antes de desenvolvimento de conectores específicos.


## Supervisor e pesquisa V11 — 02/11/2026

`packages/execution-engine/Cargo.lock` fixa serde/serde_json/sha2 e21 pacotes
externos resolvidos. Declarações de licença/versão/repositório extraídas de cargo
metadata: [execution-dependencies.json](docs/generated/execution-dependencies.json).
Predominam MIT/Apache-2.0; unicode-ident também declara Unicode-3.0. Preservar
avisos aplicáveis na distribuição. Inventário não substitui revisão de avisos,
advisories ou permissões de redistribuição; cargo audit local não estava disponível.

[Pesquisa projetos de referência autorizados](registro de pesquisa interno) fixa nove revisões e
separa licença observada de compatibilidade ainda não resolvida. Há AGPL,
repositórios sem licença identificada e, em Referência F, LICENSE AGPL junto de
license.md CC-BY-NC-SA. Nenhum código dessas referências foi incorporado, nem
instalado como dependência ou executado. O supervisor usa implementação própria
de conceitos gerais de integridade/resultado de processo. Qualquer incorporação
futura requer revisar a licença efetiva antes de tratá-la como permitida.
