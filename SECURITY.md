# Security Policy

## Escopo

O repositorio contem vulnerabilidades intencionais exclusivamente sob o modo `vulnerable`. Elas existem para demonstracao educacional com dados ficticios.

Achados no modo `secure`, no pipeline, nas migrations, no container ou que escapem do isolamento esperado sao considerados validos.

## Reporte

Nao abra publicamente um exploit que afete uma implantacao real. Envie um relato privado ao mantenedor contendo:

- componente e versao afetados
- pre-condicoes
- passos minimos para reproducao
- impacto observado
- sugestao de correcao, quando disponivel

## Uso responsavel

- Execute o laboratorio apenas em ambiente controlado.
- Nao conecte dados ou credenciais reais.
- Nao publique o modo vulneravel em uma rede nao confiavel.
- Use as tecnicas somente em sistemas proprios ou com autorizacao explicita.

## Riscos aceitos

- `src/public/vulnerable-lab.js` contem um sink HTML intencional.
- A funcao PostgreSQL `lab.lookup_invoice_unsafe` existe apenas para reproduzir BOLA.
- Credenciais em `compose.yaml` sao exclusivas do banco local nao publicado.
