# Roteiro de demonstracao

Duracao sugerida: 5 a 7 minutos.

## 1. Contexto

"Este e um SaaS financeiro multi-tenant com duas implementacoes do mesmo fluxo. A ideia e mostrar a vulnerabilidade, o impacto, a correcao e o teste de regressao."

## 2. Autenticacao

1. Abra o modo vulneravel.
2. Explique que mensagens diferentes permitem enumerar usuarios e que MFA nao e exigido.
3. Abra o modo seguro e entre com Ana.
4. Mostre os controles: MFA, rate limiting, cookies `HttpOnly`, CSRF e refresh rotativo.

## 3. BOLA

1. Consulte `inv-2001` no modo vulneravel.
2. Mostre que Ana, da Acme, recebe uma fatura da Orbit.
3. Repita no modo seguro.
4. Mostre o `404` e o evento `T1190` na auditoria.
5. Explique as duas barreiras: ownership na API e RLS no PostgreSQL.

## 4. Stored XSS

1. No modo vulneravel, publique `<strong>conteudo controlado</strong>`.
2. Mostre que o navegador interpreta HTML.
3. No modo seguro, repita e mostre que o conteudo aparece como texto.
4. Cite CSP como defesa adicional, nao substituta do encoding.

## 5. Evidencias

```bash
npm test
node scripts/verify-stack.mjs
```

Mostre os workflows e explique que o sink vulneravel foi isolado e documentado como risco aceito para o laboratorio.

## Fechamento

"O projeto conecta desenvolvimento, AppSec e operacao: eu consigo construir o produto, modelar as ameacas, implementar os controles e provar que eles continuam funcionando."
