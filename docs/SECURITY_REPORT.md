# Security Assessment Report

## Resumo executivo

A avaliacao compara duas implementacoes dos mesmos fluxos. O ambiente vulneravel contem falhas intencionais para treinamento. O ambiente seguro aplica controles server-side e possui testes de regressao para os principais findings.

## Findings

### F-01: BOLA em consulta de fatura

- Severidade: Alta
- Referencia: OWASP API1 - Broken Object Level Authorization
- Endpoint vulneravel: `GET /api/vulnerable/invoices/:id`
- Impacto: um usuario autenticado pode consultar dados financeiros de outro tenant ao alterar o ID.
- Evidencia: a conta Acme recebe `200` ao consultar `inv-2001`, pertencente ao tenant Orbit.
- Correcao: o endpoint seguro compara `invoice.tenantId` com o tenant derivado do token e retorna `404` quando nao ha ownership.
- Regressao: `test/security.test.js` valida os dois comportamentos.

### F-02: Enumeracao de usuarios no login

- Severidade: Media
- Referencia: OWASP Authentication Failures
- Endpoint vulneravel: `POST /api/vulnerable/login`
- Impacto: respostas diferentes permitem descobrir contas validas.
- Evidencia: usuario inexistente retorna `404`, enquanto senha incorreta retorna `401` com outra mensagem.
- Correcao: o fluxo seguro retorna a mesma resposta para e-mail, senha ou MFA invalidos.

### F-03: Ausencia de MFA e rate limiting

- Severidade: Alta
- Endpoint vulneravel: `POST /api/vulnerable/login`
- Impacto: aumenta a viabilidade de credential stuffing e uso de credenciais vazadas.
- Correcao: o fluxo seguro exige segundo fator e bloqueia tentativas repetidas por IP e identidade durante uma janela de tempo.
- Limitacao conhecida: o rate limiter e local a instancia e deve usar Redis ou servico equivalente em producao.

### F-04: Stored XSS em notas

- Severidade: Alta
- Componente vulneravel: renderizacao de notas no frontend
- Impacto: HTML controlado pelo usuario e inserido no DOM com `innerHTML`.
- Correcao: o modo seguro usa `textContent`, remove caracteres de controle e aplica limite de tamanho no servidor.
- Observacao: validacao de entrada nao substitui output encoding contextual.

### F-05: Auditoria ausente no ambiente vulneravel

- Severidade: Baixa
- Impacto: reduz capacidade de investigacao e nao-repudio.
- Correcao: o ambiente seguro registra autenticacoes, consultas, negacoes e publicacao de notas. A consulta exige role administrativa e filtra o tenant.

### F-06: Sessao exposta ao JavaScript e sem rotacao

- Severidade: Alta
- Impacto: um token obtido por XSS permanece utilizavel ate expirar.
- Correcao: access token de cinco minutos em cookie `HttpOnly`, refresh token opaco armazenado como hash, rotacao a cada uso e revogacao da familia quando ha replay.

### F-07: Escritas sem protecao CSRF

- Severidade: Media
- Impacto: um site externo pode tentar induzir operacoes com a sessao da vitima.
- Correcao: `SameSite=Strict`, header customizado no refresh e token CSRF vinculado ao access token para operacoes autenticadas.

### F-08: Isolamento dependente apenas da aplicacao

- Severidade: Alta
- Impacto: uma regressao de query pode atravessar tenants.
- Correcao: papel PostgreSQL limitado, contexto transacional de tenant e policies Row-Level Security com `FORCE ROW LEVEL SECURITY`.

## Evidencias automatizadas

Execute:

```bash
node --test
```

Resultado esperado: 15 testes aprovados, incluindo BOLA, CSP, cookies, CSRF, refresh rotation, replay detection e MITRE.

## Priorizacao de remediacao

1. Garantir autorizacao por objeto em todas as rotas multi-tenant.
2. Remover renderizacao de HTML nao confiavel.
3. Reforcar autenticacao com MFA, mensagens uniformes e rate limiting distribuido.
4. Centralizar eventos de auditoria e alertas.
5. Adicionar banco com Row-Level Security como defesa adicional.
