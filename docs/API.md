# API

Base: `/api/:mode`, onde `mode` e `secure` ou `vulnerable`.

## Publicos

### `GET /api/health`

Retorna saude e adapter de banco ativo.

### `POST /api/:mode/login`

```json
{
  "email": "ana@acme.test",
  "password": "Secure123!",
  "mfaCode": "482911"
}
```

No modo seguro, define cookies `HttpOnly` e retorna `csrfToken`. No vulneravel, retorna bearer token no JSON.

## Sessao segura

### `GET /api/secure/session`

Restaura usuario e CSRF token usando o access cookie.

### `POST /api/secure/session/refresh`

Exige refresh cookie e `X-Requested-With: AegisLedger`. Rotaciona o token e devolve novo CSRF.

### `POST /api/secure/session/logout`

Exige access cookie e `X-CSRF-Token`. Revoga a familia de refresh tokens.

## Faturas

### `GET /api/:mode/invoices`

Lista somente faturas do tenant autenticado.

### `GET /api/:mode/invoices/:id`

- Secure: ownership check e RLS; outro tenant recebe `404`.
- Vulnerable: lookup deliberadamente cross-tenant.

## Notas

### `GET /api/:mode/notes`

Lista notas do tenant.

### `POST /api/:mode/notes`

```json
{ "content": "Revisar o contrato." }
```

No modo seguro exige CSRF, remove caracteres de controle e limita a 280 caracteres.

## Auditoria

### `GET /api/secure/audit`

Exige role `admin`. Retorna eventos do tenant atual com severidade e, quando aplicavel, tecnica MITRE ATT&CK.

## Codigos relevantes

| Status | Significado |
| --- | --- |
| `200` | Operacao concluida |
| `201` | Nota criada |
| `401` | Sessao ou credenciais invalidas |
| `403` | Role ou CSRF invalido |
| `404` | Recurso ausente ou nao autorizado |
| `413` | Corpo acima de 32 KiB |
| `422` | Entrada semanticamente invalida |
| `429` | Rate limit atingido |
