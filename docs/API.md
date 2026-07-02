# API

Base URL: `http://127.0.0.1:3000`

## Health

`GET /api/health`

Returns runtime status and stack metadata.

## Authentication

`POST /api/vulnerable/login`

Accepts email and password. This endpoint intentionally reveals different errors for missing users and wrong passwords.

`POST /api/secure/login`

Accepts email, password and `mfaCode`. Returns a CSRF token and sets HttpOnly cookies.

`POST /api/secure/session/refresh`

Requires `X-Requested-With: AegisLedger` and a refresh cookie. Rotates the refresh token and returns a new CSRF token.

## Resources

`GET /api/{mode}/session`

Returns the authenticated demo user.

`GET /api/{mode}/invoices`

Returns invoices for the authenticated tenant.

`GET /api/{mode}/invoices/{id}`

In `vulnerable` mode, this intentionally allows cross-tenant lookup. In `secure` mode, ownership is enforced and cross-tenant access returns `404`.

`GET /api/{mode}/notes`

Lists notes for the tenant.

`POST /api/{mode}/notes`

Creates a note. Secure mode requires a valid `X-CSRF-Token` header and truncates/sanitizes plain text.

`GET /api/secure/audit`

Admin-only audit view for secure-mode evidence.
