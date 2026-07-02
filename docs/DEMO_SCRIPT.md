# Demo Script

## Setup

```bash
dotnet test SecureSaasLab.sln
TOKEN_SECRET="$(openssl rand -base64 48)" docker compose up -d --build
```

Open `http://127.0.0.1:3000`.

## Flow

1. Log in as `ana@acme.test` with password `Secure123!` and MFA `482911`.
2. Show that vulnerable login accepts the same credentials without MFA.
3. Query invoice `inv-2001` in vulnerable mode and show Orbit tenant data leaking to Acme.
4. Query the same invoice in secure mode and show `404`.
5. Create a secure note without CSRF and show the request blocked.
6. Open audit events and point to the denied BOLA attempt.

## Validation

```bash
dotnet test SecureSaasLab.sln
```

Expected result: all xUnit tests pass.
