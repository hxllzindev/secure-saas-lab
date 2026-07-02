# Runbook

## Local Tests

```bash
dotnet test SecureSaasLab.sln
```

## Docker Run

```bash
TOKEN_SECRET="$(openssl rand -base64 48)" docker compose up -d --build
curl --fail http://127.0.0.1:3000/api/health
docker compose down
```

## Common Issues

### Missing .NET runtime

The project targets `.NET 10`. Install or select a .NET 10 SDK/runtime if `dotnet test` says `Microsoft.NETCore.App` is missing.

### Production token secret

Production Docker runs require `TOKEN_SECRET` with at least 32 characters.

### GitHub language mix

This is expected. The backend is C#, while the frontend lives in `wwwroot` as HTML/CSS/JavaScript.
