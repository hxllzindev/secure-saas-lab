# Secure SaaS Lab

Laboratorio fullstack de AppSec em **ASP.NET Core/.NET 10** que apresenta o mesmo SaaS financeiro multi-tenant em dois ambientes: `vulnerable` e `secure`. O objetivo e demonstrar exploracao, impacto, correcao, defesa em profundidade e evidencia automatizada no mesmo repositorio.

## O que este projeto prova

- Backend C# com ASP.NET Core Minimal APIs
- Interface web estatica servida pelo proprio app .NET
- Login vulneravel com enumeracao de usuario para demonstracao controlada
- Login seguro com resposta generica, MFA e rate limiting
- Sessao segura com cookie `HttpOnly`, CSRF e refresh token rotativo
- BOLA/IDOR reproduzido no ambiente vulneravel e bloqueado no seguro
- Auditoria por tenant com mapeamento MITRE ATT&CK
- Testes xUnit cobrindo controles de seguranca
- CI DevSecOps com build/test .NET, Semgrep C#, CodeQL, Gitleaks, Trivy, SBOM e DAST

## Inicio rapido

Requer .NET 10 SDK:

```bash
dotnet restore SecureSaasLab.sln
dotnet run --project src/SecureSaasLab.Api/SecureSaasLab.Api.csproj
```

Acesse `http://127.0.0.1:3000`.

Com Docker:

```bash
TOKEN_SECRET="$(openssl rand -base64 48)" docker compose up -d --build
```

O Compose publica a porta somente em `127.0.0.1` e habilita explicitamente o laboratório inseguro. Em qualquer implantação real, não defina `ALLOW_INSECURE_LAB`; no ambiente `Production`, as rotas vulneráveis ficam desabilitadas por padrão.

## Testes

```bash
dotnet test SecureSaasLab.sln
```

## Credenciais de demonstracao

```text
E-mail: ana@acme.test
Senha:  Secure123!
MFA:    482911
Tenant: Acme Health
Role:   admin
```

Use `inv-2001` na consulta de fatura. A conta Acme recebe dados da Orbit no ambiente vulneravel. No ambiente seguro, recebe `404`; o evento e auditado como MITRE `T1190`.

## Estrutura

```text
src/SecureSaasLab.Api/       API ASP.NET Core, regras de seguranca e UI em wwwroot
test/SecureSaasLab.Tests/    Testes xUnit de AppSec
.github/workflows/          CI, CodeQL e DAST
docs/                       Evidencias e documentacao tecnica
```

## Limites conscientes

- Dados e credenciais sao ficticios.
- MFA usa codigo estatico para facilitar a demonstracao; producao usaria TOTP ou WebAuthn.
- O armazenamento atual e em memoria para manter a demo simples e deterministica.
- O rate limiter em memoria deve ser substituido por Redis em multiplas instancias.
- O modo vulneravel deve permanecer isolado e nunca ser publicado com dados reais.
- Nenhum nome, e-mail, documento ou dado financeiro real deve ser usado nesta demonstração; consulte [PRIVACY.md](PRIVACY.md).
