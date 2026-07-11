# Security Policy

This repository is a portfolio AppSec lab. It intentionally contains a `vulnerable` mode so the secure controls can be compared against realistic failure modes.

## Supported Scope

- ASP.NET Core API and security controls in `src/SecureSaasLab.Api`
- Static frontend assets in `src/SecureSaasLab.Api/wwwroot`
- xUnit regression tests in `test/SecureSaasLab.Tests`
- GitHub Actions security gates

## Intentional Risk Areas

- The `vulnerable` mode demonstrates user enumeration, missing MFA and BOLA/IDOR.
- Production disables vulnerable API routes unless `ALLOW_INSECURE_LAB=true` is explicitly configured. The supplied Compose enables it only for a loopback-bound local demonstration.
- Demo credentials and seed data are fictitious. Credentials remain server-side and
  are not embedded or prefilled in the public frontend.
- The shipped UI exposes only secure mode. Vulnerable Bearer-token and raw-payload
  exercises remain API-only and gated for controlled local testing.
- Secure browser responses project anonymous workspace labels, amount bands and
  allowlisted audit metadata; email, tenant, customer, author, note content and raw
  resource identifiers are not sent to the UI.
- The current persistence layer is in memory for deterministic portfolio demos.

## Reporting

Do not publish exploitable details, credentials, tokens or personal data in a public issue. Contact the maintainer privately first with reproduction steps, expected impact and sanitized evidence.

## Personal-data incidents

Contain access, rotate affected credentials, preserve sanitized evidence, identify the data and tenants involved, and assess relevant risk or harm. When the LGPD and Resolução CD/ANPD nº 15/2024 require notification, communicate with the ANPD and affected data subjects within the applicable three-business-day period and retain the incident record for the regulatory period. This laboratory must never be populated with real personal data.
