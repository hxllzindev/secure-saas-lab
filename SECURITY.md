# Security Policy

This repository is a portfolio AppSec lab. It intentionally contains a `vulnerable` mode so the secure controls can be compared against realistic failure modes.

## Supported Scope

- ASP.NET Core API and security controls in `src/SecureSaasLab.Api`
- Static frontend assets in `src/SecureSaasLab.Api/wwwroot`
- xUnit regression tests in `test/SecureSaasLab.Tests`
- GitHub Actions security gates

## Intentional Risk Areas

- The `vulnerable` mode demonstrates user enumeration, missing MFA and BOLA/IDOR.
- Demo credentials and seed data are fictitious.
- The current persistence layer is in memory for deterministic portfolio demos.

## Reporting

Open a GitHub issue with reproduction steps, expected impact and the affected route or file. Do not include real credentials, tokens or customer data.
