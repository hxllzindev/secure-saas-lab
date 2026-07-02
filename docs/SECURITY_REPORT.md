# Security Report

## Validated Controls

- Generic secure-login errors reduce account enumeration.
- MFA is required only in secure mode so the contrast is visible.
- Secure sessions use HttpOnly cookies instead of exposing access tokens to JavaScript.
- Refresh tokens rotate on refresh and reuse revokes the session family.
- Secure writes require CSRF protection.
- Secure invoice lookup blocks BOLA/IDOR and records audit evidence.
- Notes are normalized and length-limited in secure mode.

## Intentional Findings

| ID | Area | Vulnerable Behavior | Secure Behavior |
| --- | --- | --- | --- |
| F-01 | Authentication | User enumeration | Generic invalid credential response |
| F-02 | MFA | Missing MFA | MFA required |
| F-03 | Session | Bearer token in browser state | HttpOnly cookie |
| F-04 | CSRF | Missing write protection | CSRF header required |
| F-05 | BOLA | Cross-tenant invoice access | Tenant ownership enforced |

## Evidence

The xUnit suite in `test/SecureSaasLab.Tests` covers the behaviors above, and GitHub Actions runs build, test, SAST, secret scanning, container scanning, SBOM and smoke checks.
