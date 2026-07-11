# Security Report

Last verified: 2026-07-11

## Validated Controls

- Generic secure-login errors reduce account enumeration.
- MFA is required only in secure mode so the contrast is visible.
- Secure sessions use HttpOnly cookies instead of exposing access tokens to JavaScript.
- Refresh tokens rotate on refresh and reuse revokes the session family.
- Secure writes require CSRF protection.
- Secure invoice lookup blocks BOLA/IDOR and records audit evidence.
- Notes are normalized and length-limited in secure mode.
- Logout enforces the session CSRF token.
- Refresh rotation is serialized so concurrent replay cannot mint two valid replacements.
- Secure login applies both per-account and per-IP limits with bounded input.
- Production disables vulnerable routes unless the operator explicitly enables the isolated lab.
- Request bodies, JSON depth and signed-token length are bounded.

## Intentional Findings

| ID | Area | Vulnerable Behavior | Secure Behavior |
| --- | --- | --- | --- |
| F-01 | Authentication | User enumeration | Generic invalid credential response |
| F-02 | MFA | Missing MFA | MFA required |
| F-03 | Session | Bearer token in browser state | HttpOnly cookie |
| F-04 | CSRF | Missing write protection | CSRF header required |
| F-05 | BOLA | Cross-tenant invoice access | Tenant ownership enforced |

## Remediated Findings

| ID | Finding | Resolution |
| --- | --- | --- |
| S-01 | Vulnerable training endpoints were enabled by default in Production | Fail-closed production gate; explicit `ALLOW_INSECURE_LAB` opt-in and loopback-only Compose port |
| S-02 | Secure logout accepted a cookie without validating CSRF | CSRF is now mandatory and regression-tested |
| S-03 | Simultaneous refresh requests could race token rotation | Refresh-family mutation is atomic under a store lock; only one rotation succeeds |
| S-04 | Mutable in-memory audit, note, rate-limit and session state was accessed concurrently | Mutations and sensitive snapshots are synchronized |
| S-05 | Authentication inputs and bodies were broadly unbounded | 64 KiB body limit, JSON depth limit, login field bounds and 2 KiB token bound |

## Evidence

The xUnit suite in `test/SecureSaasLab.Tests` now passes 10/10 tests in the Linux .NET 10 SDK container, including CSRF logout, concurrent refresh and the production vulnerable-mode gate. The NuGet vulnerability audit reports no known vulnerable packages from the configured source. The hardened production container was also validated as non-root, read-only compatible, healthy, and returned `404` for `/api/vulnerable/*` without explicit opt-in.
