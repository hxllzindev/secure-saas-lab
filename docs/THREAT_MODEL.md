# Threat Model

## Assets

- Demo tenant invoice data.
- Authentication and refresh sessions.
- Audit events.
- Security comparison logic between vulnerable and secure modes.

## Actors

- Demo user exploring expected workflows.
- Malicious tenant user attempting BOLA/IDOR.
- Attacker attempting credential enumeration or CSRF.
- Maintainer reviewing CI security gates.

## Abuse Cases

| Abuse Case | Vulnerable Mode | Secure Mode |
| --- | --- | --- |
| Enumerate accounts | Distinct login errors | Generic error |
| Skip MFA | Allowed | Blocked |
| Access another tenant invoice | Allowed by ID | Returns `404` |
| Write without CSRF | Allowed | Blocked |
| Reuse refresh token | Not modeled | Session family revoked |

## Trust Boundaries

- Browser to ASP.NET Core API.
- Secure-mode cookies and CSRF token.
- CI workflow supply chain through pinned GitHub Actions.

## Residual Risks

- Data is in memory for deterministic demos.
- MFA codes are static for portfolio usability.
- A production version would need persistent storage, OIDC, distributed rate limiting and managed secrets.
