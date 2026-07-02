# Portfolio Case Study

## Summary

I built a fullstack AppSec lab in ASP.NET Core/.NET 10 that compares vulnerable and secure SaaS behaviors side by side. The project demonstrates user enumeration, missing MFA, session abuse and BOLA/IDOR, then implements secure alternatives with MFA, HttpOnly cookies, refresh-token rotation, CSRF protection, tenant checks, audit events and automated security gates.

## Stack

`C#`, `ASP.NET Core`, `.NET 10`, `xUnit`, `Docker`, `GitHub Actions`, `Semgrep`, `CodeQL`, `Gitleaks`, `Trivy`, `OWASP ZAP`, `HTML`, `CSS`, `JavaScript`.

## What This Proves

- Secure API design in C#.
- Fullstack delivery with a browser UI.
- Understanding of OWASP API risks, especially BOLA.
- Ability to write regression tests for security controls.
- DevSecOps pipeline ownership beyond local development.

## Interview Pitch

I wanted a project that shows more than certificates. I built a SaaS-style AppSec lab where the same workflow exists in vulnerable and secure modes. In vulnerable mode, changing an invoice ID leaks another tenant's data. In secure mode, the API blocks it, records audit evidence and the behavior is covered by automated tests and CI security gates.
