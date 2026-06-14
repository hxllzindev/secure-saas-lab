# Estudo de caso para portfolio

## Titulo sugerido

Secure SaaS Lab: construindo e protegendo uma aplicacao multi-tenant ponta a ponta

## Resumo curto

Desenvolvi um SaaS financeiro fullstack com ambientes vulneravel e seguro lado a lado. O laboratorio demonstra BOLA, stored XSS, enumeracao de usuarios e abuso de sessao, depois aplica MFA, CSRF, refresh token rotativo, auditoria MITRE e PostgreSQL Row-Level Security. A entrega inclui Docker e pipeline DevSecOps com testes, SAST, DAST, CodeQL, secret scan, container scan e SBOM.

## Problema

Aplicacoes multi-tenant precisam impedir que uma identidade autenticada atravesse a fronteira de outra organizacao. Uma simples validacao ausente em um endpoint pode expor dados financeiros mesmo quando login e criptografia existem.

## Solucao

- Modelei ativos, atores, fronteiras e ameacas com STRIDE.
- Implementei o mesmo produto em fluxos vulneravel e seguro.
- Derivei tenant e role exclusivamente da sessao assinada.
- Apliquei autorizacao por objeto e RLS como defesa em profundidade.
- Protegi sessoes com cookies `HttpOnly`, CSRF e rotacao de refresh token.
- Transformei eventos de seguranca em auditoria associada ao MITRE ATT&CK.
- Automatizei regressao e gates de seguranca no CI.

## Evidencias mensuraveis

- 15 testes automatizados de seguranca
- 2 tenants e 3 perfis de usuario
- 2 camadas independentes de isolamento de dados
- 7 categorias de verificacao no pipeline
- Zero dependencias vulneraveis reportadas no build local
- Container sem root, sem capabilities e com filesystem read-only

## Competencias demonstradas

`Node.js`, `JavaScript`, `PostgreSQL`, `Docker`, `AppSec`, `OWASP`, `MITRE ATT&CK`, `Threat Modeling`, `DevSecOps`, `CI/CD`, `SAST`, `DAST`, `API Security`, `RBAC`, `RLS`.

## Pitch de entrevista

"Eu queria um projeto que nao dependesse apenas de certificados. Criei um SaaS multi-tenant funcional e usei o proprio produto para demonstrar falhas reais. O ponto mais importante e a BOLA: no modo vulneravel, trocar o ID revela uma fatura de outro tenant; no seguro, a API bloqueia e o PostgreSQL RLS funciona como segunda barreira. Depois transformei essa tentativa em evento MITRE e cobri tudo com testes e pipeline."

## Bullet para curriculo

Desenvolvi laboratorio AppSec fullstack multi-tenant com Node.js/PostgreSQL, implementando MFA, sessoes rotativas, CSRF, RBAC/RLS, auditoria MITRE e pipeline DevSecOps com SAST, DAST, CodeQL, Trivy, Gitleaks e SBOM.
