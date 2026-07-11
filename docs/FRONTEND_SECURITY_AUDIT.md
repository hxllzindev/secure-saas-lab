# Frontend security pass — 2026-07-11

O frontend deixou de incluir credenciais de demonstração, modo vulnerável, Bearer token
em memória, CSRF token em JavaScript, nomes/emails/tenants, clientes, valores exatos,
notas livres, autores e identificadores de auditoria. O modo vulnerável permanece apenas
na API local controlada para preservar o objetivo educacional.

A sessão segura usa cookies HttpOnly e valida `Origin` mais Fetch Metadata nas escritas.
Respostas para a UI são projeções allowlisted: rótulo anônimo, papel, referência
sintética, status, data, faixa de valor e metadados de detecção sem ator/recurso.

`scripts/frontend-security-test.py` bloqueia regressões de credenciais embutidas,
tokens de navegador, campos brutos, sinks HTML, armazenamento persistente e padrões
comuns de segredo.
