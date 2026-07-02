import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import { createApp, createConfiguredApp } from "../src/server.js";

let server;
let baseUrl;
let secureSession;
let vulnerableToken;

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers ?? {})
    }
  });
  const payload = response.headers.get("content-type")?.includes("application/json")
    ? await response.json()
    : await response.text();
  return { response, payload };
}

async function login(mode, overrides = {}) {
  return request(`/api/${mode}/login`, {
    method: "POST",
    body: JSON.stringify({
      email: "ana@acme.test",
      password: "Secure123!",
      mfaCode: "482911",
      ...overrides
    })
  });
}

function cookiesFrom(response) {
  return response.headers.getSetCookie()
    .map((cookie) => cookie.split(";", 1)[0])
    .join("; ");
}

function secureHeaders(session = secureSession, extra = {}) {
  return {
    Cookie: session.cookie,
    ...(session.csrfToken ? { "X-CSRF-Token": session.csrfToken } : {}),
    "X-Requested-With": "AegisLedger",
    ...extra
  };
}

before(async () => {
  const app = createApp({ tokenSecret: "test-secret-with-enough-entropy" });
  server = app.server;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  baseUrl = `http://127.0.0.1:${address.port}`;

  const secureLogin = await login("secure");
  secureSession = {
    cookie: cookiesFrom(secureLogin.response),
    csrfToken: secureLogin.payload.csrfToken
  };
  vulnerableToken = (await login("vulnerable", { mfaCode: "" })).payload.token;
});

after(async () => {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
});

test("serve a interface e aplica headers basicos", async () => {
  const response = await fetch(baseUrl);
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
});

test("o fluxo vulneravel permite enumerar usuarios", async () => {
  const unknown = await login("vulnerable", {
    email: "naoexiste@example.test",
    password: "qualquer"
  });
  const wrongPassword = await login("vulnerable", { password: "incorreta" });

  assert.equal(unknown.response.status, 404);
  assert.equal(unknown.payload.error, "Conta nao encontrada.");
  assert.equal(wrongPassword.response.status, 401);
  assert.equal(wrongPassword.payload.error, "Senha incorreta.");
});

test("o fluxo seguro usa resposta generica para credenciais invalidas", async () => {
  const unknown = await login("secure", {
    email: "outro@example.test",
    password: "qualquer",
    mfaCode: "000000"
  });
  const wrongPassword = await login("secure", {
    email: "caio@acme.test",
    password: "incorreta",
    mfaCode: "731204"
  });

  assert.equal(unknown.response.status, 401);
  assert.equal(wrongPassword.response.status, 401);
  assert.equal(unknown.payload.error, wrongPassword.payload.error);
});

test("MFA e obrigatorio apenas no fluxo seguro", async () => {
  const secure = await login("secure", { mfaCode: "" });
  const vulnerable = await login("vulnerable", { mfaCode: "" });

  assert.equal(secure.response.status, 401);
  assert.equal(vulnerable.response.status, 200);
});

test("a sessao segura usa cookies HttpOnly, SameSite e access token curto", async () => {
  const result = await login("secure");
  const cookies = result.response.headers.getSetCookie();

  assert.equal(result.response.status, 200);
  assert.equal(result.payload.token, undefined);
  assert.ok(result.payload.csrfToken);
  assert.equal(result.payload.expiresIn, 300);
  assert.equal(cookies.length, 2);
  assert.ok(cookies.every((cookie) => cookie.includes("HttpOnly")));
  assert.ok(cookies.every((cookie) => cookie.includes("SameSite=Strict")));
});

test("a sessao segura pode ser restaurada sem expor o access token", async () => {
  const { response, payload } = await request("/api/secure/session", {
    headers: secureHeaders()
  });

  assert.equal(response.status, 200);
  assert.equal(payload.user.email, "ana@acme.test");
  assert.equal(payload.csrfToken, secureSession.csrfToken);
  assert.equal(payload.token, undefined);
});

test("headers defensivos incluem uma Content Security Policy estrita", async () => {
  const response = await fetch(baseUrl);
  const policy = response.headers.get("content-security-policy");
  assert.match(policy, /default-src 'self'/);
  assert.match(policy, /frame-ancestors 'none'/);
  assert.doesNotMatch(policy, /unsafe-inline/);
});

test("producao rejeita TOKEN_SECRET ausente ou conhecido", async () => {
  await assert.rejects(
    () => createConfiguredApp({ NODE_ENV: "production" }),
    /TOKEN_SECRET must be set/
  );
  await assert.rejects(
    () => createConfiguredApp({
      NODE_ENV: "production",
      TOKEN_SECRET: ["local", "development", "secret", "change", "before", "deploy"].join("-")
    }),
    /TOKEN_SECRET must be set/
  );
});

test("producao aceita TOKEN_SECRET unico e forte", async () => {
  const app = await createConfiguredApp({
    NODE_ENV: "production",
    TOKEN_SECRET: "x".repeat(48)
  });

  await app.repository.close();
});

test("o fluxo vulneravel reproduz BOLA entre tenants", async () => {
  const { response, payload } = await request("/api/vulnerable/invoices/inv-2001", {
    headers: { Authorization: `Bearer ${vulnerableToken}` }
  });

  assert.equal(response.status, 200);
  assert.equal(payload.invoice.tenantId, "orbit");
});

test("o fluxo seguro bloqueia BOLA e oculta a existencia do recurso", async () => {
  const { response, payload } = await request("/api/secure/invoices/inv-2001", {
    headers: secureHeaders()
  });

  assert.equal(response.status, 404);
  assert.equal(payload.error, "Fatura nao encontrada.");
});

test("a listagem de faturas permanece isolada por tenant", async () => {
  for (const mode of ["vulnerable", "secure"]) {
    const headers = mode === "secure"
      ? secureHeaders()
      : { Authorization: `Bearer ${vulnerableToken}` };
    const { response, payload } = await request(`/api/${mode}/invoices`, {
      headers
    });
    assert.equal(response.status, 200);
    assert.ok(payload.invoices.every((invoice) => invoice.tenantId === "acme"));
  }
});

test("o fluxo seguro limita tentativas repetidas de login", async () => {
  let result;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    result = await login("secure", {
      email: "rate-limit@example.test",
      password: "incorreta",
      mfaCode: "000000"
    });
  }

  assert.equal(result.response.status, 429);
  assert.ok(Number(result.response.headers.get("retry-after")) > 0);
});

test("notas seguras recebem limite de tamanho no servidor", async () => {
  const { response, payload } = await request("/api/secure/notes", {
    method: "POST",
    headers: secureHeaders(),
    body: JSON.stringify({ content: "x".repeat(500) })
  });

  assert.equal(response.status, 201);
  assert.equal(payload.note.content.length, 280);
});

test("operacoes seguras de escrita rejeitam CSRF ausente", async () => {
  const { response, payload } = await request("/api/secure/notes", {
    method: "POST",
    headers: { Cookie: secureSession.cookie },
    body: JSON.stringify({ content: "nao deve ser criada" })
  });

  assert.equal(response.status, 403);
  assert.equal(payload.error, "Token CSRF invalido.");
});

test("auditoria segura registra uma tentativa BOLA negada", async () => {
  const { response, payload } = await request("/api/secure/audit", {
    headers: secureHeaders()
  });

  assert.equal(response.status, 200);
  assert.ok(payload.events.some((event) => (
    event.action === "invoice_access_denied" && event.resourceId === "inv-2001"
  )));
  const denied = payload.events.find((event) => event.action === "invoice_access_denied");
  assert.equal(denied.techniqueId, "T1190");
  assert.equal(denied.severity, "high");
});

test("refresh token e rotativo e reutilizacao revoga a familia", async () => {
  const freshLogin = await login("secure", { email: "caio@acme.test", mfaCode: "731204" });
  const originalCookie = cookiesFrom(freshLogin.response);

  const firstRefresh = await request("/api/secure/session/refresh", {
    method: "POST",
    headers: {
      Cookie: originalCookie,
      "X-Requested-With": "AegisLedger"
    }
  });
  assert.equal(firstRefresh.response.status, 200);
  assert.ok(firstRefresh.payload.csrfToken);
  assert.notEqual(cookiesFrom(firstRefresh.response), originalCookie);

  const reuse = await request("/api/secure/session/refresh", {
    method: "POST",
    headers: {
      Cookie: originalCookie,
      "X-Requested-With": "AegisLedger"
    }
  });
  assert.equal(reuse.response.status, 401);
  assert.match(reuse.payload.error, /reutilizacao/);
});
