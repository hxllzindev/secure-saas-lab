import { createServer as createHttpServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { createStore } from "./data.js";
import { enrichAuditEvent } from "./detections.js";
import { createMemoryRepository } from "./repositories/memory.js";
import { createPostgresRepository } from "./repositories/postgres.js";
import {
  ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_SECONDS,
  VULNERABLE_TOKEN_TTL_SECONDS,
  checkRateLimit,
  clearRateLimit,
  cookieNames,
  createCsrfToken,
  createOpaqueToken,
  createTokenService,
  hashOpaqueToken,
  normalizeEmail,
  parseCookies,
  sanitizePlainText,
  serializeCookie,
  verifyPassword
} from "./security.js";

const PUBLIC_DIR = fileURLToPath(new URL("./public", import.meta.url));
const MAX_BODY_BYTES = 32 * 1024;
const MODES = new Set(["vulnerable", "secure"]);
const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml"
};

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...extraHeaders
  });
  res.end(body);
}

async function readJson(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error("PAYLOAD_TOO_LARGE");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    const error = new Error("INVALID_JSON");
    error.statusCode = 400;
    throw error;
  }
}

function requestIp(req) {
  return req.socket.remoteAddress ?? "unknown";
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    tenantId: user.tenantId,
    tenantName: user.tenantName
  };
}

async function audit(repository, event) {
  return repository.addAuditEvent(enrichAuditEvent(event));
}

function issueVulnerableSession(tokenService, user) {
  const now = Math.floor(Date.now() / 1000);
  const token = tokenService.sign({
    sub: user.id,
    tenantId: user.tenantId,
    role: user.role,
    mode: "vulnerable",
    type: "access",
    iat: now,
    exp: now + VULNERABLE_TOKEN_TTL_SECONDS
  });
  return { token, expiresIn: VULNERABLE_TOKEN_TTL_SECONDS, user: publicUser(user) };
}

function sessionCookies(config, accessToken, refreshToken) {
  const names = cookieNames(config.production);
  return [
    serializeCookie(names.access, accessToken, {
      maxAge: ACCESS_TOKEN_TTL_SECONDS,
      secure: config.production,
      path: "/"
    }),
    serializeCookie(names.refresh, refreshToken, {
      maxAge: REFRESH_TOKEN_TTL_SECONDS,
      secure: config.production,
      path: "/api/secure/session"
    })
  ];
}

function clearSessionCookies(config) {
  const names = cookieNames(config.production);
  return [
    serializeCookie(names.access, "", { maxAge: 0, secure: config.production, path: "/" }),
    serializeCookie(names.refresh, "", {
      maxAge: 0,
      secure: config.production,
      path: "/api/secure/session"
    })
  ];
}

async function issueSecureSession(repository, tokenService, config, user, req, familyId = randomUUID()) {
  const now = Math.floor(Date.now() / 1000);
  const csrfToken = createCsrfToken();
  const refreshToken = createOpaqueToken();
  const tokenHash = hashOpaqueToken(refreshToken);
  const accessToken = tokenService.sign({
    sub: user.id,
    tenantId: user.tenantId,
    role: user.role,
    mode: "secure",
    type: "access",
    familyId,
    csrf: csrfToken,
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS
  });

  await repository.createRefreshSession({
    tokenHash,
    familyId,
    userId: user.id,
    tenantId: user.tenantId,
    expiresAt: new Date((now + REFRESH_TOKEN_TTL_SECONDS) * 1000).toISOString(),
    revokedAt: null,
    replacedByHash: null,
    userAgent: String(req.headers["user-agent"] ?? "unknown").slice(0, 300),
    ip: requestIp(req)
  });

  return {
    payload: {
      expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      csrfToken,
      user: publicUser(user)
    },
    cookies: sessionCookies(config, accessToken, refreshToken),
    refreshToken,
    tokenHash,
    familyId
  };
}

async function authenticate(req, mode, repository, tokenService, config) {
  const authorization = req.headers.authorization ?? "";
  const cookies = parseCookies(req.headers.cookie);
  const names = cookieNames(config.production);
  const bearer = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const token = mode === "secure" ? cookies[names.access] : bearer;
  const payload = tokenService.verify(token);
  if (!payload || payload.mode !== mode || payload.type !== "access") return null;
  const user = await repository.findUserById(payload.sub);
  if (!user || user.tenantId !== payload.tenantId || user.role !== payload.role) return null;
  return { user, payload };
}

function validateCsrf(req, session) {
  if (!UNSAFE_METHODS.has(req.method)) return true;
  const provided = req.headers["x-csrf-token"];
  return typeof provided === "string" && provided === session.payload.csrf;
}

async function login(req, res, mode, repository, store, tokenService, config) {
  const body = await readJson(req);
  const email = normalizeEmail(body.email);
  const user = await repository.findUserByEmail(email);
  const ip = requestIp(req);

  if (mode === "vulnerable") {
    if (!user) {
      await audit(repository, { action: "login_failed", mode, email, ip, reason: "user_not_found" });
      return sendJson(res, 404, { error: "Conta nao encontrada." });
    }
    if (!verifyPassword(body.password, user.password)) {
      await audit(repository, { action: "login_failed", mode, email, ip, reason: "wrong_password", tenantId: user.tenantId });
      return sendJson(res, 401, { error: "Senha incorreta." });
    }
    await audit(repository, { action: "login_success", mode, email, ip, tenantId: user.tenantId, actor: user.name });
    return sendJson(res, 200, issueVulnerableSession(tokenService, user));
  }

  const rateKey = `${ip}:${email || "missing"}`;
  const rate = checkRateLimit(store, rateKey);
  if (!rate.allowed) {
    await audit(repository, { action: "login_blocked", mode, email, ip, reason: "rate_limit", tenantId: user?.tenantId });
    return sendJson(res, 429, { error: "Nao foi possivel autenticar. Tente novamente mais tarde." }, { "Retry-After": String(rate.retryAfter) });
  }

  const passwordValid = user ? verifyPassword(body.password, user.password) : false;
  const mfaValid = user ? body.mfaCode === user.mfaCode : false;
  if (!user || !passwordValid || !mfaValid) {
    await audit(repository, { action: "login_failed", mode, email, ip, reason: "invalid_credentials", tenantId: user?.tenantId });
    return sendJson(res, 401, { error: "Credenciais invalidas." });
  }

  clearRateLimit(store, rateKey);
  const session = await issueSecureSession(repository, tokenService, config, user, req);
  await audit(repository, { action: "login_success", mode, email, ip, tenantId: user.tenantId, actor: user.name });
  return sendJson(res, 200, session.payload, { "Set-Cookie": session.cookies });
}

async function refreshSession(req, res, repository, tokenService, config) {
  if (req.headers["x-requested-with"] !== "AegisLedger") {
    return sendJson(res, 403, { error: "Requisicao de refresh rejeitada." });
  }

  const names = cookieNames(config.production);
  const refreshToken = parseCookies(req.headers.cookie)[names.refresh];
  if (!refreshToken) return sendJson(res, 401, { error: "Refresh token ausente." });

  const tokenHash = hashOpaqueToken(refreshToken);
  const replacementToken = createOpaqueToken();
  const replacementHash = hashOpaqueToken(replacementToken);
  const current = await repository.findRefreshSession(tokenHash);
  const userId = current?.userId;
  const user = userId ? await repository.findUserById(userId) : null;

  if (!current || !user) {
    await audit(repository, { action: "refresh_failed", mode: "secure", ip: requestIp(req), reason: "unknown_token" });
    return sendJson(res, 401, { error: "Sessao nao pode ser renovada." }, { "Set-Cookie": clearSessionCookies(config) });
  }

  const now = Math.floor(Date.now() / 1000);
  const replacement = {
    tokenHash: replacementHash,
    familyId: current.familyId,
    userId: user.id,
    tenantId: user.tenantId,
    expiresAt: new Date((now + REFRESH_TOKEN_TTL_SECONDS) * 1000).toISOString(),
    revokedAt: null,
    replacedByHash: null,
    userAgent: String(req.headers["user-agent"] ?? "unknown").slice(0, 300),
    ip: requestIp(req)
  };
  const rotation = await repository.consumeRefreshSession(tokenHash, replacement);
  if (rotation.status !== "rotated") {
    await audit(repository, { action: "refresh_reuse_detected", mode: "secure", tenantId: current.tenantId, ip: requestIp(req), severity: "high" });
    return sendJson(res, 401, { error: "Sessao revogada por reutilizacao de token." }, { "Set-Cookie": clearSessionCookies(config) });
  }

  const csrfToken = createCsrfToken();
  const accessToken = tokenService.sign({
    sub: user.id,
    tenantId: user.tenantId,
    role: user.role,
    mode: "secure",
    type: "access",
    familyId: current.familyId,
    csrf: csrfToken,
    iat: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS
  });
  await audit(repository, { action: "session_refreshed", mode: "secure", actor: user.name, tenantId: user.tenantId, ip: requestIp(req) });
  return sendJson(res, 200, { csrfToken, expiresIn: ACCESS_TOKEN_TTL_SECONDS, user: publicUser(user) }, {
    "Set-Cookie": sessionCookies(config, accessToken, replacementToken)
  });
}

async function serveStatic(res, pathname) {
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const safeRelative = normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  const filePath = join(PUBLIC_DIR, safeRelative);
  try {
    const file = await readFile(filePath);
    res.writeHead(200, {
      "Content-Type": contentTypes[extname(filePath)] ?? "application/octet-stream",
      "Content-Length": file.length,
      "Cache-Control": "no-cache"
    });
    res.end(file);
  } catch {
    sendJson(res, 404, { error: "Recurso nao encontrado." });
  }
}

async function handleApi(req, res, url, repository, store, tokenService, config) {
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments[1] === "health") {
    return sendJson(res, 200, { status: "ok", database: config.database });
  }

  const mode = segments[1];
  if (!MODES.has(mode)) return sendJson(res, 404, { error: "Modo desconhecido." });

  if (req.method === "POST" && segments[2] === "login") {
    return login(req, res, mode, repository, store, tokenService, config);
  }
  if (mode === "secure" && req.method === "POST" && segments[2] === "session" && segments[3] === "refresh") {
    return refreshSession(req, res, repository, tokenService, config);
  }

  const session = await authenticate(req, mode, repository, tokenService, config);
  if (!session) return sendJson(res, 401, { error: "Sessao invalida ou expirada." });

  if (mode === "secure" && !validateCsrf(req, session)) {
    await audit(repository, { action: "csrf_blocked", mode, actor: session.user.name, tenantId: session.user.tenantId, ip: requestIp(req) });
    return sendJson(res, 403, { error: "Token CSRF invalido." });
  }

  const { user } = session;
  if (req.method === "GET" && segments[2] === "session") {
    return sendJson(res, 200, {
      user: publicUser(user),
      mode,
      ...(mode === "secure" ? { csrfToken: session.payload.csrf } : {})
    });
  }

  if (mode === "secure" && req.method === "POST" && segments[2] === "session" && segments[3] === "logout") {
    await repository.revokeRefreshFamily(session.payload.familyId);
    await audit(repository, { action: "logout", mode, actor: user.name, tenantId: user.tenantId, ip: requestIp(req) });
    return sendJson(res, 200, { ok: true }, { "Set-Cookie": clearSessionCookies(config) });
  }

  if (segments[2] === "invoices") {
    if (req.method === "GET" && segments.length === 3) {
      return sendJson(res, 200, { invoices: await repository.listInvoices(user.tenantId) });
    }
    if (req.method === "GET" && segments[3]) {
      const invoice = await repository.findInvoiceById(segments[3], user.tenantId, mode === "vulnerable");
      await audit(repository, {
        action: invoice ? "invoice_viewed" : "invoice_access_denied",
        mode,
        actor: user.name,
        tenantId: user.tenantId,
        resourceId: segments[3],
        ip: requestIp(req)
      });
      if (!invoice) return sendJson(res, 404, { error: "Fatura nao encontrada." });
      return sendJson(res, 200, { invoice });
    }
  }

  if (segments[2] === "notes") {
    if (req.method === "GET") {
      return sendJson(res, 200, { notes: await repository.listNotes(user.tenantId) });
    }
    if (req.method === "POST") {
      const body = await readJson(req);
      const content = mode === "secure" ? sanitizePlainText(body.content) : String(body.content ?? "").slice(0, 2_000);
      if (!content) return sendJson(res, 422, { error: "A nota nao pode ficar vazia." });
      const note = await repository.createNote({ tenantId: user.tenantId, author: user.name, content });
      await audit(repository, { action: "note_created", mode, actor: user.name, tenantId: user.tenantId, resourceId: note.id, ip: requestIp(req) });
      return sendJson(res, 201, { note });
    }
  }

  if (req.method === "GET" && segments[2] === "audit") {
    if (mode !== "secure" || user.role !== "admin") return sendJson(res, 403, { error: "Permissao insuficiente." });
    return sendJson(res, 200, { events: await repository.listAuditEvents(user.tenantId, 30) });
  }

  return sendJson(res, 404, { error: "Endpoint nao encontrado." });
}

export function createApp(options = {}) {
  const store = options.store ?? createStore();
  const repository = options.repository ?? createMemoryRepository(store);
  const tokenService = options.tokenService ?? createTokenService(options.tokenSecret);
  const config = {
    production: options.production ?? false,
    database: options.database ?? "memory"
  };

  const server = createHttpServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    try {
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname.startsWith("/api/")) await handleApi(req, res, url, repository, store, tokenService, config);
      else await serveStatic(res, url.pathname);
    } catch (error) {
      const status = error.statusCode ?? 500;
      const message = status === 500 ? "Erro interno do servidor." : error.message;
      if (!res.headersSent) sendJson(res, status, { error: message });
      else res.end();
    }
  });

  return { server, store, repository };
}

export async function createConfiguredApp(env = process.env) {
  if (env.NODE_ENV === "production" && (!env.TOKEN_SECRET || env.TOKEN_SECRET.length < 32)) {
    throw new Error("TOKEN_SECRET must contain at least 32 characters in production.");
  }
  if (!env.DATABASE_URL) return createApp({ production: env.NODE_ENV === "production" });
  const repository = await createPostgresRepository(env.DATABASE_URL);
  return createApp({
    repository,
    production: env.NODE_ENV === "production",
    database: "postgresql",
    tokenSecret: env.TOKEN_SECRET
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number.parseInt(process.env.PORT ?? "3000", 10);
  const { server, repository } = await createConfiguredApp();
  server.listen(port, "0.0.0.0", () => {
    console.log(`Secure SaaS Lab: http://127.0.0.1:${port}`);
  });

  async function shutdown() {
    server.close(async () => {
      await repository.close();
      process.exit(0);
    });
  }

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
