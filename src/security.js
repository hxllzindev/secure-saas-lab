import {
  createHmac,
  createHash,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual
} from "node:crypto";

export const ACCESS_TOKEN_TTL_SECONDS = 5 * 60;
export const VULNERABLE_TOKEN_TTL_SECONDS = 20 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

function encode(value) {
  return Buffer.from(value).toString("base64url");
}

function decode(value) {
  return Buffer.from(value, "base64url").toString("utf8");
}

export function createTokenService(secret = randomBytes(32).toString("hex")) {
  function sign(payload) {
    const header = encode(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = encode(JSON.stringify(payload));
    const signature = createHmac("sha256", secret)
      .update(`${header}.${body}`)
      .digest("base64url");
    return `${header}.${body}.${signature}`;
  }

  function verify(token) {
    if (typeof token !== "string") return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [header, body, signature] = parts;
    const expected = createHmac("sha256", secret)
      .update(`${header}.${body}`)
      .digest();
    const received = Buffer.from(signature, "base64url");

    if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
      return null;
    }

    try {
      const payload = JSON.parse(decode(body));
      if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) return null;
      return payload;
    } catch {
      return null;
    }
  }

  return { sign, verify };
}

export function createOpaqueToken() {
  return randomBytes(32).toString("base64url");
}

export function hashOpaqueToken(token) {
  return createHash("sha256").update(token).digest("hex");
}

export function createCsrfToken() {
  return randomBytes(24).toString("base64url");
}

export function parseCookies(header = "") {
  const cookies = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) cookies[name] = decodeURIComponent(value);
  }
  return cookies;
}

export function cookieNames(production = false) {
  return production
    ? { access: "__Host-aegis_access", refresh: "__Secure-aegis_refresh" }
    : { access: "aegis_access", refresh: "aegis_refresh" };
}

export function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${options.path ?? "/"}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, options.maxAge)}`);
  if (options.httpOnly !== false) parts.push("HttpOnly");
  parts.push(`SameSite=${options.sameSite ?? "Strict"}`);
  if (options.secure) parts.push("Secure");
  return parts.join("; ");
}

export function verifyPassword(password, record) {
  if (typeof password !== "string" || !record) return false;
  const candidate = pbkdf2Sync(
    password,
    record.salt,
    record.iterations,
    32,
    "sha256"
  );
  const expected = Buffer.from(record.hash, "hex");
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

export function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function sanitizePlainText(value, maxLength = 280) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim()
    .slice(0, maxLength);
}

export function checkRateLimit(store, key, options = {}) {
  const limit = options.limit ?? 5;
  const windowMs = options.windowMs ?? 60_000;
  const now = Date.now();
  const recent = (store.loginAttempts.get(key) ?? []).filter(
    (timestamp) => now - timestamp < windowMs
  );

  if (recent.length >= limit) {
    store.loginAttempts.set(key, recent);
    return { allowed: false, retryAfter: Math.ceil((windowMs - (now - recent[0])) / 1000) };
  }

  recent.push(now);
  store.loginAttempts.set(key, recent);
  return { allowed: true, retryAfter: 0 };
}

export function clearRateLimit(store, key) {
  store.loginAttempts.delete(key);
}
