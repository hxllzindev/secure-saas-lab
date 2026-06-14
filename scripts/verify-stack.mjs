const baseUrl = process.env.BASE_URL ?? "http://127.0.0.1:3000";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function json(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const payload = await response.json();
  return { response, payload };
}

function cookieHeader(response) {
  return response.headers.getSetCookie()
    .map((cookie) => cookie.split(";", 1)[0])
    .join("; ");
}

const health = await json("/api/health");
assert(health.response.status === 200, "Healthcheck failed");
assert(health.payload.database === "postgresql", "Application is not using PostgreSQL");

const secureLogin = await json("/api/secure/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    email: "ana@acme.test",
    password: "Secure123!",
    mfaCode: "482911"
  })
});
assert(secureLogin.response.status === 200, "Secure login failed");
assert(!secureLogin.payload.token, "Secure login exposed its access token");
const secureCookie = cookieHeader(secureLogin.response);

const secureBola = await json("/api/secure/invoices/inv-2001", {
  headers: { Cookie: secureCookie }
});
assert(secureBola.response.status === 404, "Secure endpoint allowed cross-tenant BOLA");

const secureNote = await json("/api/secure/notes", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Cookie: secureCookie,
    "X-CSRF-Token": secureLogin.payload.csrfToken
  },
  body: JSON.stringify({ content: "Stack verification evidence" })
});
assert(secureNote.response.status === 201, "CSRF-protected write failed");

const vulnerableLogin = await json("/api/vulnerable/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "ana@acme.test", password: "Secure123!" })
});
assert(vulnerableLogin.response.status === 200, "Vulnerable lab login failed");

const vulnerableBola = await json("/api/vulnerable/invoices/inv-2001", {
  headers: { Authorization: `Bearer ${vulnerableLogin.payload.token}` }
});
assert(vulnerableBola.response.status === 200, "Vulnerable lab no longer reproduces BOLA");
assert(vulnerableBola.payload.invoice.tenantId === "orbit", "Unexpected vulnerable resource");

console.log("Stack verified: PostgreSQL, secure controls, CSRF and vulnerable lab behavior.");
