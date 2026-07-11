"use strict";

const state = { user: null, invoices: [], events: [] };
const elements = {
  authSection: document.querySelector("#auth-section"),
  dashboard: document.querySelector("#dashboard"),
  loginForm: document.querySelector("#login-form"),
  loginMessage: document.querySelector("#login-message"),
  banner: document.querySelector("#environment-banner"),
  userChip: document.querySelector("#user-chip"),
  logoutButton: document.querySelector("#logout-button"),
  invoiceTable: document.querySelector("#invoice-table"),
  invoiceCount: document.querySelector("#invoice-count"),
  invoiceLookupForm: document.querySelector("#invoice-lookup-form"),
  invoiceResult: document.querySelector("#invoice-result"),
  auditList: document.querySelector("#audit-list"),
  refreshAudit: document.querySelector("#refresh-audit"),
  controlList: document.querySelector("#control-list"),
  metricTotal: document.querySelector("#metric-total"),
  metricPending: document.querySelector("#metric-pending"),
  metricEvents: document.querySelector("#metric-events"),
  metricPosture: document.querySelector("#metric-posture"),
  metricMode: document.querySelector("#metric-mode"),
  toast: document.querySelector("#toast")
};

const dateTime = new Intl.DateTimeFormat("pt-BR", {
  day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
});

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.remove("hidden");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.add("hidden"), 3200);
}

async function refreshSession() {
  const response = await fetch("/api/secure/session/refresh", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Requested-With": "AegisLedger" }
  });
  if (!response.ok) return false;
  const payload = await response.json();
  state.user = payload.user;
  renderUser();
  return true;
}

async function api(path, options = {}, retry = true) {
  const response = await fetch(`/api/secure${path}`, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "AegisLedger",
      ...(options.headers ?? {})
    }
  });
  const payload = await response.json().catch(() => ({}));
  if (response.status === 401 && state.user && retry && !path.includes("/refresh")) {
    if (await refreshSession()) return api(path, options, false);
  }
  if (!response.ok) {
    const safeMessage = response.status === 401
      ? "Sessao invalida ou expirada."
      : response.status === 403
        ? "Operacao nao permitida."
        : response.status === 404
          ? "Registro sintetico nao encontrado."
          : "Operacao indisponivel.";
    throw new Error(safeMessage);
  }
  return payload;
}

function resetSession() {
  state.user = null;
  state.invoices = [];
  state.events = [];
  elements.authSection.classList.remove("hidden");
  elements.dashboard.classList.add("hidden");
  elements.logoutButton.classList.add("hidden");
  elements.userChip.replaceChildren();
  const avatar = document.createElement("span");
  const labels = document.createElement("span");
  const title = document.createElement("strong");
  const subtitle = document.createElement("small");
  avatar.className = "avatar";
  avatar.textContent = "WD";
  title.textContent = "Visitante";
  subtitle.textContent = "Sem sessao";
  labels.append(title, subtitle);
  elements.userChip.append(avatar, labels);
  elements.loginMessage.textContent = "";
}

function renderUser() {
  elements.userChip.replaceChildren();
  const avatar = document.createElement("span");
  const labels = document.createElement("span");
  const title = document.createElement("strong");
  const subtitle = document.createElement("small");
  avatar.className = "avatar";
  avatar.textContent = "WD";
  title.textContent = state.user?.displayLabel ?? "Workspace de demonstracao";
  subtitle.textContent = state.user?.role === "admin" ? "Perfil administrativo" : "Perfil de leitura";
  labels.append(title, subtitle);
  elements.userChip.append(avatar, labels);
  elements.logoutButton.classList.remove("hidden");
}

function statusText(status) {
  return { paid: "Pago", pending: "Pendente", overdue: "Vencido" }[status] ?? "Desconhecido";
}

function safeDate(value, withTime = false) {
  const parsed = new Date(withTime ? value : `${value}T12:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return "Indisponivel";
  return withTime ? dateTime.format(parsed) : parsed.toLocaleDateString("pt-BR", { timeZone: "UTC" });
}

function renderInvoices() {
  elements.invoiceTable.replaceChildren();
  for (const invoice of state.invoices.slice(0, 100)) {
    const row = document.createElement("tr");
    const id = document.createElement("td");
    const due = document.createElement("td");
    const status = document.createElement("td");
    const band = document.createElement("td");
    const badge = document.createElement("span");
    id.className = "table-id";
    id.textContent = String(invoice.id ?? "").slice(0, 32);
    due.textContent = safeDate(invoice.dueDate);
    badge.className = ["paid", "pending", "overdue"].includes(invoice.status)
      ? `badge badge-${invoice.status}` : "badge";
    badge.textContent = statusText(invoice.status);
    status.appendChild(badge);
    band.textContent = ["Faixa A", "Faixa B", "Faixa C"].includes(invoice.amountBand)
      ? invoice.amountBand : "Indisponivel";
    row.append(id, due, status, band);
    elements.invoiceTable.appendChild(row);
  }
  elements.invoiceCount.textContent = `${state.invoices.length} registros sinteticos`;
}

function actionLabel(action) {
  return {
    login_success: "Login concluido", login_failed: "Falha de autenticacao",
    login_blocked: "Login bloqueado", invoice_viewed: "Fatura consultada",
    invoice_access_denied: "Acesso negado", csrf_blocked: "Origem bloqueada",
    session_refreshed: "Sessao renovada", refresh_reuse_detected: "Reutilizacao detectada",
    refresh_failed: "Falha ao renovar sessao", logout: "Sessao encerrada"
  }[action] ?? "Evento de seguranca";
}

function renderAudit() {
  elements.auditList.replaceChildren();
  if (state.events.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "Nenhum evento sintetico disponivel.";
    elements.auditList.appendChild(empty);
    return;
  }
  for (const event of state.events.slice(0, 30)) {
    const item = document.createElement("article");
    const detail = document.createElement("div");
    const title = document.createElement("strong");
    const description = document.createElement("p");
    const mode = document.createElement("span");
    const detection = document.createElement("span");
    item.className = "audit-item";
    title.textContent = actionLabel(event.action);
    description.textContent = safeDate(event.createdAt, true);
    mode.className = "event-mode";
    mode.textContent = "secure";
    const severity = ["info", "low", "medium", "high"].includes(event.severity) ? event.severity : "info";
    detection.className = `detection-label severity-${severity}`;
    detection.textContent = ["T1078", "T1190"].includes(event.techniqueId) ? event.techniqueId : severity;
    detail.append(detection, title, description);
    item.append(detail, mode);
    elements.auditList.appendChild(item);
  }
}

function renderControls() {
  const controls = [
    "Autenticacao multifator", "Rate limiting no login", "Autorizacao por tenant",
    "PostgreSQL Row-Level Security", "Cookies HttpOnly e SameSite", "Refresh rotativo",
    "Validacao de mesma origem", "Output encoding", "Auditoria administrativa"
  ];
  elements.controlList.replaceChildren();
  for (const label of controls) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    const status = document.createElement("span");
    name.textContent = label;
    status.textContent = "Ativo";
    status.className = "control-state";
    item.append(name, status);
    elements.controlList.appendChild(item);
  }
}

function renderMetrics() {
  elements.metricTotal.textContent = String(state.invoices.length);
  elements.metricPending.textContent = String(state.invoices.filter((invoice) => invoice.status !== "paid").length);
  elements.metricEvents.textContent = String(state.events.length);
  elements.metricPosture.textContent = "Protegida";
  elements.metricMode.textContent = "Ambiente seguro";
}

async function loadInvoices() {
  const payload = await api("/invoices");
  state.invoices = Array.isArray(payload.invoices) ? payload.invoices : [];
  renderInvoices();
}

async function loadAudit() {
  if (state.user?.role !== "admin") {
    state.events = [];
  } else {
    try {
      const payload = await api("/audit");
      state.events = Array.isArray(payload.events) ? payload.events : [];
    } catch {
      state.events = [];
      showToast("Auditoria indisponivel.");
    }
  }
  renderAudit();
  renderMetrics();
}

async function loadDashboard() {
  await loadInvoices();
  await loadAudit();
  renderMetrics();
}

elements.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.loginMessage.textContent = "Autenticando...";
  const form = new FormData(elements.loginForm);
  try {
    const session = await api("/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.get("email"), password: form.get("password"), mfaCode: form.get("mfaCode")
      })
    });
    state.user = session.user;
    elements.loginForm.reset();
    elements.authSection.classList.add("hidden");
    elements.dashboard.classList.remove("hidden");
    renderUser();
    await loadDashboard();
    showToast("Sessao segura iniciada.");
  } catch {
    elements.loginForm.reset();
    elements.loginMessage.textContent = "Nao foi possivel autenticar.";
  }
});

elements.logoutButton.addEventListener("click", async () => {
  try { await api("/session/logout", { method: "POST", body: "{}" }, false); } catch { /* local reset follows */ }
  resetSession();
});

elements.invoiceLookupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const invoiceId = document.querySelector("#invoice-id").value.trim();
  elements.invoiceResult.className = "lookup-result empty";
  elements.invoiceResult.textContent = "Consultando...";
  try {
    const { invoice } = await api(`/invoices/${encodeURIComponent(invoiceId)}`);
    const status = statusText(invoice.status);
    const band = ["Faixa A", "Faixa B", "Faixa C"].includes(invoice.amountBand) ? invoice.amountBand : "Indisponivel";
    elements.invoiceResult.className = "lookup-result";
    elements.invoiceResult.textContent = `${String(invoice.id).slice(0, 32)} · ${status} · ${band}`;
  } catch {
    elements.invoiceResult.className = "lookup-result denied";
    elements.invoiceResult.textContent = "Registro sintetico indisponivel.";
  }
  await loadAudit();
});

elements.refreshAudit.addEventListener("click", loadAudit);
document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
    button.classList.add("active");
    const section = document.querySelector(`#${button.dataset.target}`);
    if (section && !elements.dashboard.classList.contains("hidden")) {
      section.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
});

async function restoreSession() {
  try {
    let response = await fetch("/api/secure/session", {
      credentials: "same-origin", headers: { "X-Requested-With": "AegisLedger" }
    });
    if (response.status === 401 && await refreshSession()) {
      response = await fetch("/api/secure/session", {
        credentials: "same-origin", headers: { "X-Requested-With": "AegisLedger" }
      });
    }
    if (!response.ok) return;
    const session = await response.json();
    state.user = session.user;
    elements.authSection.classList.add("hidden");
    elements.dashboard.classList.remove("hidden");
    renderUser();
    await loadDashboard();
  } catch { resetSession(); }
}

elements.banner.className = "environment-banner secure";
renderControls();
resetSession();
restoreSession();
