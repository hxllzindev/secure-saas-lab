import { renderVulnerableContent } from "./vulnerable-lab.js";

const state = {
  mode: "secure",
  token: null,
  csrfToken: null,
  user: null,
  invoices: [],
  notes: [],
  events: []
};

const elements = {
  authSection: document.querySelector("#auth-section"),
  dashboard: document.querySelector("#dashboard"),
  loginForm: document.querySelector("#login-form"),
  loginMessage: document.querySelector("#login-message"),
  mfaField: document.querySelector("#mfa-field"),
  banner: document.querySelector("#environment-banner"),
  userChip: document.querySelector("#user-chip"),
  logoutButton: document.querySelector("#logout-button"),
  invoiceTable: document.querySelector("#invoice-table"),
  invoiceCount: document.querySelector("#invoice-count"),
  invoiceLookupForm: document.querySelector("#invoice-lookup-form"),
  invoiceResult: document.querySelector("#invoice-result"),
  noteForm: document.querySelector("#note-form"),
  noteContent: document.querySelector("#note-content"),
  noteLimit: document.querySelector("#note-limit"),
  notesList: document.querySelector("#notes-list"),
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

const currency = new Intl.NumberFormat("pt-BR", {
  style: "currency",
  currency: "BRL"
});

const dateTime = new Intl.DateTimeFormat("pt-BR", {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit"
});

function initials(name) {
  return name
    .split(" ")
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.remove("hidden");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.add("hidden"), 3200);
}

async function refreshSecureSession() {
  const response = await fetch("/api/secure/session/refresh", {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Requested-With": "AegisLedger" }
  });
  if (!response.ok) return false;
  const payload = await response.json();
  state.csrfToken = payload.csrfToken;
  state.user = payload.user;
  renderUser();
  return true;
}

async function api(path, options = {}, retry = true) {
  const method = options.method ?? "GET";
  const response = await fetch(`/api/${state.mode}${path}`, {
    ...options,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "AegisLedger",
      ...(state.mode === "vulnerable" && state.token ? { Authorization: `Bearer ${state.token}` } : {}),
      ...(state.mode === "secure" && method !== "GET" && state.csrfToken
        ? { "X-CSRF-Token": state.csrfToken }
        : {}),
      ...(options.headers ?? {})
    }
  });

  const payload = await response.json();
  if (response.status === 401 && state.mode === "secure" && state.user && retry && !path.includes("/refresh")) {
    const refreshed = await refreshSecureSession();
    if (refreshed) return api(path, options, false);
  }
  if (!response.ok) {
    const error = new Error(payload.error ?? "Falha na requisicao.");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function updateModeUi() {
  document.querySelectorAll("[data-mode]").forEach((button) => {
    button.classList.toggle("active", button.dataset.mode === state.mode);
  });

  const secure = state.mode === "secure";
  elements.banner.className = `environment-banner ${state.mode}`;
  elements.banner.innerHTML = secure
    ? "<strong>Ambiente seguro</strong><span>MFA, rate limiting, autorizacao por tenant e output encoding ativos.</span>"
    : "<strong>Ambiente vulneravel</strong><span>Enumeracao de usuarios, ausencia de MFA, BOLA e HTML nao confiavel ativos.</span>";
  elements.mfaField.classList.toggle("hidden", !secure);
  elements.noteContent.maxLength = secure ? 280 : 2000;
  updateNoteLimit();
  renderControls();
}

function resetSession() {
  state.token = null;
  state.csrfToken = null;
  state.user = null;
  state.invoices = [];
  state.notes = [];
  state.events = [];
  elements.authSection.classList.remove("hidden");
  elements.dashboard.classList.add("hidden");
  elements.logoutButton.classList.add("hidden");
  elements.userChip.innerHTML = '<span class="avatar">AS</span><span><strong>Visitante</strong><small>Sem sessao</small></span>';
  elements.loginMessage.textContent = "";
}

function renderUser() {
  elements.userChip.innerHTML = `
    <span class="avatar">${initials(state.user.name)}</span>
    <span><strong>${state.user.name}</strong><small>${state.user.tenantName}</small></span>
  `;
  elements.logoutButton.classList.remove("hidden");
}

function renderMetrics() {
  const total = state.invoices.reduce((sum, invoice) => sum + invoice.amount, 0);
  const pending = state.invoices.filter((invoice) => invoice.status !== "paid").length;
  const secure = state.mode === "secure";
  elements.metricTotal.textContent = currency.format(total);
  elements.metricPending.textContent = String(pending);
  elements.metricEvents.textContent = String(state.events.length);
  elements.metricPosture.textContent = secure ? "Protegida" : "Exposta";
  elements.metricMode.textContent = secure ? "Ambiente seguro" : "Ambiente vulneravel";
}

function statusText(status) {
  return {
    paid: "Pago",
    pending: "Pendente",
    overdue: "Vencido"
  }[status] ?? status;
}

function renderInvoices() {
  elements.invoiceTable.replaceChildren();
  for (const invoice of state.invoices) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td class="table-id"></td>
      <td></td>
      <td></td>
      <td><span class="badge badge-${invoice.status}"></span></td>
      <td></td>
    `;
    const cells = row.querySelectorAll("td");
    cells[0].textContent = invoice.id;
    cells[1].textContent = invoice.customer;
    cells[2].textContent = new Date(`${invoice.dueDate}T12:00:00`).toLocaleDateString("pt-BR");
    cells[3].querySelector("span").textContent = statusText(invoice.status);
    cells[4].textContent = currency.format(invoice.amount);
    elements.invoiceTable.append(row);
  }
  elements.invoiceCount.textContent = `${state.invoices.length} registros`;
}

function renderNotes() {
  elements.notesList.replaceChildren();

  if (state.notes.length === 0) {
    elements.notesList.innerHTML = '<div class="empty-state">Nenhuma nota publicada.</div>';
    return;
  }

  for (const note of state.notes) {
    const item = document.createElement("article");
    item.className = "note-item";
    const meta = document.createElement("div");
    meta.className = "note-meta";
    const author = document.createElement("strong");
    const time = document.createElement("time");
    author.textContent = note.author;
    time.textContent = dateTime.format(new Date(note.createdAt));
    meta.append(author, time);

    const content = document.createElement("p");
    content.className = "note-content";
    if (state.mode === "vulnerable") {
      renderVulnerableContent(content, note.content);
    } else {
      content.textContent = note.content;
    }

    item.append(meta, content);
    elements.notesList.append(item);
  }
}

function actionLabel(action) {
  return {
    login_success: "Login concluido",
    login_failed: "Falha de autenticacao",
    login_blocked: "Login bloqueado",
    invoice_viewed: "Fatura consultada",
    invoice_access_denied: "Acesso a fatura negado",
    note_created: "Nota publicada",
    csrf_blocked: "Requisicao CSRF bloqueada",
    session_refreshed: "Sessao renovada",
    refresh_reuse_detected: "Reutilizacao de token detectada",
    refresh_failed: "Falha ao renovar sessao",
    logout: "Sessao encerrada"
  }[action] ?? action;
}

function renderAudit() {
  elements.auditList.replaceChildren();

  if (state.mode !== "secure") {
    elements.auditList.innerHTML = '<div class="empty-state">Auditoria indisponivel neste ambiente.</div>';
    return;
  }

  if (state.events.length === 0) {
    elements.auditList.innerHTML = '<div class="empty-state">Nenhum evento para o tenant atual.</div>';
    return;
  }

  for (const event of state.events) {
    const item = document.createElement("article");
    item.className = "audit-item";
    const detail = document.createElement("div");
    const title = document.createElement("strong");
    const description = document.createElement("p");
    const mode = document.createElement("span");
    const detection = document.createElement("span");
    title.textContent = actionLabel(event.action);
    description.textContent = `${event.actor ?? event.email ?? "Sistema"} · ${dateTime.format(new Date(event.createdAt))}${event.resourceId ? ` · ${event.resourceId}` : ""}`;
    mode.className = "event-mode";
    mode.textContent = event.mode;
    detection.className = `detection-label severity-${event.severity ?? "info"}`;
    detection.textContent = event.techniqueId
      ? `${event.techniqueId} · ${event.techniqueName}`
      : (event.severity ?? "info");
    detail.append(detection);
    detail.append(title, description);
    item.append(detail, mode);
    elements.auditList.append(item);
  }
}

function renderControls() {
  const secure = state.mode === "secure";
  const controls = [
    ["Autenticacao multifator", secure],
    ["Rate limiting no login", secure],
    ["Autorizacao por tenant", secure],
    ["PostgreSQL Row-Level Security", secure],
    ["Cookies HttpOnly e SameSite", secure],
    ["Refresh token rotativo", secure],
    ["Protecao CSRF", secure],
    ["Output encoding", secure],
    ["Auditoria administrativa", secure]
  ];

  elements.controlList.replaceChildren();
  for (const [label, active] of controls) {
    const item = document.createElement("li");
    const name = document.createElement("span");
    const status = document.createElement("span");
    name.textContent = label;
    status.textContent = active ? "Ativo" : "Inativo";
    status.className = `control-state${active ? "" : " off"}`;
    item.append(name, status);
    elements.controlList.append(item);
  }
}

async function loadInvoices() {
  const payload = await api("/invoices");
  state.invoices = payload.invoices;
  renderInvoices();
}

async function loadNotes() {
  const payload = await api("/notes");
  state.notes = payload.notes;
  renderNotes();
}

async function loadAudit() {
  if (state.mode !== "secure" || state.user.role !== "admin") {
    state.events = [];
    renderAudit();
    renderMetrics();
    return;
  }

  try {
    const payload = await api("/audit");
    state.events = payload.events;
  } catch (error) {
    state.events = [];
    showToast(error.message);
  }
  renderAudit();
  renderMetrics();
}

async function loadDashboard() {
  await Promise.all([loadInvoices(), loadNotes()]);
  await loadAudit();
  renderMetrics();
}

document.querySelectorAll("[data-mode]").forEach((button) => {
  button.addEventListener("click", () => {
    if (button.dataset.mode === state.mode) return;
    state.mode = button.dataset.mode;
    resetSession();
    updateModeUi();
  });
});

elements.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.loginMessage.textContent = "Autenticando...";
  const form = new FormData(elements.loginForm);

  try {
    const session = await api("/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.get("email"),
        password: form.get("password"),
        mfaCode: form.get("mfaCode")
      })
    });
    state.token = session.token;
    state.csrfToken = session.csrfToken ?? null;
    state.user = session.user;
    elements.authSection.classList.add("hidden");
    elements.dashboard.classList.remove("hidden");
    renderUser();
    await loadDashboard();
    showToast(`Sessao iniciada em ambiente ${state.mode}.`);
  } catch (error) {
    elements.loginMessage.textContent = error.message;
  }
});

elements.logoutButton.addEventListener("click", async () => {
  if (state.mode === "secure") {
    try {
      await api("/session/logout", { method: "POST", body: "{}" }, false);
    } catch {
      // The local session is cleared even when the server is unreachable.
    }
  }
  resetSession();
});

elements.invoiceLookupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const invoiceId = document.querySelector("#invoice-id").value.trim();
  elements.invoiceResult.className = "lookup-result empty";
  elements.invoiceResult.textContent = "Consultando...";

  try {
    const { invoice } = await api(`/invoices/${encodeURIComponent(invoiceId)}`);
    elements.invoiceResult.className = "lookup-result";
    elements.invoiceResult.textContent = `${invoice.id} · ${invoice.customer} · ${currency.format(invoice.amount)} · tenant: ${invoice.tenantId}`;
  } catch (error) {
    elements.invoiceResult.className = "lookup-result denied";
    elements.invoiceResult.textContent = error.message;
  }
  await loadAudit();
});

function updateNoteLimit() {
  const max = state.mode === "secure" ? 280 : 2000;
  elements.noteLimit.textContent = `${elements.noteContent.value.length} / ${max}`;
}

elements.noteContent.addEventListener("input", updateNoteLimit);

elements.noteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/notes", {
      method: "POST",
      body: JSON.stringify({ content: elements.noteContent.value })
    });
    elements.noteContent.value = "";
    updateNoteLimit();
    await Promise.all([loadNotes(), loadAudit()]);
    showToast("Nota publicada.");
  } catch (error) {
    showToast(error.message);
  }
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

async function restoreSecureSession() {
  try {
    let response = await fetch("/api/secure/session", {
      credentials: "same-origin",
      headers: { "X-Requested-With": "AegisLedger" }
    });
    if (response.status === 401) {
      const refreshed = await refreshSecureSession();
      if (!refreshed) return;
      response = await fetch("/api/secure/session", {
        credentials: "same-origin",
        headers: { "X-Requested-With": "AegisLedger" }
      });
    }
    if (!response.ok) return;
    const session = await response.json();
    state.user = session.user;
    state.csrfToken = session.csrfToken;
    elements.authSection.classList.add("hidden");
    elements.dashboard.classList.remove("hidden");
    renderUser();
    await loadDashboard();
  } catch {
    resetSession();
  }
}

updateModeUi();
resetSession();
restoreSecureSession();
