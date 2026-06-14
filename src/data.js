import { pbkdf2Sync, randomBytes } from "node:crypto";

const PASSWORD_ITERATIONS = 120_000;

function createPasswordRecord(password) {
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(password, salt, PASSWORD_ITERATIONS, 32, "sha256").toString("hex");
  return { salt, hash, iterations: PASSWORD_ITERATIONS };
}

export function createStore() {
  const users = [
    {
      id: "usr-acme-admin",
      name: "Ana Silva",
      email: "ana@acme.test",
      tenantId: "acme",
      tenantName: "Acme Health",
      role: "admin",
      mfaCode: "482911",
      password: createPasswordRecord("Secure123!")
    },
    {
      id: "usr-acme-analyst",
      name: "Caio Mendes",
      email: "caio@acme.test",
      tenantId: "acme",
      tenantName: "Acme Health",
      role: "analyst",
      mfaCode: "731204",
      password: createPasswordRecord("Secure123!")
    },
    {
      id: "usr-orbit-admin",
      name: "Bruno Lima",
      email: "bruno@orbit.test",
      tenantId: "orbit",
      tenantName: "Orbit Logistics",
      role: "admin",
      mfaCode: "195730",
      password: createPasswordRecord("Secure123!")
    }
  ];

  const invoices = [
    {
      id: "inv-1001",
      tenantId: "acme",
      customer: "Clinica Horizonte",
      amount: 12480.9,
      status: "paid",
      dueDate: "2026-06-04"
    },
    {
      id: "inv-1002",
      tenantId: "acme",
      customer: "Laboratorio Norte",
      amount: 7820.0,
      status: "pending",
      dueDate: "2026-06-24"
    },
    {
      id: "inv-2001",
      tenantId: "orbit",
      customer: "Atlas Transportes",
      amount: 31990.5,
      status: "overdue",
      dueDate: "2026-05-30"
    }
  ];

  const notes = [
    {
      id: "note-1",
      tenantId: "acme",
      author: "Ana Silva",
      content: "Revisar o contrato antes da renovacao.",
      createdAt: "2026-06-13T14:20:00.000Z"
    },
    {
      id: "note-2",
      tenantId: "orbit",
      author: "Bruno Lima",
      content: "Validar a conciliacao do mes.",
      createdAt: "2026-06-13T16:45:00.000Z"
    }
  ];

  return {
    users,
    invoices,
    notes,
    auditEvents: [],
    loginAttempts: new Map(),
    refreshSessions: new Map()
  };
}
