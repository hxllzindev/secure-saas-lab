import { randomUUID } from "node:crypto";

export function createMemoryRepository(store) {
  return {
    store,

    async findUserByEmail(email) {
      return store.users.find((user) => user.email === email) ?? null;
    },

    async findUserById(id) {
      return store.users.find((user) => user.id === id) ?? null;
    },

    async listInvoices(tenantId) {
      return store.invoices.filter((invoice) => invoice.tenantId === tenantId);
    },

    async findInvoiceById(id, tenantId, allowCrossTenant = false) {
      const invoice = store.invoices.find((candidate) => candidate.id === id);
      if (!invoice || (!allowCrossTenant && invoice.tenantId !== tenantId)) return null;
      return invoice;
    },

    async listNotes(tenantId) {
      return store.notes.filter((note) => note.tenantId === tenantId);
    },

    async createNote({ tenantId, author, content }) {
      const note = {
        id: randomUUID(),
        tenantId,
        author,
        content,
        createdAt: new Date().toISOString()
      };
      store.notes.unshift(note);
      return note;
    },

    async addAuditEvent(event) {
      const auditEvent = {
        id: randomUUID(),
        createdAt: new Date().toISOString(),
        ...event
      };
      store.auditEvents.unshift(auditEvent);
      store.auditEvents.splice(100);
      return auditEvent;
    },

    async listAuditEvents(tenantId, limit = 30) {
      return store.auditEvents
        .filter((event) => event.tenantId === tenantId)
        .slice(0, limit);
    },

    async createRefreshSession(session) {
      store.refreshSessions.set(session.tokenHash, { ...session });
      return session;
    },

    async findRefreshSession(tokenHash) {
      return store.refreshSessions.get(tokenHash) ?? null;
    },

    async consumeRefreshSession(tokenHash, replacement) {
      const current = store.refreshSessions.get(tokenHash);
      if (!current) return { status: "missing" };

      if (current.revokedAt || new Date(current.expiresAt).getTime() <= Date.now()) {
        for (const session of store.refreshSessions.values()) {
          if (session.familyId === current.familyId) session.revokedAt = new Date().toISOString();
        }
        return { status: "reused", session: current };
      }

      current.revokedAt = new Date().toISOString();
      current.replacedByHash = replacement.tokenHash;
      store.refreshSessions.set(replacement.tokenHash, { ...replacement });
      return { status: "rotated", session: current };
    },

    async revokeRefreshFamily(familyId) {
      for (const session of store.refreshSessions.values()) {
        if (session.familyId === familyId) session.revokedAt = new Date().toISOString();
      }
    },

    async close() {}
  };
}
