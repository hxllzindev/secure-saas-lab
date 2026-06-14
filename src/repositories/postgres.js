function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    tenantId: row.tenant_id,
    tenantName: row.tenant_name,
    role: row.role,
    mfaCode: row.mfa_code,
    password: {
      salt: row.password_salt,
      hash: row.password_hash,
      iterations: row.password_iterations
    }
  };
}

function mapInvoice(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    customer: row.customer,
    amount: Number(row.amount),
    status: row.status,
    dueDate: row.due_date.toISOString?.().slice(0, 10) ?? String(row.due_date)
  };
}

function mapNote(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    author: row.author,
    content: row.content,
    createdAt: row.created_at.toISOString()
  };
}

function mapAudit(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    action: row.action,
    mode: row.mode,
    actor: row.actor,
    email: row.email,
    ip: row.ip,
    reason: row.reason,
    resourceId: row.resource_id,
    techniqueId: row.technique_id,
    techniqueName: row.technique_name,
    severity: row.severity,
    createdAt: row.created_at.toISOString()
  };
}

export async function createPostgresRepository(connectionString) {
  const { Pool } = await import("pg");
  const pool = new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000
  });

  async function withTenant(tenantId, role, callback) {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      await client.query("SELECT set_config('app.user_role', $1, true)", [role ?? "analyst"]);
      const result = await callback(client);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  await pool.query("SELECT 1");

  return {
    async findUserByEmail(email) {
      const result = await pool.query("SELECT * FROM auth.lookup_user($1)", [email]);
      return mapUser(result.rows[0]);
    },

    async findUserById(id) {
      const result = await pool.query("SELECT * FROM auth.lookup_user_by_id($1)", [id]);
      return mapUser(result.rows[0]);
    },

    async listInvoices(tenantId) {
      return withTenant(tenantId, "analyst", async (client) => {
        const result = await client.query("SELECT * FROM invoices ORDER BY due_date DESC");
        return result.rows.map(mapInvoice);
      });
    },

    async findInvoiceById(id, tenantId, allowCrossTenant = false) {
      if (allowCrossTenant) {
        const result = await pool.query("SELECT * FROM lab.lookup_invoice_unsafe($1)", [id]);
        return result.rows[0] ? mapInvoice(result.rows[0]) : null;
      }
      return withTenant(tenantId, "analyst", async (client) => {
        const result = await client.query("SELECT * FROM invoices WHERE id = $1", [id]);
        return result.rows[0] ? mapInvoice(result.rows[0]) : null;
      });
    },

    async listNotes(tenantId) {
      return withTenant(tenantId, "analyst", async (client) => {
        const result = await client.query("SELECT * FROM notes ORDER BY created_at DESC");
        return result.rows.map(mapNote);
      });
    },

    async createNote({ tenantId, author, content }) {
      return withTenant(tenantId, "analyst", async (client) => {
        const result = await client.query(
          "INSERT INTO notes (tenant_id, author, content) VALUES ($1, $2, $3) RETURNING *",
          [tenantId, author, content]
        );
        return mapNote(result.rows[0]);
      });
    },

    async addAuditEvent(event) {
      const result = await pool.query(
        "SELECT * FROM auth.write_audit_event($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        [
          event.tenantId ?? null,
          event.action,
          event.mode,
          event.actor ?? null,
          event.email ?? null,
          event.ip ?? null,
          event.reason ?? null,
          event.resourceId ?? null,
          event.techniqueId ?? null,
          event.techniqueName ?? null,
          event.severity ?? "info"
        ]
      );
      return mapAudit(result.rows[0]);
    },

    async listAuditEvents(tenantId, limit = 30) {
      return withTenant(tenantId, "admin", async (client) => {
        const result = await client.query(
          "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT $1",
          [limit]
        );
        return result.rows.map(mapAudit);
      });
    },

    async createRefreshSession(session) {
      await pool.query(
        "SELECT auth.create_refresh_session($1,$2,$3,$4,$5,$6,$7)",
        [
          session.tokenHash,
          session.familyId,
          session.userId,
          session.tenantId,
          session.expiresAt,
          session.userAgent,
          session.ip
        ]
      );
      return session;
    },

    async findRefreshSession(tokenHash) {
      const result = await pool.query("SELECT * FROM auth.lookup_refresh_session($1)", [tokenHash]);
      const row = result.rows[0];
      if (!row) return null;
      return {
        tokenHash: row.token_hash,
        familyId: row.family_id,
        userId: row.user_id,
        tenantId: row.tenant_id,
        expiresAt: row.expires_at.toISOString(),
        revokedAt: row.revoked_at?.toISOString() ?? null,
        replacedByHash: row.replaced_by_hash
      };
    },

    async consumeRefreshSession(tokenHash, replacement) {
      const result = await pool.query(
        "SELECT * FROM auth.rotate_refresh_session($1,$2,$3,$4,$5,$6,$7,$8)",
        [
          tokenHash,
          replacement.tokenHash,
          replacement.familyId,
          replacement.userId,
          replacement.tenantId,
          replacement.expiresAt,
          replacement.userAgent,
          replacement.ip
        ]
      );
      return { status: result.rows[0]?.status ?? "missing" };
    },

    async revokeRefreshFamily(familyId) {
      await pool.query("SELECT auth.revoke_refresh_family($1)", [familyId]);
    },

    async close() {
      await pool.end();
    }
  };
}
