INSERT INTO tenants (id, name) VALUES
  ('acme', 'Acme Health'),
  ('orbit', 'Orbit Logistics')
ON CONFLICT DO NOTHING;

-- Password for all demo users: Secure123!
INSERT INTO users
  (id, tenant_id, name, email, role, mfa_code, password_salt, password_hash, password_iterations)
VALUES
  ('usr-acme-admin', 'acme', 'Ana Silva', 'ana@acme.test', 'admin', '482911',
   '684a37ebc8990c0c248d7f4f04dcbd05', 'd847c1e477834daa98a985a62a0f7f589f6ee8c2643a0d4e41dda1daf3e7d045', 120000),
  ('usr-acme-analyst', 'acme', 'Caio Mendes', 'caio@acme.test', 'analyst', '731204',
   '684a37ebc8990c0c248d7f4f04dcbd05', 'd847c1e477834daa98a985a62a0f7f589f6ee8c2643a0d4e41dda1daf3e7d045', 120000),
  ('usr-orbit-admin', 'orbit', 'Bruno Lima', 'bruno@orbit.test', 'admin', '195730',
   '684a37ebc8990c0c248d7f4f04dcbd05', 'd847c1e477834daa98a985a62a0f7f589f6ee8c2643a0d4e41dda1daf3e7d045', 120000)
ON CONFLICT DO NOTHING;

INSERT INTO invoices (id, tenant_id, customer, amount, status, due_date) VALUES
  ('inv-1001', 'acme', 'Clinica Horizonte', 12480.90, 'paid', '2026-06-04'),
  ('inv-1002', 'acme', 'Laboratorio Norte', 7820.00, 'pending', '2026-06-24'),
  ('inv-2001', 'orbit', 'Atlas Transportes', 31990.50, 'overdue', '2026-05-30')
ON CONFLICT DO NOTHING;

INSERT INTO notes (id, tenant_id, author, content, created_at) VALUES
  ('00000000-0000-4000-8000-000000000001', 'acme', 'Ana Silva', 'Revisar o contrato antes da renovacao.', '2026-06-13T14:20:00Z'),
  ('00000000-0000-4000-8000-000000000002', 'orbit', 'Bruno Lima', 'Validar a conciliacao do mes.', '2026-06-13T16:45:00Z')
ON CONFLICT DO NOTHING;
