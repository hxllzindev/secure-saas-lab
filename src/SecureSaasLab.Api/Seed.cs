namespace SecureSaasLab.Api;

public static class Seed
{
    public static LabStore Create() => new()
    {
        Users =
        [
            new("usr-acme-admin", "Ana Silva", "ana@acme.test", "acme", "Acme Health", "admin", "482911", "Secure123!"),
            new("usr-acme-analyst", "Caio Mendes", "caio@acme.test", "acme", "Acme Health", "analyst", "731204", "Secure123!"),
            new("usr-orbit-admin", "Bruno Lima", "bruno@orbit.test", "orbit", "Orbit Logistics", "admin", "195730", "Secure123!")
        ],
        Invoices =
        [
            new("inv-1001", "acme", "Clinica Horizonte", 12480.90m, "paid", "2026-06-04"),
            new("inv-1002", "acme", "Laboratorio Norte", 7820.00m, "pending", "2026-06-24"),
            new("inv-2001", "orbit", "Atlas Transportes", 31990.50m, "overdue", "2026-05-30")
        ],
        Notes =
        [
            new("note-1", "acme", "Ana Silva", "Revisar o contrato antes da renovacao.", "2026-06-13T14:20:00.000Z"),
            new("note-2", "orbit", "Bruno Lima", "Validar a conciliacao do mes.", "2026-06-13T16:45:00.000Z")
        ]
    };
}
