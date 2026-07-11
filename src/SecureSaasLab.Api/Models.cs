namespace SecureSaasLab.Api;

public sealed class LabStore
{
    public object SyncRoot { get; } = new();
    public List<UserAccount> Users { get; init; } = [];
    public List<Invoice> Invoices { get; init; } = [];
    public List<Note> Notes { get; init; } = [];
    public List<AuditEvent> AuditEvents { get; init; } = [];
    public Dictionary<string, List<DateTimeOffset>> LoginAttempts { get; init; } = [];
    public Dictionary<string, RefreshSession> RefreshSessions { get; init; } = [];

    public void AddAudit(AuditEvent auditEvent)
    {
        lock (SyncRoot) AuditEvents.Add(auditEvent);
    }

    public void AddNote(Note note)
    {
        lock (SyncRoot) Notes.Add(note);
    }

    public Note[] NotesForTenant(string tenantId)
    {
        lock (SyncRoot) return Notes.Where(item => item.TenantId == tenantId).ToArray();
    }

    public AuditEvent[] RecentAuditForTenant(string tenantId)
    {
        lock (SyncRoot) return AuditEvents.Where(item => item.TenantId == tenantId || item.TenantId is null).TakeLast(30).Reverse().ToArray();
    }
}

public sealed record UserAccount(string Id, string Name, string Email, string TenantId, string TenantName, string Role, string MfaCode, string Password);
public sealed record Invoice(string Id, string TenantId, string Customer, decimal Amount, string Status, string DueDate);
public sealed record Note(string Id, string TenantId, string Author, string Content, string CreatedAt);
public sealed record PublicUser(string DisplayLabel, string Role);
public sealed record FrontendInvoice(string Id, string Status, string DueDate, string AmountBand);
public sealed record FrontendNote(string Id, string CreatedAt);
public sealed record FrontendAuditEvent(string Action, string Mode, string Severity, string CreatedAt, string TechniqueId);
public sealed class RefreshSession
{
    public required string TokenHash { get; init; }
    public required string FamilyId { get; init; }
    public required string UserId { get; init; }
    public required string TenantId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? ReplacedByHash { get; set; }
}

public sealed record AuditEvent(string Id, string Action, string Mode, string? Actor, string? TenantId, string? ResourceId, string? Reason, string Severity, string CreatedAt, string TechniqueId)
{
    public static AuditEvent Create(string action, string mode, string? actor = null, string? tenantId = null, string? resourceId = null, string? reason = null, string severity = "info") =>
        new(Guid.NewGuid().ToString(), action, mode, actor, tenantId, resourceId, reason, severity, DateTimeOffset.UtcNow.ToString("O"), action == "invoice_access_denied" ? "T1190" : "T1078");
}

public sealed class LoginRequest { public string? Email { get; init; } public string? Password { get; init; } public string? MfaCode { get; init; } }
public sealed class NoteRequest { public string? Content { get; init; } }
public sealed record TokenPayload(string Sub, string TenantId, string Role, string Mode, string Type, string? FamilyId, long Exp);
public sealed record AuthSession(UserAccount User, TokenPayload Payload);
