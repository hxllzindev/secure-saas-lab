namespace SecureSaasLab.Api;

public sealed class LabStore
{
    public const int MaxAuditEvents = 5000;
    public const int MaxNotesPerTenant = 500;

    public object SyncRoot { get; } = new();
    public List<UserAccount> Users { get; init; } = [];
    public List<Invoice> Invoices { get; init; } = [];
    public List<Note> Notes { get; init; } = [];
    public Queue<AuditEvent> AuditEvents { get; init; } = new();
    public Dictionary<string, List<DateTimeOffset>> LoginAttempts { get; init; } = [];
    public Dictionary<string, RefreshSession> RefreshSessions { get; init; } = [];

    public void AddAudit(AuditEvent auditEvent)
    {
        lock (SyncRoot)
        {
            AuditEvents.Enqueue(auditEvent);
            while (AuditEvents.Count > MaxAuditEvents) AuditEvents.Dequeue();
        }
    }

    public bool TryAddNote(Note note)
    {
        lock (SyncRoot)
        {
            if (Notes.Count(item => item.TenantId == note.TenantId) >= MaxNotesPerTenant) return false;
            Notes.Add(note);
            return true;
        }
    }

    public void PurgeStaleRefreshSessions(DateTimeOffset now)
    {
        lock (SyncRoot)
        {
            var cutoff = now.AddHours(-1);
            var staleHashes = RefreshSessions
                .Where(pair => pair.Value.ExpiresAt < cutoff || pair.Value.RevokedAt is { } revokedAt && revokedAt < cutoff)
                .Select(pair => pair.Key)
                .ToArray();
            foreach (var staleHash in staleHashes) RefreshSessions.Remove(staleHash);
        }
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

public sealed class UserAccount
{
    public UserAccount(string id, string name, string email, string tenantId, string tenantName, string role, string mfaCode, PasswordCredential passwordCredential)
    {
        Id = id;
        Name = name;
        Email = email;
        TenantId = tenantId;
        TenantName = tenantName;
        Role = role;
        MfaCode = mfaCode;
        PasswordCredential = passwordCredential;
    }

    public string Id { get; }
    public string Name { get; }
    public string Email { get; }
    public string TenantId { get; }
    public string TenantName { get; }
    public string Role { get; }
    public string MfaCode { get; }
    public PasswordCredential PasswordCredential { get; }
}
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
