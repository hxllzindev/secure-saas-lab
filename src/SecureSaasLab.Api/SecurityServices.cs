using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecureSaasLab.Api;

public sealed class TokenService
{
    private readonly byte[] _secret;
    public TokenService(string secret) => _secret = Encoding.UTF8.GetBytes(secret);

    public string Sign(TokenPayload payload)
    {
        var body = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload, JsonOptions)));
        var signature = Hmac(body);
        return $"{body}.{signature}";
    }

    public TokenPayload? Verify(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 2048) return null;
        try
        {
            var parts = token.Split('.');
            if (parts.Length != 2 || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Hmac(parts[0])), Encoding.UTF8.GetBytes(parts[1]))) return null;
            var payload = JsonSerializer.Deserialize<TokenPayload>(Encoding.UTF8.GetString(Base64UrlDecode(parts[0])), JsonOptions);
            return payload is null || payload.Exp <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? null : payload;
        }
        catch (FormatException) { return null; }
        catch (JsonException) { return null; }
    }

    public static string OpaqueToken() => Base64Url(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private string Hmac(string value) => Base64Url(new HMACSHA256(_secret).ComputeHash(Encoding.UTF8.GetBytes(value)));
    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
}

public static class SecurityControls
{
    public const int AccessTokenTtlSeconds = 300;
    public const int VulnerableTokenTtlSeconds = 1200;
    public const int RefreshTokenTtlSeconds = 604800;
    private static readonly Regex ControlChars = new("[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]", RegexOptions.Compiled);

    public static string NormalizeEmail(string? value) => value?.Trim().ToLowerInvariant() ?? "";
    public static bool ValidLoginShape(LoginRequest input) =>
        input.Email is { Length: > 2 and <= 254 } &&
        input.Password is { Length: > 0 and <= 256 } &&
        input.MfaCode is { Length: 6 } && input.MfaCode.All(char.IsAsciiDigit);
    public static bool VerifyPassword(string? password, UserAccount user) => password == user.Password;
    public static string SanitizePlainText(string? value, int maxLength = 280)
    {
        var clean = ControlChars.Replace(value ?? "", "").Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    public static bool CheckRateLimit(LabStore store, string key, out int retryAfter, int maxAttempts = 5)
    {
        lock (store.SyncRoot)
        {
            var now = DateTimeOffset.UtcNow;
            var recent = store.LoginAttempts.GetValueOrDefault(key, []).Where(item => now - item < TimeSpan.FromMinutes(1)).ToList();
            retryAfter = recent.Count > 0 ? Math.Max(1, 60 - (int)(now - recent[0]).TotalSeconds) : 0;
            if (recent.Count >= maxAttempts) { store.LoginAttempts[key] = recent; return false; }
            recent.Add(now);
            store.LoginAttempts[key] = recent;
            return true;
        }
    }

    public static void ResetRateLimit(LabStore store, string key)
    {
        lock (store.SyncRoot) store.LoginAttempts.Remove(key);
    }

    public static PublicUser Public(UserAccount user) => new("Workspace de demonstracao", user.Role);
    public static FrontendInvoice Public(Invoice invoice) => new(
        invoice.Id,
        invoice.Status,
        invoice.DueDate,
        invoice.Amount switch { < 10_000 => "Faixa A", < 25_000 => "Faixa B", _ => "Faixa C" });
    public static FrontendNote Public(Note note) => new(note.Id, note.CreatedAt);
    public static FrontendAuditEvent Public(AuditEvent auditEvent) => new(
        auditEvent.Action, auditEvent.Mode, auditEvent.Severity, auditEvent.CreatedAt, auditEvent.TechniqueId);
    public static string Cookie(string name, string value, int maxAge, string path, bool secure = false) =>
        $"{name}={Uri.EscapeDataString(value)}; Path={path}; Max-Age={Math.Max(0, maxAge)}; HttpOnly; SameSite=Strict{(secure ? "; Secure" : "")}";
}
