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
        if (string.IsNullOrWhiteSpace(token)) return null;
        var parts = token.Split('.');
        if (parts.Length != 2 || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Hmac(parts[0])), Encoding.UTF8.GetBytes(parts[1]))) return null;
        var payload = JsonSerializer.Deserialize<TokenPayload>(Encoding.UTF8.GetString(Base64UrlDecode(parts[0])), JsonOptions);
        return payload is null || payload.Exp <= DateTimeOffset.UtcNow.ToUnixTimeSeconds() ? null : payload;
    }

    public static string OpaqueToken() => Base64Url(RandomNumberGenerator.GetBytes(32));
    public static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    public static string CsrfToken() => Base64Url(RandomNumberGenerator.GetBytes(24));
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
    public static bool VerifyPassword(string? password, UserAccount user) => password == user.Password;
    public static string SanitizePlainText(string? value, int maxLength = 280)
    {
        var clean = ControlChars.Replace(value ?? "", "").Trim();
        return clean.Length <= maxLength ? clean : clean[..maxLength];
    }

    public static bool CheckRateLimit(LabStore store, string key, out int retryAfter)
    {
        var now = DateTimeOffset.UtcNow;
        var recent = store.LoginAttempts.GetValueOrDefault(key, []).Where(item => now - item < TimeSpan.FromMinutes(1)).ToList();
        retryAfter = recent.Count > 0 ? Math.Max(1, 60 - (int)(now - recent[0]).TotalSeconds) : 0;
        if (recent.Count >= 5) { store.LoginAttempts[key] = recent; return false; }
        recent.Add(now);
        store.LoginAttempts[key] = recent;
        return true;
    }

    public static PublicUser Public(UserAccount user) => new(user.Id, user.Name, user.Email, user.Role, user.TenantId, user.TenantName);
    public static string Cookie(string name, string value, int maxAge, string path, bool secure = false) =>
        $"{name}={Uri.EscapeDataString(value)}; Path={path}; Max-Age={Math.Max(0, maxAge)}; HttpOnly; SameSite=Strict{(secure ? "; Secure" : "")}";
}
