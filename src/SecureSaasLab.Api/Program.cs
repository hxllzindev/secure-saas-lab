using SecureSaasLab.Api;

var builder = WebApplication.CreateBuilder(args);
var configuredSecret = builder.Configuration["TOKEN_SECRET"] ?? Environment.GetEnvironmentVariable("TOKEN_SECRET");
if (builder.Environment.IsProduction() && (string.IsNullOrWhiteSpace(configuredSecret) || configuredSecret.Length < 32))
{
    throw new InvalidOperationException("TOKEN_SECRET must be set to a unique secret with at least 32 characters in production.");
}
builder.Services.AddSingleton(Seed.Create());
builder.Services.AddSingleton(new TokenService(configuredSecret ?? TokenService.OpaqueToken()));

var app = builder.Build();
var secureCookies = app.Environment.IsProduction();
var accessCookie = secureCookies ? "__Host-aegis_access" : "aegis_access";
var refreshCookie = secureCookies ? "__Secure-aegis_refresh" : "aegis_refresh";

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok", database = "memory", stack = ".NET 10" }));

app.MapPost("/api/{mode}/login", (string mode, LoginRequest input, HttpContext http, LabStore store, TokenService tokens) =>
{
    if (mode is not ("secure" or "vulnerable")) return Results.NotFound(new { error = "Modo desconhecido." });
    var email = SecurityControls.NormalizeEmail(input.Email);
    var user = store.Users.FirstOrDefault(item => item.Email == email);
    var ip = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    if (mode == "vulnerable")
    {
        if (user is null) { store.AuditEvents.Add(AuditEvent.Create("login_failed", mode, null, null, null, "user_not_found")); return Results.NotFound(new { error = "Conta nao encontrada." }); }
        if (!SecurityControls.VerifyPassword(input.Password, user)) { store.AuditEvents.Add(AuditEvent.Create("login_failed", mode, null, user.TenantId, null, "wrong_password")); return Results.Json(new { error = "Senha incorreta." }, statusCode: 401); }
        var exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + SecurityControls.VulnerableTokenTtlSeconds;
        var token = tokens.Sign(new TokenPayload(user.Id, user.TenantId, user.Role, mode, "access", null, null, exp));
        store.AuditEvents.Add(AuditEvent.Create("login_success", mode, user.Name, user.TenantId));
        return Results.Ok(new { token, expiresIn = SecurityControls.VulnerableTokenTtlSeconds, user = SecurityControls.Public(user) });
    }

    var rateKey = $"{ip}:{email}";
    if (!SecurityControls.CheckRateLimit(store, rateKey, out var retryAfter))
    {
        store.AuditEvents.Add(AuditEvent.Create("login_blocked", mode, null, user?.TenantId, null, "rate_limit", "medium"));
        http.Response.Headers["Retry-After"] = retryAfter.ToString();
        return Results.Json(new { error = "Nao foi possivel autenticar. Tente novamente mais tarde." }, statusCode: 429);
    }
    if (user is null || !SecurityControls.VerifyPassword(input.Password, user) || input.MfaCode != user.MfaCode)
    {
        store.AuditEvents.Add(AuditEvent.Create("login_failed", mode, null, user?.TenantId, null, "invalid_credentials"));
        return Results.Json(new { error = "Credenciais invalidas." }, statusCode: 401);
    }

    var familyId = Guid.NewGuid().ToString();
    var csrf = TokenService.CsrfToken();
    var refresh = TokenService.OpaqueToken();
    var refreshHash = TokenService.Hash(refresh);
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var access = tokens.Sign(new TokenPayload(user.Id, user.TenantId, user.Role, mode, "access", familyId, csrf, now + SecurityControls.AccessTokenTtlSeconds));
    store.RefreshSessions[refreshHash] = new RefreshSession { TokenHash = refreshHash, FamilyId = familyId, UserId = user.Id, TenantId = user.TenantId, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(SecurityControls.RefreshTokenTtlSeconds) };
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(accessCookie, access, SecurityControls.AccessTokenTtlSeconds, "/", secureCookies));
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(refreshCookie, refresh, SecurityControls.RefreshTokenTtlSeconds, "/api/secure/session", secureCookies));
    store.AuditEvents.Add(AuditEvent.Create("login_success", mode, user.Name, user.TenantId));
    return Results.Ok(new { expiresIn = SecurityControls.AccessTokenTtlSeconds, csrfToken = csrf, user = SecurityControls.Public(user) });
});

app.MapPost("/api/secure/session/refresh", (HttpContext http, LabStore store, TokenService tokens) =>
{
    if (http.Request.Headers["X-Requested-With"] != "AegisLedger") return Results.Json(new { error = "Requisicao de refresh rejeitada." }, statusCode: 403);
    var refresh = http.Request.Cookies[refreshCookie];
    if (string.IsNullOrWhiteSpace(refresh)) return Results.Json(new { error = "Refresh token ausente." }, statusCode: 401);
    var hash = TokenService.Hash(refresh);
    if (!store.RefreshSessions.TryGetValue(hash, out var current))
    {
        store.AuditEvents.Add(AuditEvent.Create("refresh_failed", "secure", null, null, null, "unknown_token"));
        return Results.Json(new { error = "Sessao nao pode ser renovada." }, statusCode: 401);
    }
    var user = store.Users.FirstOrDefault(item => item.Id == current.UserId);
    if (user is null || current.RevokedAt is not null || current.ExpiresAt <= DateTimeOffset.UtcNow)
    {
        current.RevokedAt ??= DateTimeOffset.UtcNow;
        store.RefreshSessions.Values.Where(item => item.FamilyId == current.FamilyId).ToList().ForEach(item => item.RevokedAt ??= DateTimeOffset.UtcNow);
        store.AuditEvents.Add(AuditEvent.Create("refresh_reuse_detected", "secure", null, current.TenantId, null, "reuse", "high"));
        return Results.Json(new { error = "Sessao revogada por reutilizacao de token." }, statusCode: 401);
    }
    var replacement = TokenService.OpaqueToken();
    var replacementHash = TokenService.Hash(replacement);
    current.RevokedAt = DateTimeOffset.UtcNow;
    current.ReplacedByHash = replacementHash;
    store.RefreshSessions[replacementHash] = new RefreshSession { TokenHash = replacementHash, FamilyId = current.FamilyId, UserId = user.Id, TenantId = user.TenantId, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(SecurityControls.RefreshTokenTtlSeconds) };
    var csrf = TokenService.CsrfToken();
    var access = tokens.Sign(new TokenPayload(user.Id, user.TenantId, user.Role, "secure", "access", current.FamilyId, csrf, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + SecurityControls.AccessTokenTtlSeconds));
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(accessCookie, access, SecurityControls.AccessTokenTtlSeconds, "/", secureCookies));
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(refreshCookie, replacement, SecurityControls.RefreshTokenTtlSeconds, "/api/secure/session", secureCookies));
    store.AuditEvents.Add(AuditEvent.Create("session_refreshed", "secure", user.Name, user.TenantId));
    return Results.Ok(new { csrfToken = csrf, expiresIn = SecurityControls.AccessTokenTtlSeconds, user = SecurityControls.Public(user) });
});

app.MapMethods("/api/{mode}/{resource}", ["GET", "POST"], HandleResource);
app.MapGet("/api/{mode}/invoices/{id}", HandleInvoice);
app.MapPost("/api/secure/session/logout", (HttpContext http, LabStore store) =>
{
    var session = Authenticate(http, "secure");
    if (session is null) return Results.Json(new { error = "Sessao invalida ou expirada." }, statusCode: 401);
    store.RefreshSessions.Values.Where(item => item.FamilyId == session.Payload.FamilyId).ToList().ForEach(item => item.RevokedAt ??= DateTimeOffset.UtcNow);
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(accessCookie, "", 0, "/", secureCookies));
    http.Response.Headers.Append("Set-Cookie", SecurityControls.Cookie(refreshCookie, "", 0, "/api/secure/session", secureCookies));
    return Results.Ok(new { ok = true });
});

app.Run();

IResult HandleResource(string mode, string resource, HttpContext http, LabStore store, TokenService tokens)
{
    var session = Authenticate(http, mode);
    if (session is null) return Results.Json(new { error = "Sessao invalida ou expirada." }, statusCode: 401);
    if (mode == "secure" && !ValidateCsrf(http, session)) { store.AuditEvents.Add(AuditEvent.Create("csrf_blocked", mode, session.User.Name, session.User.TenantId)); return Results.Json(new { error = "Token CSRF invalido." }, statusCode: 403); }
    return (resource, http.Request.Method) switch
    {
        ("session", "GET") => Results.Ok(new { user = SecurityControls.Public(session.User), mode, csrfToken = mode == "secure" ? session.Payload.Csrf : null }),
        ("invoices", "GET") => Results.Ok(new { invoices = store.Invoices.Where(item => item.TenantId == session.User.TenantId) }),
        ("notes", "GET") => Results.Ok(new { notes = store.Notes.Where(item => item.TenantId == session.User.TenantId) }),
        ("notes", "POST") => CreateNote(http, store, session, mode),
        ("audit", "GET") when mode == "secure" && session.User.Role == "admin" => Results.Ok(new { events = store.AuditEvents.Where(item => item.TenantId == session.User.TenantId || item.TenantId is null).TakeLast(30).Reverse() }),
        ("audit", "GET") => Results.Json(new { error = "Permissao insuficiente." }, statusCode: 403),
        _ => Results.NotFound(new { error = "Endpoint nao encontrado." })
    };
}

IResult HandleInvoice(string mode, string id, HttpContext http, LabStore store, TokenService tokens)
{
    var session = Authenticate(http, mode);
    if (session is null) return Results.Json(new { error = "Sessao invalida ou expirada." }, statusCode: 401);
    var invoice = mode == "vulnerable"
        ? store.Invoices.FirstOrDefault(item => item.Id == id)
        : store.Invoices.FirstOrDefault(item => item.Id == id && item.TenantId == session.User.TenantId);
    store.AuditEvents.Add(AuditEvent.Create(invoice is null ? "invoice_access_denied" : "invoice_viewed", mode, session.User.Name, session.User.TenantId, id, null, invoice is null ? "high" : "info"));
    return invoice is null ? Results.NotFound(new { error = "Fatura nao encontrada." }) : Results.Ok(new { invoice });
}

IResult CreateNote(HttpContext http, LabStore store, AuthSession session, string mode)
{
    var input = http.Request.ReadFromJsonAsync<NoteRequest>().GetAwaiter().GetResult() ?? new NoteRequest();
    var rawContent = input.Content ?? "";
    var content = mode == "secure" ? SecurityControls.SanitizePlainText(rawContent) : rawContent[..Math.Min(rawContent.Length, 2000)];
    if (string.IsNullOrWhiteSpace(content)) return Results.Json(new { error = "A nota nao pode ficar vazia." }, statusCode: 422);
    var note = new Note($"note-{Guid.NewGuid()}", session.User.TenantId, session.User.Name, content, DateTimeOffset.UtcNow.ToString("O"));
    store.Notes.Add(note);
    store.AuditEvents.Add(AuditEvent.Create("note_created", mode, session.User.Name, session.User.TenantId, note.Id));
    return Results.Created($"/api/{mode}/notes/{note.Id}", new { note });
}

AuthSession? Authenticate(HttpContext http, string mode)
{
    if (mode is not ("secure" or "vulnerable")) return null;
    var token = mode == "secure"
        ? http.Request.Cookies[accessCookie]
        : http.Request.Headers["Authorization"].ToString().StartsWith("Bearer ") ? http.Request.Headers["Authorization"].ToString()["Bearer ".Length..] : null;
    var payload = http.RequestServices.GetRequiredService<TokenService>().Verify(token);
    var store = http.RequestServices.GetRequiredService<LabStore>();
    if (payload is null || payload.Mode != mode || payload.Type != "access") return null;
    var user = store.Users.FirstOrDefault(item => item.Id == payload.Sub && item.TenantId == payload.TenantId && item.Role == payload.Role);
    return user is null ? null : new AuthSession(user, payload);
}

static bool ValidateCsrf(HttpContext http, AuthSession session) =>
    !HttpMethods.IsPost(http.Request.Method) || http.Request.Headers["X-CSRF-Token"] == session.Payload.Csrf;

public partial class Program;
