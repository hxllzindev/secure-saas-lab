using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography;
using SecureSaasLab.Api;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace SecureSaasLab.Tests;

public sealed class SecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;
    private readonly HttpClient _labClient;
    private readonly LabStore _store;

    public SecurityTests(WebApplicationFactory<Program> factory)
    {
        _store = factory.Services.GetRequiredService<LabStore>();
        var options = new WebApplicationFactoryClientOptions { HandleCookies = false };
        _client = factory.CreateClient(options);
        _labClient = factory
            .WithWebHostBuilder(host => host.UseSetting("ALLOW_INSECURE_LAB", "true"))
            .CreateClient(options);
    }

    [Fact]
    public async Task ServesInterfaceWithDefensiveHeaders()
    {
        var response = await _client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task VulnerableFlowAllowsUserEnumeration()
    {
        var unknown = await _labClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "naoexiste@example.test", password = "qualquer" });
        var wrongPassword = await _labClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "incorreta" });
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongPassword.StatusCode);
    }

    [Fact]
    public async Task SecureFlowUsesGenericInvalidCredentialResponse()
    {
        var unknown = await _client.PostAsJsonAsync("/api/secure/login", new { email = "outro@example.test", password = "qualquer", mfaCode = "000000" });
        var wrong = await _client.PostAsJsonAsync("/api/secure/login", new { email = "caio@acme.test", password = "incorreta", mfaCode = "731204" });
        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(await unknown.Content.ReadAsStringAsync(), await wrong.Content.ReadAsStringAsync());
    }

    [Fact]
    public void UserAccountToStringDoesNotExposeCredentials()
    {
        var user = SecureSaasLab.Api.Seed.Create().Users.First();
        var text = user.ToString();

        Assert.DoesNotContain("Secure123!", text);
        Assert.DoesNotContain(user.MfaCode, text);
    }

    [Fact]
    public void AuditEventsRemainWithinConfiguredCapacity()
    {
        var store = new LabStore();
        for (var index = 0; index < LabStore.MaxAuditEvents + 5; index++)
            store.AddAudit(AuditEvent.Create($"event-{index}", "secure"));

        Assert.Equal(LabStore.MaxAuditEvents, store.AuditEvents.Count);
        Assert.Equal("event-5", store.AuditEvents.Peek().Action);
    }

    [Fact]
    public void StaleLoginAttemptKeysArePrunedWhenAtCapacity()
    {
        var store = new LabStore();
        var expired = DateTimeOffset.UtcNow.AddMinutes(-2);
        for (var index = 0; index < SecurityControls.MaxLoginAttemptKeys; index++)
            store.LoginAttempts[$"expired-{index}"] = [expired];

        Assert.True(SecurityControls.CheckRateLimit(store, "new-account", out _));
        Assert.Single(store.LoginAttempts);
    }

    [Fact]
    public void DistinctLoginAttemptKeysRemainBounded()
    {
        var store = new LabStore();
        for (var index = 0; index < 1000; index++)
            Assert.True(SecurityControls.CheckRateLimit(store, $"account-{index}", out _));

        Assert.Equal(1000, store.LoginAttempts.Count);
        Assert.True(store.LoginAttempts.Count <= SecurityControls.MaxLoginAttemptKeys);
    }

    [Fact]
    public void OldRefreshSessionsArePurgedButRecentSessionsRemain()
    {
        var store = new LabStore();
        var now = DateTimeOffset.UtcNow;
        store.RefreshSessions["expired-old"] = new RefreshSession
        {
            TokenHash = "expired-old",
            FamilyId = "family-old",
            UserId = "user",
            TenantId = "tenant",
            ExpiresAt = now.AddHours(-2)
        };
        store.RefreshSessions["revoked-old"] = new RefreshSession
        {
            TokenHash = "revoked-old",
            FamilyId = "family-revoked",
            UserId = "user",
            TenantId = "tenant",
            ExpiresAt = now.AddDays(1),
            RevokedAt = now.AddHours(-2)
        };
        store.RefreshSessions["recent"] = new RefreshSession
        {
            TokenHash = "recent",
            FamilyId = "family-recent",
            UserId = "user",
            TenantId = "tenant",
            ExpiresAt = now.AddDays(1)
        };

        store.PurgeStaleRefreshSessions(now);

        Assert.Equal(["recent"], store.RefreshSessions.Keys);
    }

    [Fact]
    public async Task InvalidRefreshRequestsAreRateLimited()
    {
        var responses = new List<HttpResponseMessage>();
        for (var index = 0; index < 21; index++)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/secure/session/refresh");
            request.Headers.Add("Cookie", "aegis_refresh=unknown-token");
            request.Headers.Add("X-Requested-With", "AegisLedger");
            AddSameOriginHeaders(request);
            responses.Add(await _client.SendAsync(request));
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, responses[^1].StatusCode);
        Assert.True(responses[^1].Headers.Contains("Retry-After"));
        foreach (var response in responses) response.Dispose();
    }

    [Fact]
    public async Task NotesBeyondTenantLimitReturn422()
    {
        var existingCount = _store.NotesForTenant("acme").Length;
        for (var index = existingCount; index < LabStore.MaxNotesPerTenant; index++)
        {
            Assert.True(_store.TryAddNote(new Note($"limit-{index}", "acme", "Ana Silva", "nota", DateTimeOffset.UtcNow.ToString("O"))));
        }

        var login = await LoginSecure();
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/secure/notes")
        {
            Content = JsonContent.Create(new { content = "nota excedente" })
        };
        request.Headers.Add("Cookie", login.CookieHeader);
        AddSameOriginHeaders(request);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, (await _client.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task MfaIsRequiredOnlyInSecureFlow()
    {
        var secure = await _client.PostAsJsonAsync("/api/secure/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
        var vulnerable = await _labClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
        Assert.Equal(HttpStatusCode.Unauthorized, secure.StatusCode);
        Assert.Equal(HttpStatusCode.OK, vulnerable.StatusCode);
    }

    [Fact]
    public async Task SecureSessionUsesHttpOnlyCookiesWithoutBrowserTokens()
    {
        var login = await LoginSecure();
        Assert.Equal(HttpStatusCode.OK, login.Response.StatusCode);
        Assert.Contains(login.Cookies, cookie => cookie.Contains("HttpOnly") && cookie.Contains("SameSite=Strict"));
        Assert.False(login.Payload.RootElement.TryGetProperty("csrfToken", out _));
        Assert.False(login.Payload.RootElement.TryGetProperty("token", out _));
        var user = login.Payload.RootElement.GetProperty("user");
        Assert.False(user.TryGetProperty("email", out _));
        Assert.False(user.TryGetProperty("tenantId", out _));
        Assert.False(user.TryGetProperty("name", out _));
    }

    [Fact]
    public async Task VulnerableFlowReproducesBolaAcrossTenants()
    {
        var login = await _labClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
        var payload = await JsonDocument.ParseAsync(await login.Content.ReadAsStreamAsync());
        var token = payload.RootElement.GetProperty("token").GetString();
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/vulnerable/invoices/inv-2001");
        request.Headers.Add("Authorization", $"Bearer {token}");
        var response = await _labClient.SendAsync(request);
        var invoicePayload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("orbit", invoicePayload.RootElement.GetProperty("invoice").GetProperty("tenantId").GetString());
    }

    [Fact]
    public async Task SecureFlowBlocksBolaAndRequiresCsrfOnWrites()
    {
        var login = await LoginSecure();
        var bola = new HttpRequestMessage(HttpMethod.Get, "/api/secure/invoices/inv-2001");
        bola.Headers.Add("Cookie", login.CookieHeader);
        var denied = await _client.SendAsync(bola);
        Assert.Equal(HttpStatusCode.NotFound, denied.StatusCode);

        var write = new HttpRequestMessage(HttpMethod.Post, "/api/secure/notes") { Content = JsonContent.Create(new { content = "nao deve criar" }) };
        write.Headers.Add("Cookie", login.CookieHeader);
        var csrf = await _client.SendAsync(write);
        Assert.Equal(HttpStatusCode.Forbidden, csrf.StatusCode);
    }

    [Fact]
    public async Task SecureLogoutRequiresSameOriginMetadata()
    {
        var login = await LoginSecure();
        var withoutCsrf = new HttpRequestMessage(HttpMethod.Post, "/api/secure/session/logout") { Content = JsonContent.Create(new { }) };
        withoutCsrf.Headers.Add("Cookie", login.CookieHeader);
        Assert.Equal(HttpStatusCode.Forbidden, (await _client.SendAsync(withoutCsrf)).StatusCode);

        var sameOrigin = new HttpRequestMessage(HttpMethod.Post, "/api/secure/session/logout") { Content = JsonContent.Create(new { }) };
        sameOrigin.Headers.Add("Cookie", login.CookieHeader);
        AddSameOriginHeaders(sameOrigin);
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(sameOrigin)).StatusCode);
    }

    [Fact]
    public async Task ConcurrentRefreshAllowsOnlyOneRotation()
    {
        var login = await LoginSecure();
        HttpRequestMessage RefreshRequest()
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/secure/session/refresh") { Content = JsonContent.Create(new { }) };
            request.Headers.Add("Cookie", login.CookieHeader);
            request.Headers.Add("X-Requested-With", "AegisLedger");
            AddSameOriginHeaders(request);
            return request;
        }

        var responses = await Task.WhenAll(_client.SendAsync(RefreshRequest()), _client.SendAsync(RefreshRequest()));
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
        Assert.Single(responses, response => response.StatusCode == HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ProductionDisablesVulnerableModeWithoutExplicitOptIn()
    {
        await using var productionFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(webHost =>
        {
            webHost.UseEnvironment("Production");
            webHost.UseSetting("TOKEN_SECRET", Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)));
        });
        using var productionClient = productionFactory.CreateClient();
        var response = await productionClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!" });
    Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    [InlineData("Production")]
    public async Task NonProductionEnvironmentWithoutOptInDisablesVulnerableMode(string environment)
    {
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(host =>
        {
            host.UseEnvironment(environment);
            host.UseSetting("TOKEN_SECRET", Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)));
        });
        using var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!" });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")]
    [InlineData("replace-with-at-least-32-random-bytes")]
    [InlineData("0123456789012345678901234567890")]
    public void WeakTokenSecretIsRejected(string secret)
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(host =>
        {
            host.UseEnvironment("Staging");
            host.UseSetting("TOKEN_SECRET", secret);
        });

        Assert.Throws<InvalidOperationException>(() => factory.CreateClient());
    }

    private async Task<(HttpResponseMessage Response, JsonDocument Payload, string[] Cookies, string CookieHeader)> LoginSecure()
    {
        var response = await _client.PostAsJsonAsync("/api/secure/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "482911" });
        var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];
        return (response, payload, cookies, string.Join("; ", cookies.Select(cookie => cookie.Split(';')[0])));
    }

    private static void AddSameOriginHeaders(HttpRequestMessage request)
    {
        request.Headers.Add("Origin", "http://localhost");
        request.Headers.Add("Sec-Fetch-Site", "same-origin");
    }
}
