using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SecureSaasLab.Tests;

public sealed class SecurityTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public SecurityTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient(new WebApplicationFactoryClientOptions { HandleCookies = false });
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
        var unknown = await _client.PostAsJsonAsync("/api/vulnerable/login", new { email = "naoexiste@example.test", password = "qualquer" });
        var wrongPassword = await _client.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "incorreta" });
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
    public async Task MfaIsRequiredOnlyInSecureFlow()
    {
        var secure = await _client.PostAsJsonAsync("/api/secure/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
        var vulnerable = await _client.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
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
        var login = await _client.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "" });
        var payload = await JsonDocument.ParseAsync(await login.Content.ReadAsStreamAsync());
        var token = payload.RootElement.GetProperty("token").GetString();
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/vulnerable/invoices/inv-2001");
        request.Headers.Add("Authorization", $"Bearer {token}");
        var response = await _client.SendAsync(request);
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
            webHost.UseSetting("TOKEN_SECRET", new string('x', 48));
        });
        using var productionClient = productionFactory.CreateClient();
        var response = await productionClient.PostAsJsonAsync("/api/vulnerable/login", new { email = "ana@acme.test", password = "Secure123!" });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
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
