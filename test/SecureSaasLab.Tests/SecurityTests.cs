using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
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
    public async Task SecureSessionUsesHttpOnlyCookiesAndCsrf()
    {
        var login = await LoginSecure();
        Assert.Equal(HttpStatusCode.OK, login.Response.StatusCode);
        Assert.Contains(login.Cookies, cookie => cookie.Contains("HttpOnly") && cookie.Contains("SameSite=Strict"));
        Assert.True(login.Payload.RootElement.TryGetProperty("csrfToken", out _));
        Assert.False(login.Payload.RootElement.TryGetProperty("token", out _));
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

    private async Task<(HttpResponseMessage Response, JsonDocument Payload, string[] Cookies, string CookieHeader)> LoginSecure()
    {
        var response = await _client.PostAsJsonAsync("/api/secure/login", new { email = "ana@acme.test", password = "Secure123!", mfaCode = "482911" });
        var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? values.ToArray() : [];
        return (response, payload, cookies, string.Join("; ", cookies.Select(cookie => cookie.Split(';')[0])));
    }
}
