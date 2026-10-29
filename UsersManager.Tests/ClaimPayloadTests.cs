using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using UsersManager.Helpers;
using UsersManager.Models;
using UsersManager.Security;

namespace UsersManager.Tests;

public class ClaimPayloadTests : IDisposable
{
    private readonly TestHost _host = new();

    private static ClaimPayload[] Payload(string name, params string[] values) =>
        [new ClaimPayload { ClaimName = name, ClaimValues = values }];

    [Theory]
    [InlineData(ClaimTypes.Role)]
    [InlineData("role")]
    [InlineData("roles")]
    [InlineData(ClaimTypes.Name)]
    [InlineData("unique_name")]
    [InlineData(ClaimTypes.NameIdentifier)]
    [InlineData("nameid")]
    [InlineData("sub")]
    [InlineData(JwtHandler.ImpersonatorClaim)]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("exp")]
    [InlineData("nbf")]
    [InlineData("iat")]
    [InlineData("jti")]
    public void AReservedClaimTypeIsRefused(string claimName)
    {
        var handler = _host.Get<JwtHandler>();

        Assert.Throws<ArgumentException>(() =>
            handler.GetClaims("user@example.org", [], null, Payload(claimName, "forged")));
    }

    /// <summary><see cref="ClaimsIdentity.IsInRole" /> and <c>FindFirst</c> match claim types ignoring case.</summary>
    [Theory]
    [InlineData("HTTP://SCHEMAS.MICROSOFT.COM/WS/2008/06/IDENTITY/CLAIMS/ROLE")]
    [InlineData("Role")]
    [InlineData("IMPERSONATOR")]
    public void AReservedClaimTypeIsRefusedInAnyCase(string claimName)
    {
        var handler = _host.Get<JwtHandler>();

        Assert.Throws<ArgumentException>(() =>
            handler.GetClaims("user@example.org", [], null, Payload(claimName, "forged")));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void AClaimWithoutANameIsRefused(string? claimName)
    {
        var handler = _host.Get<JwtHandler>();

        Assert.Throws<ArgumentException>(() =>
            handler.GetClaims("user@example.org", [], null, Payload(claimName!, "value")));
    }

    [Fact]
    public async Task LoginIssuesNoTokenForAReservedClaim()
    {
        var user = await _host.CreateUserAsync();
        var login = await _host.LoginOfAsync(user);

        await Assert.ThrowsAsync<ArgumentException>(() => _host.Get<UsersServices>()
            .Login(login, _host.Get<IConfiguration>(), user.Email, Payload(ClaimTypes.Role, "SystemAdmin")));
    }

    [Fact]
    public async Task ACustomClaimSurvivesTokenValidationAndGrantsNoRole()
    {
        var token = await _host.Get<JwtHandler>()
            .GenerateToken("user@example.org", [], null, Payload("tenant", "unops", "undp"));

        var principal = Validate(token);

        Assert.Equal(["unops", "undp"], principal.FindAll("tenant").Select(c => c.Value));
        Assert.Equal("user@example.org", principal.Identity!.Name);
        Assert.Empty(principal.FindAll(ClaimTypes.Role));
    }

    [Fact]
    public void AClaimWithNoValuesAddsNothing()
    {
        var claims = _host.Get<JwtHandler>().GetClaims("user@example.org", [], null,
            [new ClaimPayload { ClaimName = "tenant", ClaimValues = null! }]);

        Assert.DoesNotContain(claims, c => c.Type == "tenant");
    }

    private ClaimsPrincipal Validate(string token)
    {
        var parameters = _host.Get<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        return new JwtSecurityTokenHandler().ValidateToken(token, parameters, out _);
    }

    public void Dispose() => _host.Dispose();
}
