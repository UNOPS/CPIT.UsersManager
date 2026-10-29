using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using UsersManager.Domain;
using UsersManager.Helpers;
using UsersManager.Models;
using UsersManager.Security;

namespace UsersManager.Tests;

/// <summary>
///     Impersonation mints a token in someone else's name, so it must only be issued between accounts that may sign
///     in, stay within the configured lifetime, leave a trace, and be refusable for sensitive actions.
/// </summary>
public class ImpersonationTests : IDisposable
{
    private readonly TestHost _host = new();

    private Task<AuthResponseDto> ImpersonateAsync(ClaimsPrincipal impersonator, string userEmail,
        TimeSpan? lifetime = null) =>
        _host.Get<UsersServices>().Impersonate(impersonator, userEmail, _host.Get<IConfiguration>(), null, lifetime);

    private async Task<(ApplicationUser Admin, ApplicationUser User)> AdminAndUserAsync()
    {
        var admin = await _host.CreateUserAsync(true, TestRole.Admin);
        var user = await _host.CreateUserAsync();
        return (admin, user);
    }

    [Fact]
    public async Task AnActiveAccountCanBeImpersonated()
    {
        var (admin, user) = await AdminAndUserAsync();

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), user.Email!);

        Assert.True(response.IsAuthSuccessful);
        Assert.Equal(admin.Email, response.Impersonator);
        var principal = Validate(response.Token!);
        Assert.Equal(user.Email, principal.Identity!.Name);
        Assert.Equal(admin.Email, principal.GetImpersonator());
        Assert.True(principal.IsImpersonated());
    }

    [Fact]
    public async Task AnImpersonationTokenCarriesTheUsersRolesNotTheImpersonators()
    {
        var (admin, user) = await AdminAndUserAsync();

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), user.Email!);

        Assert.Empty(Validate(response.Token!).FindAll(ClaimTypes.Role));
    }

    [Fact]
    public async Task IssuingAnImpersonationTokenIsLoggedWithBothAccountsAndTheTokenId()
    {
        var (admin, user) = await AdminAndUserAsync();

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), user.Email!);

        var jti = new JwtSecurityTokenHandler().ReadJwtToken(response.Token).Id;
        var entry = Assert.Single(_host.Logs, l => l.EventId == JwtHandler.ImpersonationTokenIssued);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(admin.Email!, entry.Message);
        Assert.Contains(user.Email!, entry.Message);
        Assert.Contains(jti, entry.Message);
    }

    /// <summary>This used to throw an ArgumentNullException.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task AMissingUserEmailIsRefusedWithoutThrowing(string? userEmail)
    {
        var admin = await _host.CreateUserAsync(true, TestRole.Admin);

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), userEmail!);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
    }

    [Fact]
    public async Task AnOrdinaryLoginIsNotLoggedAsImpersonation()
    {
        var user = await _host.CreateUserAsync();

        await _host.Get<UsersServices>().Login(await _host.LoginOfAsync(user), _host.Get<IConfiguration>());

        Assert.DoesNotContain(_host.Logs, l => l.EventId == JwtHandler.ImpersonationTokenIssued);
    }

    public static TheoryData<string> UnusableAccounts => new() { "inactive", "locked out", "unknown" };

    [Theory]
    [MemberData(nameof(UnusableAccounts))]
    public async Task AnAccountThatCannotSignInCannotBeImpersonated(string state)
    {
        var admin = await _host.CreateUserAsync(true, TestRole.Admin);
        var email = await AccountInStateAsync(state);

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), email);

        AssertRefused(response);
    }

    [Theory]
    [MemberData(nameof(UnusableAccounts))]
    public async Task AnImpersonatorWhoCannotSignInCannotImpersonate(string state)
    {
        var user = await _host.CreateUserAsync();
        var email = await AccountInStateAsync(state);

        var response = await ImpersonateAsync(TestHost.TokenFor(email), user.Email!);

        AssertRefused(response);
    }

    [Fact]
    public async Task AnImpersonationTokenCannotStartAnotherImpersonation()
    {
        var (admin, user) = await AdminAndUserAsync();
        var other = await _host.CreateUserAsync();

        var response = await ImpersonateAsync(TestHost.TokenFor(user.Email!, admin.Email), other.Email!);

        AssertRefused(response);
    }

    [Fact]
    public async Task AnAccountCannotImpersonateItself()
    {
        var admin = await _host.CreateUserAsync(true, TestRole.Admin);

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), admin.Email!.ToUpperInvariant());

        AssertRefused(response);
    }

    [Fact]
    public async Task AnAnonymousCallerCannotImpersonate()
    {
        var user = await _host.CreateUserAsync();

        var response = await ImpersonateAsync(new ClaimsPrincipal(new ClaimsIdentity()), user.Email!);

        AssertRefused(response);
    }

    [Fact]
    public async Task ARefusalIsLogged()
    {
        var (admin, _) = await AdminAndUserAsync();

        await ImpersonateAsync(TestHost.TokenFor(admin.Email!), "nobody@example.org");

        var entry = Assert.Single(_host.Logs, l => l.EventId == UsersServices.ImpersonationRefused);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(admin.Email!, entry.Message);
        Assert.Contains("nobody@example.org", entry.Message);
    }

    [Fact]
    public async Task ALifetimeBeyondTheConfiguredMaximumIsRefused()
    {
        var (admin, user) = await AdminAndUserAsync();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            ImpersonateAsync(TestHost.TokenFor(admin.Email!), user.Email!, TimeSpan.FromDays(3650)));
        Assert.DoesNotContain(_host.Logs, l => l.EventId == JwtHandler.ImpersonationTokenIssued);
    }

    [Fact]
    public async Task AShorterLifetimeIsHonoured()
    {
        var (admin, user) = await AdminAndUserAsync();

        var response = await ImpersonateAsync(TestHost.TokenFor(admin.Email!), user.Email!, TimeSpan.FromMinutes(5));

        var token = new JwtSecurityTokenHandler().ReadJwtToken(response.Token);
        Assert.Equal(TimeSpan.FromMinutes(5), token.ValidTo - token.IssuedAt);
    }

    [Fact]
    public async Task ImpersonationRefusedForAnActionThatDisallowsIt()
    {
        var admin = await _host.CreateUserAsync(true, TestRole.Admin);
        // The impersonated account holds the role, so only the impersonation can be what refuses it.
        var target = await _host.CreateUserAsync(true, TestRole.Admin);

        Assert.False(await AllowsAsync(TestHost.TokenFor(target.Email!, admin.Email),
            nameof(TestPermissions.CanDoAdminThingsInOwnName)));
        Assert.True(await AllowsAsync(TestHost.TokenFor(target.Email!, admin.Email),
            nameof(TestPermissions.CanDoAdminThings)));
        Assert.True(await AllowsAsync(TestHost.TokenFor(target.Email!),
            nameof(TestPermissions.CanDoAdminThingsInOwnName)));
    }

    private async Task<bool> AllowsAsync(ClaimsPrincipal user, string policy) =>
        (await _host.Get<IAuthorizationService>().AuthorizeAsync(user, null, policy)).Succeeded;

    private async Task<string> AccountInStateAsync(string state)
    {
        switch (state)
        {
            case "inactive":
                return (await _host.CreateUserAsync(active: false)).Email!;
            case "locked out":
                var user = await _host.CreateUserAsync();
                await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));
                return user.Email!;
            default:
                return "nobody@example.org";
        }
    }

    private static void AssertRefused(AuthResponseDto response)
    {
        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
        Assert.Null(response.Impersonator);
        Assert.False(string.IsNullOrEmpty(response.ErrorMessage));
    }

    private ClaimsPrincipal Validate(string token)
    {
        var parameters = _host.Get<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        return new JwtSecurityTokenHandler().ValidateToken(token, parameters, out _);
    }

    public void Dispose() => _host.Dispose();
}

/// <summary>Any token, impersonation or not, is capped so that no code path can mint a long-lived one.</summary>
public class TokenLifetimeTests
{
    private static async Task<JwtSecurityToken> MintAsync(TestHost host, TimeSpan? lifetime) =>
        new JwtSecurityTokenHandler().ReadJwtToken(
            await host.Get<JwtHandler>().GenerateToken("user@example.org", [], null, null, lifetime));

    [Fact]
    public async Task WithoutALifetimeATokenLivesForExpiryInMinutes()
    {
        using var host = new TestHost();

        var token = await MintAsync(host, null);

        Assert.Equal(TimeSpan.FromMinutes(15), token.ValidTo - token.IssuedAt);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(5256000)]
    public async Task WithoutAMaximumNoLifetimeMayExceedExpiryInMinutes(int minutes)
    {
        using var host = new TestHost();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => MintAsync(host, TimeSpan.FromMinutes(minutes)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public async Task ALifetimeMustBePositive(int minutes)
    {
        using var host = new TestHost();

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => MintAsync(host, TimeSpan.FromMinutes(minutes)));
    }

    [Fact]
    public async Task MaxLifetimeInMinutesAllowsLongerTokensUpToIt()
    {
        using var host = new TestHost(new Dictionary<string, string?> { ["JwtSettings:maxLifetimeInMinutes"] = "60" });

        var token = await MintAsync(host, TimeSpan.FromMinutes(60));

        Assert.Equal(TimeSpan.FromMinutes(60), token.ValidTo - token.IssuedAt);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => MintAsync(host, TimeSpan.FromMinutes(61)));
    }

    [Fact]
    public async Task AnImpersonatorMustBeNamed()
    {
        using var host = new TestHost();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            host.Get<JwtHandler>().GenerateToken("user@example.org", [], " "));
    }
}
