using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using UsersManager.Domain;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

public class AccountLinkingTests : IDisposable
{
    private readonly TestHost _host = new();

    private static UserLoginInfo NewGoogleLogin() =>
        new(JwtHandler.GoogleProvider, Guid.NewGuid().ToString("N"), JwtHandler.GoogleProvider);

    private Task<Models.AuthResponseDto> LoginAsync(UserLoginInfo info, string? email) =>
        _host.Get<UsersServices>().Login(info, _host.Get<IConfiguration>(), email);

    private async Task<ApplicationUser> CreateProvisionedUserAsync()
    {
        var email = $"invited.{Guid.NewGuid():N}@example.org";
        var user = new ApplicationUser { Email = email, UserName = email };
        user.Activate();
        Assert.True((await _host.Get<UserManager<ApplicationUser>>().CreateAsync(user)).Succeeded);
        return user;
    }

    [Fact]
    public async Task TheFirstSignInClaimsAnAccountCreatedByEMail()
    {
        var user = await CreateProvisionedUserAsync();
        var login = NewGoogleLogin();

        var registered = await _host.Get<UsersServices>().Register(login, user.Email!);

        Assert.Equal(user.Id, registered.Id);
        Assert.Equal(login.ProviderKey, (await _host.LoginOfAsync(user)).ProviderKey);
        Assert.True((await LoginAsync(login, user.Email)).IsAuthSuccessful);
    }

    [Fact]
    public async Task AnAccountCreatedByEMailCanSignInBeforeItIsLinked()
    {
        var user = await CreateProvisionedUserAsync();

        var response = await LoginAsync(NewGoogleLogin(), user.Email);

        Assert.True(response.IsAuthSuccessful);
    }

    [Fact]
    public async Task ADifferentLoginWithTheSameEMailGetsNoToken()
    {
        var victim = await _host.CreateUserAsync();

        var response = await LoginAsync(NewGoogleLogin(), victim.Email);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
    }

    [Theory]
    [InlineData(JwtHandler.GoogleProvider)]
    [InlineData("Microsoft")]
    public async Task ADifferentLoginWithTheSameEMailIsNotLinked(string provider)
    {
        var victim = await _host.CreateUserAsync();
        var attacker = new UserLoginInfo(provider, Guid.NewGuid().ToString("N"), provider);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _host.Get<UsersServices>().Register(attacker, victim.Email!));

        Assert.Single(await _host.Get<UserManager<ApplicationUser>>().GetLoginsAsync(victim));
        Assert.False((await LoginAsync(attacker, victim.Email)).IsAuthSuccessful);
    }

    [Fact]
    public async Task RegisteringAgainWithTheSameLoginReturnsTheSameAccount()
    {
        var user = await _host.CreateUserAsync();
        var login = await _host.LoginOfAsync(user);

        var again = await _host.Get<UsersServices>().Register(login, user.Email!);

        Assert.Equal(user.Id, again.Id);
        Assert.Single(await _host.Get<UserManager<ApplicationUser>>().GetLoginsAsync(user));
    }

    [Fact]
    public async Task TwoAccountsCannotShareAnEMailAddress()
    {
        var user = await _host.CreateUserAsync();
        var email = user.Email!.ToUpperInvariant();

        var result = await _host.Get<UserManager<ApplicationUser>>()
            .CreateAsync(new ApplicationUser { Email = email, UserName = $"other.{email}" });

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task OnlyGoogleTokensAreVerified()
    {
        var auth = new ExternalAuthDto { Provider = "Facebook", IdToken = "not-checked" };

        await Assert.ThrowsAsync<InvalidJwtException>(() => _host.Get<JwtHandler>().VerifyGoogleToken(auth));
    }

    /// <summary>Google throws an ArgumentException for these, which callers catching InvalidJwtException missed.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public async Task AMissingIdTokenIsAnInvalidToken(string? idToken)
    {
        var auth = new ExternalAuthDto { Provider = JwtHandler.GoogleProvider, IdToken = idToken! };

        await Assert.ThrowsAsync<InvalidJwtException>(() => _host.Get<JwtHandler>().VerifyGoogleToken(auth));
    }

    [Theory]
    [InlineData(false, "user@example.org")]
    [InlineData(true, null)]
    public void AGoogleAccountWithoutAVerifiedEMailIsRefused(bool emailVerified, string? email)
    {
        var payload = new GoogleJsonWebSignature.Payload { EmailVerified = emailVerified, Email = email };

        Assert.Throws<InvalidJwtException>(() => JwtHandler.EnsureEmailVerified(payload));
    }

    [Fact]
    public void AGoogleAccountWithAVerifiedEMailIsAccepted()
    {
        JwtHandler.EnsureEmailVerified(new GoogleJsonWebSignature.Payload
            { EmailVerified = true, Email = "user@example.org" });
    }

    public void Dispose() => _host.Dispose();
}
