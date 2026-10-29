using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using UsersManager.Helpers;

namespace UsersManager.Tests;

public class LoginTests : IDisposable
{
    private readonly TestHost _host = new();

    private Task<Models.AuthResponseDto> LoginAsync(UserLoginInfo info, string? email) =>
        _host.Get<UsersServices>().Login(info, _host.Get<IConfiguration>(), email);

    [Fact]
    public async Task AnActiveAccountGetsAToken()
    {
        var user = await _host.CreateUserAsync();

        var response = await LoginAsync(await _host.LoginOfAsync(user), user.Email);

        Assert.True(response.IsAuthSuccessful);
        Assert.False(string.IsNullOrEmpty(response.Token));
        Assert.NotNull(user.LastLoginDate);
    }

    [Fact]
    public async Task AnAccountThatWasNeverActivatedGetsNoToken()
    {
        var user = await _host.CreateUserAsync(active: false);

        var response = await LoginAsync(await _host.LoginOfAsync(user), user.Email);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
        Assert.False(string.IsNullOrEmpty(response.ErrorMessage));
        Assert.Null(user.LastLoginDate);
    }

    [Fact]
    public async Task ADeactivatedAccountGetsNoToken()
    {
        var user = await _host.CreateUserAsync();
        await _host.DeactivateAsync(user);

        var response = await LoginAsync(await _host.LoginOfAsync(user), user.Email);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
    }

    [Fact]
    public async Task ALockedOutAccountGetsNoToken()
    {
        var user = await _host.CreateUserAsync();
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        var response = await LoginAsync(await _host.LoginOfAsync(user), user.Email);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
    }

    [Fact]
    public async Task AnExpiredLockoutNoLongerBlocksLogin()
    {
        var user = await _host.CreateUserAsync();
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddMinutes(-1));

        var response = await LoginAsync(await _host.LoginOfAsync(user), user.Email);

        Assert.True(response.IsAuthSuccessful);
    }

    /// <summary>This used to throw a NullReferenceException.</summary>
    [Theory]
    [InlineData("nobody@example.org")]
    [InlineData("")]
    [InlineData(null)]
    public async Task AnUnknownAccountIsRefusedWithoutThrowing(string? email)
    {
        var response = await LoginAsync(new UserLoginInfo("Google", "unknown-subject", "Google"), email);

        Assert.False(response.IsAuthSuccessful);
        Assert.Null(response.Token);
    }

    public void Dispose() => _host.Dispose();
}
