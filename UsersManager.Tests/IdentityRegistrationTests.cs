using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using UsersManager.Domain;

namespace UsersManager.Tests;

/// <summary>
///     Until 5.0.0 the library called <c>AddIdentity</c>, which also registered Identity's cookie schemes, unconfigured,
///     and <see cref="SignInManager{TUser}" />, a second way to sign in alongside the JWT.
/// </summary>
public class IdentityRegistrationTests : IDisposable
{
    private readonly TestHost _host = new();

    [Fact]
    public async Task TheBearerSchemeIsTheOnlyAuthenticationScheme()
    {
        var schemes = await _host.Get<IAuthenticationSchemeProvider>().GetAllSchemesAsync();

        Assert.Equal([JwtBearerDefaults.AuthenticationScheme], schemes.Select(s => s.Name));
    }

    [Fact]
    public async Task SigningInWithoutASchemeThrowsInsteadOfIssuingACookie()
    {
        var context = new DefaultHttpContext { RequestServices = _host.Services };
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, "a@example.org")], "Test"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => context.SignInAsync(user));
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
    }

    [Fact]
    public void SignInManagerIsNotRegistered()
    {
        Assert.Null(_host.Services.GetService<SignInManager<ApplicationUser>>());
    }

    [Fact]
    public void UserAndRoleManagementIsStillRegistered()
    {
        Assert.NotNull(_host.Get<UserManager<ApplicationUser>>());
        Assert.NotNull(_host.Get<RoleManager<ApplicationRole>>());
        Assert.True(_host.Get<IOptions<IdentityOptions>>().Value.User.RequireUniqueEmail);
    }

    public void Dispose() => _host.Dispose();
}
