using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using UsersManager.Domain;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

/// <summary>
///     The roles in a token are those the account had when it was minted. <c>User.IsInRole</c> and
///     <see cref="Extensions.HasRoles(ClaimsPrincipal, string[])" /> must see the roles the account has now.
/// </summary>
public class RolesFromDatabaseTests : IDisposable
{
    private const string OtherRole = "TestOther";

    private readonly TestHost _host = new();

    public RolesFromDatabaseTests()
    {
        foreach (var role in new[] { TestRole.Admin, OtherRole })
            _host.Get<RoleManager<ApplicationRole>>().CreateAsync(new ApplicationRole { Name = role }).Wait();
    }

    private Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal) =>
        _host.Get<IClaimsTransformation>().TransformAsync(principal);

    [Fact]
    public async Task ARoleRemovedSinceTheTokenWasMintedIsNoLongerHeld()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        var token = TestHost.TokenFor(user.Email!, null, TestRole.Admin);
        await _host.Get<UsersServices>().AssignRoles(user);

        var principal = await TransformAsync(token);

        Assert.False(principal.HasRoles(TestRole.Admin));
        Assert.False(principal.IsInRole(TestRole.Admin));
    }

    [Fact]
    public async Task ARoleTheTokenClaimsButTheAccountNeverHadIsNotHeld()
    {
        var user = await _host.CreateUserAsync();

        var principal = await TransformAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin));

        Assert.False(principal.HasRoles(TestRole.Admin));
    }

    [Fact]
    public async Task ARoleAddedSinceTheTokenWasMintedIsHeld()
    {
        var user = await _host.CreateUserAsync(true, OtherRole);
        var token = TestHost.TokenFor(user.Email!, null, OtherRole);
        await _host.Get<UsersServices>().AssignRoles(user, OtherRole, TestRole.Admin);

        var principal = await TransformAsync(token);

        Assert.True(principal.HasRoles(TestRole.Admin));
        Assert.True(principal.HasRoles(OtherRole));
    }

    [Fact]
    public async Task ADeactivatedAccountHoldsNoRoles()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.DeactivateAsync(user);

        var principal = await TransformAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin));

        Assert.Empty(principal.FindAll(ClaimTypes.Role));
    }

    [Fact]
    public async Task ALockedOutAccountHoldsNoRoles()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        var principal = await TransformAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin));

        Assert.Empty(principal.FindAll(ClaimTypes.Role));
    }

    [Fact]
    public async Task TransformingTwiceDoesNotDuplicateRoles()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);

        var principal = await TransformAsync(await TransformAsync(TestHost.TokenFor(user.Email!)));

        Assert.Single(principal.FindAll(ClaimTypes.Role));
    }

    [Fact]
    public async Task AnAnonymousCallerIsLeftAlone()
    {
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Same(anonymous, await TransformAsync(anonymous));
    }

    /// <summary>Through the bearer handler, as a request would be, to show the transformation is the one in use.</summary>
    [Fact]
    public async Task AnAuthenticatedRequestSeesTheDatabaseRoles()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        var token = await _host.Get<JwtHandler>().GenerateToken(user.Email!, [TestRole.Admin]);
        await _host.Get<UsersServices>().AssignRoles(user, OtherRole);

        var httpContext = new DefaultHttpContext { RequestServices = _host.Services };
        httpContext.Request.Headers.Authorization = $"Bearer {token}";
        var result = await httpContext.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.False(result.Principal!.HasRoles(TestRole.Admin));
        Assert.True(result.Principal.IsInRole(OtherRole));
    }

    [Fact]
    public async Task EachTokenHasItsOwnIdAndAnIssueTime()
    {
        var handler = _host.Get<JwtHandler>();

        var first = new JwtSecurityTokenHandler().ReadJwtToken(await handler.GenerateToken("user@example.org", []));
        var second = new JwtSecurityTokenHandler().ReadJwtToken(await handler.GenerateToken("user@example.org", []));

        Assert.False(string.IsNullOrEmpty(first.Id));
        Assert.NotEqual(first.Id, second.Id);
        Assert.InRange(first.IssuedAt, DateTime.UtcNow.AddMinutes(-1), DateTime.UtcNow);
    }

    public void Dispose() => _host.Dispose();
}
