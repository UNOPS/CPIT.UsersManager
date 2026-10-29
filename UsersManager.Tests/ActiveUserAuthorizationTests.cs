using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

/// <summary>
///     A token outlives the account it was minted for, so both a bare <c>[Authorize]</c> (the default policy) and the
///     permission policies must re-check the account in the database.
/// </summary>
public class ActiveUserAuthorizationTests : IDisposable
{
    private readonly TestHost _host = new();

    private async Task<bool> DefaultPolicyAllowsAsync(ClaimsPrincipal user)
    {
        var policy = await _host.Get<IAuthorizationPolicyProvider>().GetDefaultPolicyAsync();
        return (await _host.Get<IAuthorizationService>().AuthorizeAsync(user, null, policy)).Succeeded;
    }

    private async Task<bool> PermissionAllowsAsync(ClaimsPrincipal user)
    {
        var result = await _host.Get<IAuthorizationService>()
            .AuthorizeAsync(user, null, nameof(TestPermissions.CanDoAdminThings));
        return result.Succeeded;
    }

    [Fact]
    public async Task AnActiveAccountPassesTheDefaultPolicy()
    {
        var user = await _host.CreateUserAsync();

        Assert.True(await DefaultPolicyAllowsAsync(TestHost.TokenFor(user.Email!)));
    }

    [Fact]
    public async Task ADeactivatedAccountFailsTheDefaultPolicy()
    {
        var user = await _host.CreateUserAsync();
        await _host.DeactivateAsync(user);

        Assert.False(await DefaultPolicyAllowsAsync(TestHost.TokenFor(user.Email!)));
    }

    [Fact]
    public async Task AnAccountThatWasNeverActivatedFailsTheDefaultPolicy()
    {
        var user = await _host.CreateUserAsync(active: false);

        Assert.False(await DefaultPolicyAllowsAsync(TestHost.TokenFor(user.Email!)));
    }

    [Fact]
    public async Task ALockedOutAccountFailsTheDefaultPolicy()
    {
        var user = await _host.CreateUserAsync();
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        Assert.False(await DefaultPolicyAllowsAsync(TestHost.TokenFor(user.Email!)));
    }

    [Fact]
    public async Task ARemovedAccountFailsTheDefaultPolicy()
    {
        Assert.False(await DefaultPolicyAllowsAsync(TestHost.TokenFor("deleted@example.org")));
    }

    [Fact]
    public async Task AnAnonymousCallerFailsTheDefaultPolicy()
    {
        Assert.False(await DefaultPolicyAllowsAsync(new ClaimsPrincipal(new ClaimsIdentity())));
    }

    [Fact]
    public async Task AnImpersonationByAnActiveAdministratorPassesTheDefaultPolicy()
    {
        var target = await _host.CreateUserAsync();
        var administrator = await _host.CreateUserAsync();

        Assert.True(await DefaultPolicyAllowsAsync(TestHost.TokenFor(target.Email!, administrator.Email)));
    }

    [Fact]
    public async Task AnImpersonationByADeactivatedAdministratorFailsTheDefaultPolicy()
    {
        var target = await _host.CreateUserAsync();
        var administrator = await _host.CreateUserAsync();
        await _host.DeactivateAsync(administrator);

        Assert.False(await DefaultPolicyAllowsAsync(TestHost.TokenFor(target.Email!, administrator.Email)));
    }

    [Fact]
    public async Task AnActiveAccountWithTheRolePassesAPermissionPolicy()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);

        Assert.True(await PermissionAllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    [Fact]
    public async Task ALockedOutAccountWithTheRoleFailsAPermissionPolicy()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        Assert.False(await PermissionAllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    [Fact]
    public async Task AnImpersonationByADeactivatedAdministratorFailsAPermissionPolicy()
    {
        var target = await _host.CreateUserAsync(true, TestRole.Admin);
        var administrator = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.DeactivateAsync(administrator);

        Assert.False(await PermissionAllowsAsync(
            TestHost.TokenFor(target.Email!, administrator.Email, TestRole.Admin)));
    }

    public void Dispose() => _host.Dispose();
}

/// <summary>
///     <c>[Authorize(Roles = ...)]</c> builds a policy with only a role requirement, without the default policy's
///     <see cref="ActiveUserRequirement" />, so the roles handler is the only database check it gets.
/// </summary>
public class RolesAttributeAuthorizationTests : IDisposable
{
    private readonly TestHost _host = new();

    private static readonly AuthorizationPolicy RolesOnly =
        new AuthorizationPolicyBuilder().RequireRole(TestRole.Admin).Build();

    private async Task<bool> AllowsAsync(ClaimsPrincipal user) =>
        (await _host.Get<IAuthorizationService>().AuthorizeAsync(user, null, RolesOnly)).Succeeded;

    [Fact]
    public void TheRolesAttributeDoesNotIncludeTheDefaultPolicy()
    {
        Assert.DoesNotContain(RolesOnly.Requirements, r => r is ActiveUserRequirement);
    }

    [Fact]
    public async Task AnActiveAccountWithTheRolePasses()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);

        Assert.True(await AllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    [Fact]
    public async Task ALockedOutAccountWithTheRoleFails()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.LockOutAsync(user, DateTimeOffset.UtcNow.AddHours(1));

        Assert.False(await AllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    [Fact]
    public async Task ADeactivatedAccountWithTheRoleFails()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.DeactivateAsync(user);

        Assert.False(await AllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    [Fact]
    public async Task AnAccountWhoseRoleWasRemovedFails()
    {
        var user = await _host.CreateUserAsync(true, TestRole.Admin);
        await _host.Get<UsersServices>().AssignRoles(user);

        Assert.False(await AllowsAsync(TestHost.TokenFor(user.Email!, null, TestRole.Admin)));
    }

    public void Dispose() => _host.Dispose();
}
