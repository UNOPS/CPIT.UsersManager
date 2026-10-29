using System.Dynamic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

/// <summary>Not public, so that the hosts in these tests, which read the test assembly, don't see them.</summary>
internal class FirstDeclaration : SystemPermissions
{
    public static readonly SystemAction Shared = new("Shared", TestRole.Admin);
    public static readonly SystemAction Alias = Shared;
}

internal class SecondDeclaration : SystemPermissions
{
    public static readonly SystemAction Shared = new("Shared", "SomeoneElse");
}

/// <summary>
///     Permission policies used to come from every assembly loaded at startup, a duplicate name silently replaced the
///     earlier policy, and an inactive permission had no policy at all, so using it threw on every request.
/// </summary>
public class PermissionPolicyTests
{
    private static Task<AuthorizationPolicy?> PolicyAsync(TestHost host, string name) =>
        host.Get<IAuthorizationPolicyProvider>().GetPolicyAsync(name);

    [Fact]
    public async Task ByDefaultTheCallingAssemblysPermissionsBecomePolicies()
    {
        using var host = new TestHost();

        Assert.NotNull(await PolicyAsync(host, nameof(TestPermissions.CanDoAdminThings)));
    }

    /// <summary>The test assembly is loaded, but it is not one the app registered.</summary>
    [Fact]
    public async Task AnAssemblyThatWasNotRegisteredAddsNoPolicies()
    {
        using var host = new TestHost(null, typeof(JwtHandler).Assembly);

        Assert.Null(await PolicyAsync(host, nameof(TestPermissions.CanDoAdminThings)));
    }

    [Fact]
    public async Task TheRegisteredAssembliesAreRead()
    {
        using var host = new TestHost(null, typeof(JwtHandler).Assembly, typeof(TestPermissions).Assembly);

        Assert.NotNull(await PolicyAsync(host, nameof(TestPermissions.CanDoAdminThings)));
    }

    [Fact]
    public void TwoPermissionsWithTheSameNameAreAnError()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            new PermissionCatalog([typeof(FirstDeclaration), typeof(SecondDeclaration)], []));

        Assert.Contains("'Shared'", error.Message);
        Assert.Contains(typeof(FirstDeclaration).FullName!, error.Message);
        Assert.Contains(typeof(SecondDeclaration).FullName!, error.Message);
    }

    [Fact]
    public void TwoFieldsForTheSameActionAreOnePermission()
    {
        var catalog = new PermissionCatalog([typeof(FirstDeclaration)], []);

        Assert.Equal([FirstDeclaration.Shared], catalog.Actions);
    }

    [Fact]
    public async Task AnInactivePermissionHasAPolicyThatRefusesEveryone()
    {
        using var host = new TestHost(new Dictionary<string, string?>
        {
            ["InactivePermissions:0"] = nameof(TestPermissions.CanDoAdminThings)
        });
        var admin = await host.CreateUserAsync(true, TestRole.Admin);
        var token = TestHost.TokenFor(admin.Email!, null, TestRole.Admin);
        var authorization = host.Get<IAuthorizationService>();

        Assert.NotNull(await PolicyAsync(host, nameof(TestPermissions.CanDoAdminThings)));
        Assert.False((await authorization.AuthorizeAsync(token, null,
            nameof(TestPermissions.CanDoAdminThings))).Succeeded);
        Assert.True((await authorization.AuthorizeAsync(token, null,
            nameof(TestPermissions.CanDoAdminThingsInOwnName))).Succeeded);
    }

    [Fact]
    public async Task LoginReportsThePermissionsThePoliciesWereBuiltFrom()
    {
        using var host = new TestHost(new Dictionary<string, string?>
        {
            ["InactivePermissions:0"] = nameof(TestPermissions.CanDoAdminThings)
        });
        var admin = await host.CreateUserAsync(true, TestRole.Admin);

        var response = await host.Get<UsersServices>()
            .Login(await host.LoginOfAsync(admin), host.Get<IConfiguration>());

        var permissions = (IDictionary<string, object?>)response.Permissions;
        Assert.Equal([nameof(TestPermissions.CanDoAdminThingsInOwnName)], permissions.Keys);
    }

    [Fact]
    public async Task AnAccountWithoutTheRoleIsGrantedNoPermissions()
    {
        using var host = new TestHost();
        var user = await host.CreateUserAsync();

        var response = await host.Get<UsersServices>().Login(await host.LoginOfAsync(user), host.Get<IConfiguration>());

        Assert.Empty((IDictionary<string, object?>)response.Permissions);
    }
}

/// <summary>
///     Until 5.0.0 only the assembly calling <c>AddUserAuthentication</c> was read by default, which silently dropped
///     the policies of apps whose permissions live in other projects.
/// </summary>
public class DefaultPermissionAssembliesTests
{
    [Fact]
    public void IncludesTheCallingAssemblyAndEveryAssemblyThatReferencesTheLibrary()
    {
        var assemblies = Extensions.DefaultPermissionAssemblies(typeof(DefaultPermissionAssembliesTests).Assembly);

        Assert.Contains(typeof(DefaultPermissionAssembliesTests).Assembly, assemblies);
        Assert.All(assemblies, a => Assert.True(
            a == typeof(DefaultPermissionAssembliesTests).Assembly ||
            a.GetReferencedAssemblies().Any(r => r.Name == typeof(SystemPermissions).Assembly.GetName().Name)));
    }

    [Fact]
    public void LeavesOutAssembliesThatDoNotReferenceTheLibrary()
    {
        var assemblies = Extensions.DefaultPermissionAssemblies(typeof(DefaultPermissionAssembliesTests).Assembly);

        Assert.DoesNotContain(typeof(string).Assembly, assemblies);
        Assert.DoesNotContain(typeof(FactAttribute).Assembly, assemblies);
    }

    [Fact]
    public void TheCatalogNamesTheAssembliesItRead()
    {
        using var host = new TestHost();

        Assert.Contains(typeof(TestPermissions).Assembly.GetName().Name!, host.Get<PermissionCatalog>().AssemblyNames);
    }

    [Fact]
    public async Task AnEmptyCatalogIsLoggedAsAWarningWhenTheHostStarts()
    {
        using var host = new TestHost(null, typeof(string).Assembly);

        foreach (var service in host.Get<IEnumerable<IHostedService>>())
            await service.StartAsync(CancellationToken.None);

        var entry = Assert.Single(host.Logs, l => l.EventId == PermissionCatalog.NoPermissionsFound);
        Assert.Equal(LogLevel.Warning, entry.Level);
    }

    [Fact]
    public async Task APopulatedCatalogIsLoggedWhenTheHostStarts()
    {
        using var host = new TestHost();

        foreach (var service in host.Get<IEnumerable<IHostedService>>())
            await service.StartAsync(CancellationToken.None);

        Assert.Single(host.Logs, l => l.EventId == PermissionCatalog.PermissionsLoaded);
        Assert.DoesNotContain(host.Logs, l => l.EventId == PermissionCatalog.NoPermissionsFound);
    }
}
