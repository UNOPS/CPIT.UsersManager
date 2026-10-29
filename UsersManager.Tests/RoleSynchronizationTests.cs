using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UsersManager.Domain;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

public class ExtendedTestRole : TestRole
{
    public const string Auditor = "TestAuditor";
    public static readonly string Reviewer = "TestReviewer";
    public const string AuditorAlias = Auditor;
}

/// <summary>
///     Until 5.0.0 synchronization read the empty <see cref="SystemRole" /> base class, so it never created a role and
///     every permission policy refused everyone.
/// </summary>
public class RoleSynchronizationTests : IDisposable
{
    private readonly TestHost _host = new();

    private async Task<List<string?>> RoleNamesAsync() =>
        await _host.Get<RoleManager<ApplicationRole>>().Roles.Select(r => r.Name).OrderBy(n => n).ToListAsync();

    [Fact]
    public async Task CreatesTheRolesTheSubclassDeclares()
    {
        await _host.Services.SynchronizeSystemRoles<TestRole>();

        Assert.Equal([TestRole.Admin], await RoleNamesAsync());
    }

    [Fact]
    public async Task IncludesInheritedAndReadonlyRolesOnce()
    {
        await _host.Services.SynchronizeSystemRoles<ExtendedTestRole>();

        Assert.Equal([ExtendedTestRole.Admin, ExtendedTestRole.Auditor, ExtendedTestRole.Reviewer],
            await RoleNamesAsync());
    }

    [Fact]
    public async Task CreatedRolesAreNormalizedSoTheyCanBeFoundAndAssigned()
    {
        await _host.Services.SynchronizeSystemRoles<TestRole>();

        var user = await _host.CreateUserAsync(roles: TestRole.Admin);
        Assert.True(await _host.Get<UserManager<ApplicationUser>>().IsInRoleAsync(user, TestRole.Admin));
    }

    [Fact]
    public async Task RunningAgainChangesNothing()
    {
        await _host.Services.SynchronizeSystemRoles<ExtendedTestRole>();
        var created = _host.Logs.Count(l => l.EventId == RoleConfig.RoleCreated);

        await _host.Services.SynchronizeSystemRoles<ExtendedTestRole>();

        Assert.Equal(3, (await RoleNamesAsync()).Count);
        Assert.Equal(created, _host.Logs.Count(l => l.EventId == RoleConfig.RoleCreated));
    }

    [Fact]
    public async Task LeavesRolesItDoesNotDeclareAlone()
    {
        await _host.Get<RoleManager<ApplicationRole>>().CreateAsync(new ApplicationRole { Name = "Legacy" });

        await _host.Services.SynchronizeSystemRoles<TestRole>();

        Assert.Equal(["Legacy", TestRole.Admin], await RoleNamesAsync());
    }

    [Fact]
    public async Task LogsEachRoleItCreates()
    {
        await _host.Services.SynchronizeSystemRoles<ExtendedTestRole>();

        var created = _host.Logs.Where(l => l.EventId == RoleConfig.RoleCreated).ToList();
        Assert.Equal(3, created.Count);
        Assert.All(created, l => Assert.Equal(LogLevel.Information, l.Level));
    }

    [Fact]
    public async Task ARoleClassDeclaringNoRolesIsAnError()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _host.Services.SynchronizeSystemRoles<SystemRole>());

        Assert.Contains(typeof(SystemRole).FullName!, error.Message);
    }

    [Fact]
    public async Task TheHostedServiceCreatesTheRolesWhenTheHostStarts()
    {
        using var host = new TestHost(services => services.AddSystemRoleSynchronization<ExtendedTestRole>());

        foreach (var service in host.Get<IEnumerable<IHostedService>>())
            await service.StartAsync(CancellationToken.None);

        var roles = await host.Get<RoleManager<ApplicationRole>>().Roles.Select(r => r.Name).ToListAsync();
        Assert.Equal(3, roles.Count);
    }

    [Fact]
    public void RegisteringTheSameRolesTwiceAddsOneHostedService()
    {
        using var host = new TestHost(services => services
            .AddSystemRoleSynchronization<TestRole>()
            .AddSystemRoleSynchronization<TestRole>());

        Assert.Single(host.Get<IEnumerable<IHostedService>>().OfType<SystemRoleSynchronizer<TestRole>>());
    }

    public void Dispose() => _host.Dispose();
}
