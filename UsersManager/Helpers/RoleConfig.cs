using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public static class RoleConfig
{
    public static readonly EventId RoleCreated = new(1003, nameof(RoleCreated));

    /// <summary>
    ///     Creates the roles <typeparamref name="TRole" /> declares, as public static string fields (usually
    ///     <c>const</c>) of it or its base classes, that the database does not have yet when the app starts. Roles are
    ///     never removed or renamed. The app does not start if a role cannot be created, e.g. because the database is
    ///     unreachable or its migrations have not been applied.
    /// </summary>
    public static IServiceCollection AddSystemRoleSynchronization<TRole>(this IServiceCollection services)
        where TRole : SystemRole
    {
        services.AddHostedService<SystemRoleSynchronizer<TRole>>();
        return services;
    }

    /// <summary>
    ///     Creates the roles <typeparamref name="TRole" /> declares that the database does not have yet, as
    ///     <see cref="AddSystemRoleSynchronization{TRole}" /> does at startup. Call it yourself instead when it must run
    ///     at a particular point, e.g. after applying migrations: <c>await app.Services.SynchronizeSystemRoles&lt;Roles&gt;();</c>
    /// </summary>
    /// <exception cref="InvalidOperationException">
    ///     <typeparamref name="TRole" /> declares no roles, or a role could not be created.
    /// </exception>
    public static async Task SynchronizeSystemRoles<TRole>(this IServiceProvider services,
        CancellationToken cancellationToken = default) where TRole : SystemRole
    {
        var roles = RolesOf(typeof(TRole));
        // Seeding nothing would leave every permission policy refusing everyone, with no sign of why.
        if (roles.Count == 0)
            throw new InvalidOperationException(
                $"[UsersManager] {typeof(TRole).FullName} declares no roles. Declare each role as a public const " +
                "string field of a SystemRole subclass, and synchronize that subclass.");

        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(RoleConfig));
        foreach (var name in roles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await RoleExistsAsync(services, name)) continue;

            IdentityResult result;
            try
            {
                await using var scope = services.CreateAsyncScope();
                result = await scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>()
                    .CreateAsync(new ApplicationRole { Name = name });
            }
            catch (DbUpdateException)
            {
                // Another instance starting at the same time created it first, and the unique index refused this one.
                if (await RoleExistsAsync(services, name)) continue;
                throw;
            }

            if (!result.Succeeded)
                throw new InvalidOperationException(
                    $"[UsersManager] Role '{name}' could not be created: " +
                    string.Join(" ", result.Errors.Select(e => e.Description)));

            logger.LogInformation(RoleCreated, "Created role {Role}", name);
        }
    }

    [Obsolete("Never created a role: it read the empty SystemRole base class instead of yours. " +
              "Use services.AddSystemRoleSynchronization<YourRoles>() instead.", error: true)]
    public static void SynchronizeSystemRoles(this IServiceCollection services)
    {
    }

    internal static IReadOnlyList<string> RolesOf(Type type) =>
        type.GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(f => f.FieldType == typeof(string))
            .Select(f => f.GetValue(null) as string)
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => name!)
            .Distinct()
            .ToList();

    // Each check gets its own scope, so that a failed insert left in a context's change tracker cannot affect it.
    private static async Task<bool> RoleExistsAsync(IServiceProvider services, string name)
    {
        await using var scope = services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>().RoleExistsAsync(name);
    }
}

internal sealed class SystemRoleSynchronizer<TRole> : IHostedService where TRole : SystemRole
{
    private readonly IServiceProvider _services;

    public SystemRoleSynchronizer(IServiceProvider services)
    {
        _services = services;
    }

    public Task StartAsync(CancellationToken cancellationToken) =>
        _services.SynchronizeSystemRoles<TRole>(cancellationToken);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
