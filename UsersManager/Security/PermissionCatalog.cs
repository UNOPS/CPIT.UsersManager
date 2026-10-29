using System.Dynamic;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UsersManager.Domain;

namespace UsersManager.Security;

/// <summary>
///     The <see cref="SystemAction" />s declared as public static fields of the public <see cref="SystemPermissions" />
///     subclasses in the assemblies the app registered, read once at startup. Each becomes the authorization policy
///     of the same name, and is what <see cref="Permissions" /> reports to the client.
///     <para>
///         Only the registered assemblies are read, so that a package the app depends on cannot add or redefine a
///         permission policy, and two actions with the same name are an error rather than one silently replacing the
///         other. An action listed in <c>InactivePermissions</c> keeps its policy, which refuses everyone.
///     </para>
/// </summary>
public sealed class PermissionCatalog
{
    public PermissionCatalog(IEnumerable<Assembly> assemblies, IConfiguration configuration)
        : this(assemblies.Distinct().ToList(), InactiveIn(configuration))
    {
    }

    private PermissionCatalog(IReadOnlyList<Assembly> assemblies, IEnumerable<string> inactive)
        : this(assemblies.SelectMany(assembly => assembly.ExportedTypes), inactive)
    {
        AssemblyNames = assemblies.Select(a => a.GetName().Name ?? a.FullName ?? "?").ToList();
    }

    internal PermissionCatalog(IEnumerable<Type> types, IEnumerable<string> inactive)
    {
        var declared = new Dictionary<string, (SystemAction Action, FieldInfo Field)>();
        foreach (var field in types.Where(IsPermissionsClass).SelectMany(ActionFields))
        {
            if (field.GetValue(null) is not SystemAction action) continue;
            if (string.IsNullOrWhiteSpace(action.Name))
                throw new InvalidOperationException($"[UsersManager] Permission {Describe(field)} has no name.");

            if (declared.TryGetValue(action.Name, out var existing))
            {
                // A second field for the same action, e.g. an alias, defines nothing new.
                if (ReferenceEquals(existing.Action, action)) continue;
                throw new InvalidOperationException(
                    $"[UsersManager] Permission '{action.Name}' is declared by both {Describe(existing.Field)} and " +
                    $"{Describe(field)}. Each permission is a policy, so its name must be unique.");
            }

            declared.Add(action.Name, (action, field));
        }

        var inactiveNames = inactive.ToHashSet();
        Actions = declared.Values.Select(d => d.Action).Where(a => !inactiveNames.Contains(a.Name)).ToList();
        InactiveActions = declared.Values.Select(d => d.Action).Where(a => inactiveNames.Contains(a.Name)).ToList();
    }

    /// <summary>The names of the assemblies that were read for permissions.</summary>
    public IReadOnlyList<string> AssemblyNames { get; } = [];

    /// <summary>The permissions in effect, each with a policy that requires one of its roles.</summary>
    public IReadOnlyList<SystemAction> Actions { get; }

    /// <summary>The permissions listed in <c>InactivePermissions</c>, whose policies refuse everyone.</summary>
    public IReadOnlyList<SystemAction> InactiveActions { get; }

    public ExpandoObject Permissions(ApplicationUser user)
    {
        var roles = user.Roles.Select(a => a.Role.Name).ToHashSet();
        var permissions = new ExpandoObject();
        foreach (var action in Actions.Where(a => a.Roles.Any(roles.Contains)))
            permissions.TryAdd(action.Name, true);
        return permissions;
    }

    internal static string[] InactiveIn(IConfiguration configuration) =>
        configuration.GetSection("InactivePermissions").Get<string[]>() ?? [];

    private static bool IsPermissionsClass(Type type) =>
        type is { IsClass: true, IsAbstract: false, IsGenericType: false } &&
        type.IsSubclassOf(typeof(SystemPermissions));

    private static IEnumerable<FieldInfo> ActionFields(Type type) =>
        type.GetFields(BindingFlags.Public | BindingFlags.Static).Where(f => f.FieldType == typeof(SystemAction));

    private static string Describe(FieldInfo field) => $"{field.DeclaringType!.FullName}.{field.Name}";

    public static readonly EventId PermissionsLoaded = new(1004, nameof(PermissionsLoaded));
    public static readonly EventId NoPermissionsFound = new(1005, nameof(NoPermissionsFound));
}

/// <summary>
///     Logs, when the host starts, which assemblies were read and how many permissions they declared. An empty catalog
///     is logged as a warning: it means every <c>[Authorize(Policy = ...)]</c> in the app will fail with "No policy
///     found", usually because the permissions live in an assembly that was not given to <c>AddUserAuthentication</c>.
/// </summary>
internal sealed class PermissionCatalogStartupLog : IHostedService
{
    private readonly PermissionCatalog _catalog;
    private readonly ILogger<PermissionCatalog> _logger;

    public PermissionCatalogStartupLog(PermissionCatalog catalog, ILogger<PermissionCatalog> logger)
    {
        _catalog = catalog;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var assemblies = string.Join(", ", _catalog.AssemblyNames);
        if (_catalog.Actions.Count + _catalog.InactiveActions.Count == 0)
            _logger.LogWarning(PermissionCatalog.NoPermissionsFound,
                "[UsersManager] No permissions were found in {Assemblies}. Every [Authorize(Policy = ...)] will fail " +
                "with 'No policy found'. If your SystemPermissions subclasses live elsewhere, pass their assemblies to " +
                "AddUserAuthentication.", assemblies);
        else
            _logger.LogInformation(PermissionCatalog.PermissionsLoaded,
                "[UsersManager] {Count} permissions ({Inactive} inactive) loaded from {Assemblies}",
                _catalog.Actions.Count, _catalog.InactiveActions.Count, assemblies);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
