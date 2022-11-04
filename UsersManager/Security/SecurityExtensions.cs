using System.Dynamic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using UsersManager.Domain;

namespace UsersManager.Security;

public static class SecurityExtensions
{
    public static void AddAuthorizationPolicies(this AuthorizationOptions options, IConfiguration configuration)
    {
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => !a.IsDynamic);
        var inActivePermissions = configuration.GetSection("InactivePermissions")?.Get<string[]>() ?? Array.Empty<string>();

        foreach (var assembly in assemblies)
        {
            var types = assembly.ExportedTypes.Where(t => t.IsClass && !t.IsAbstract && !t.IsGenericType)
                .Where(t => t.IsSubclassOf(typeof(SystemPermissions)) || t == typeof(SystemPermissions))
                .Select(t => Activator.CreateInstance(t)!)
                .ToList();

            foreach (var type in types)
            {
                var systemActions = ((SystemPermissions)type).GetActions(type.GetType());
                foreach (var action in systemActions)
                    if (action != null && !inActivePermissions.Contains(action.Name))
                        options.AddPolicy(action.Name, policy =>
                            policy.RequireRole(action.Roles));
            }
        }
    }

    public static ExpandoObject GetPermissions(this ApplicationUser user, IConfiguration configuration)
    {
        var assemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => !a.IsDynamic);
        
        var permissions = new ExpandoObject();
        var inActivePermissions = configuration.GetSection("InactivePermissions")?.Get<string[]>() ?? Array.Empty<string>();
        foreach (var assembly in assemblies)
        {
            var types = assembly.ExportedTypes.Where(t => t.IsClass && !t.IsAbstract && !t.IsGenericType)
                .Where(t => t.IsSubclassOf(typeof(SystemPermissions)) || t == typeof(SystemPermissions))
                .Select(t => Activator.CreateInstance(t)!)
                .ToList();

            foreach (var type in types)
            {
                var actions = ((SystemPermissions)type).GetActions(type.GetType());
                foreach (var action in actions)
                    if (action != null && !inActivePermissions.Contains(action.Name))
                        foreach (var role in action.Roles)
                            if (user.Roles.Select(a => a.Role.Name).Contains(role))
                            {
                                permissions.TryAdd(action.Name, true);
                                break;
                            }
            }
        }

        return permissions;
    }
}