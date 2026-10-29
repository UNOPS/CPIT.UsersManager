using System.Dynamic;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using UsersManager.Domain;

namespace UsersManager.Security;

public static class SecurityExtensions
{
    public static void AddAuthorizationPolicies(this AuthorizationOptions options, PermissionCatalog catalog)
    {
        foreach (var action in catalog.Actions)
            options.AddPolicy(action.Name, policy =>
            {
                policy.RequireRole(action.Roles).AddRequirements(new ActiveUserRequirement());
                if (!action.AllowImpersonation)
                    policy.AddRequirements(new NotImpersonatedRequirement());
            });

        // Leaving the policy out would make [Authorize(Policy = ...)] throw on every request, a 500 instead of a 403.
        foreach (var action in catalog.InactiveActions)
            options.AddPolicy(action.Name, policy => policy.RequireAssertion(_ => false));
    }

    [Obsolete("Reads every assembly loaded so far, so a dependency can add or redefine a policy. " +
              "AddUserAuthentication registers the policies; pass it the assemblies that declare your permissions.")]
    public static void AddAuthorizationPolicies(this AuthorizationOptions options, IConfiguration configuration)
    {
        options.AddAuthorizationPolicies(LoadedAssemblies(configuration));
    }

    public static ExpandoObject GetPermissions(this ApplicationUser user, PermissionCatalog catalog)
    {
        return catalog.Permissions(user);
    }

    [Obsolete("Reads every assembly loaded so far, which may not be the permissions the policies were built from. " +
              "Use GetPermissions(PermissionCatalog) with the PermissionCatalog from dependency injection.")]
    public static ExpandoObject GetPermissions(this ApplicationUser user, IConfiguration configuration)
    {
        return LoadedAssemblies(configuration).Permissions(user);
    }

    private static PermissionCatalog LoadedAssemblies(IConfiguration configuration) =>
        new(AppDomain.CurrentDomain.GetAssemblies().Where(a => !a.IsDynamic), configuration);
}
