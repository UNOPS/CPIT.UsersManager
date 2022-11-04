using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public static class RoleConfig
{
    public static async void SynchronizeSystemRoles(this IServiceCollection services)
    {
        var roles = typeof(SystemRole)
            .GetFields()
            .Where(a => a.FieldType == typeof(string))
            .Select(f => f.GetValue(null) as string)
            .ToList();

        var roleManager = services.BuildServiceProvider()
            .CreateScope()
            .ServiceProvider
            .GetRequiredService<RoleManager<ApplicationRole>>();

        foreach (var systemRole in roles)
        {
            var exists = await roleManager.RoleExistsAsync(systemRole);

            if (!exists)
            {
                var role = new ApplicationRole
                {
                    Name = systemRole,
                    NormalizedName = systemRole
                };

                await roleManager.CreateAsync(role);
            }
        }
    }
}