using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using UsersManager.DataAccess;

namespace UsersManager.Security;

public class RolesInDbAuthorizationHandler : AuthorizationHandler<RolesAuthorizationRequirement>
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IConfiguration configuration;


    public RolesInDbAuthorizationHandler(ApplicationDbContext identityTenantDbContext, IConfiguration configuration)
    {
        _dbContext = identityTenantDbContext;
        this.configuration = configuration;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        RolesAuthorizationRequirement requirement)
    {
        if (context.User.Identity is {IsAuthenticated: false})
        {
            context.Fail();
            return;
        }

        bool found;
        if (requirement.AllowedRoles.Any() == false)
        {
            // it means any logged in user is allowed to access the resource
            found = true;
        }
        else
        {
            var userId = context.User.Identity?.Name;
            var roles = requirement.AllowedRoles;
            var roleIds = await _dbContext.Roles
                .Where(p => roles.Contains(p.Name))
                .Select(p => p.Id)
                .ToListAsync();

            found = await _dbContext.UserRoles
                .Where(p => roleIds.Contains(p.RoleId) && p.User.Email == userId)
                .AnyAsync();
        }

        if (found)
            context.Succeed(requirement);
        else
            context.Fail();
    }
}