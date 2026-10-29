using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.EntityFrameworkCore;
using UsersManager.DataAccess;
using UsersManager.Helpers;

namespace UsersManager.Security;

/// <summary>
///     Checks a role requirement against the database rather than the token, so that a role removed, or an account
///     deactivated or locked out, since the token was minted is refused on the next request. It runs for the permission
///     policies and for <c>[Authorize(Roles = ...)]</c>; the latter does not get the default policy, so this is the only
///     database check such an endpoint has.
/// </summary>
public class RolesInDbAuthorizationHandler : AuthorizationHandler<RolesAuthorizationRequirement>
{
    private readonly ApplicationDbContext _dbContext;

    public RolesInDbAuthorizationHandler(ApplicationDbContext identityTenantDbContext)
    {
        _dbContext = identityTenantDbContext;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        RolesAuthorizationRequirement requirement)
    {
        if (context.User.Identity is not { IsAuthenticated: true })
        {
            context.Fail();
            return;
        }

        var email = context.User.Identity.Name;

        // RolesAuthorizationRequirement refuses to be built without roles, so there is always at least one.
        var roles = requirement.AllowedRoles;

        // The account must hold one of the roles and still be allowed to sign in. Lockout is checked here too: the
        // claims transformation strips a locked-out account's roles, but this handler would otherwise re-grant them.
        var found = await _dbContext.Users
            .Where(u => u.Email == email)
            .Active()
            .NotLockedOut()
            .Where(u => u.Roles.Any(r => roles.Contains(r.Role.Name)))
            .AnyAsync();

        if (found)
            context.Succeed(requirement);
        else
            context.Fail();
    }
}
