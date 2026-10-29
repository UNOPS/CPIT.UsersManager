using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using UsersManager.DataAccess;
using UsersManager.Helpers;

namespace UsersManager.Security;

/// <summary>
///     The token's account, and the impersonator's if there is one, must still exist, be active and not be locked out.
///     A token outlives the account state it was minted from, so this is re-read from the database on every request.
/// </summary>
public class ActiveUserRequirement : IAuthorizationRequirement
{
}

public class ActiveUserAuthorizationHandler : AuthorizationHandler<ActiveUserRequirement>
{
    private readonly ApplicationDbContext _dbContext;

    public ActiveUserAuthorizationHandler(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context,
        ActiveUserRequirement requirement)
    {
        if (context.User.Identity is not { IsAuthenticated: true })
        {
            context.Fail();
            return;
        }

        // Roles are only checked against the impersonated account, so the impersonator's own state must be checked
        // here or deactivating an administrator would not end the impersonations they started.
        var impersonator = context.User.GetImpersonator();

        var isActive = await IsActiveAsync(context.User.Identity.Name) &&
                       (impersonator == null || await IsActiveAsync(impersonator));

        if (isActive)
            context.Succeed(requirement);
        else
            context.Fail();
    }

    private Task<bool> IsActiveAsync(string? email)
    {
        // An account that was removed outright has no row and fails the same way.
        return _dbContext.Users
            .Where(a => a.Email == email)
            .Active()
            .NotLockedOut()
            .AnyAsync();
    }
}
