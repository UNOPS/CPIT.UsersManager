using Microsoft.AspNetCore.Authorization;
using UsersManager.Helpers;

namespace UsersManager.Security;

/// <summary>
///     The token must not be an impersonation token. Add it to a policy for actions an impersonator must not take in
///     someone else's name, or set <see cref="SystemAction.AllowImpersonation" /> to <c>false</c> on the action.
/// </summary>
public class NotImpersonatedRequirement : IAuthorizationRequirement
{
}

public class NotImpersonatedAuthorizationHandler : AuthorizationHandler<NotImpersonatedRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        NotImpersonatedRequirement requirement)
    {
        if (context.User.IsImpersonated())
            context.Fail();
        else
            context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
