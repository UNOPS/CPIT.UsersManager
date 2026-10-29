using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using UsersManager.DataAccess;
using UsersManager.Helpers;

namespace UsersManager.Security;

/// <summary>
///     Replaces the role claims a token was minted with by the account's roles in the database, so that
///     <c>User.IsInRole</c> and <see cref="Extensions.HasRoles(ClaimsPrincipal, string[])" /> see a role removal, a
///     deactivation or a lockout on the next request instead of when the token expires. An account that is not active or
///     is locked out has no roles.
/// </summary>
public class DbRolesClaimsTransformation : IClaimsTransformation
{
    private readonly ApplicationDbContext _dbContext;

    public DbRolesClaimsTransformation(ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity { IsAuthenticated: true } identity)
            return principal;

        var roles = await _dbContext.Users
            .Where(a => a.Email == identity.Name)
            .Active()
            .NotLockedOut()
            .SelectMany(a => a.Roles.Select(r => r.Role.Name))
            .ToListAsync();

        // This can run more than once per request, so it works on a copy and always starts from no roles.
        var transformed = principal.Clone();
        foreach (var each in transformed.Identities)
        foreach (var claim in each.FindAll(c => c.Type == each.RoleClaimType || c.Type == ClaimTypes.Role).ToList())
            each.RemoveClaim(claim);

        var primary = (ClaimsIdentity)transformed.Identity!;
        primary.AddClaims(roles.OfType<string>().Select(role => new Claim(primary.RoleClaimType, role)));
        return transformed;
    }
}
