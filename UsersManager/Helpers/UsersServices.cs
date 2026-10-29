using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Dynamic;
using System.Security.Claims;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Models;
using UsersManager.Security;

namespace UsersManager.Helpers;

public class UsersServices
{
    private readonly ApplicationDbContext context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly JwtHandler _jwtHandler;
    private readonly ILogger<UsersServices> _logger;
    private readonly PermissionCatalog _permissions;

    public UsersServices(ApplicationDbContext context, UserManager<ApplicationUser> userManager, JwtHandler jwtHandler,
        ILogger<UsersServices> logger, PermissionCatalog permissions)
    {
        this.context = context;
        _userManager = userManager;
        _jwtHandler = jwtHandler;
        _logger = logger;
        _permissions = permissions;
    }

    public static readonly EventId ImpersonationRefused = new(1002, nameof(ImpersonationRefused));

    /// <summary>
    ///     Returns the account linked to <paramref name="info" />. Otherwise links it to the account with
    ///     <paramref name="userEmail" /> if that account has no login yet, or creates a new, inactive account. Throws
    ///     <see cref="InvalidOperationException" /> if the e-mail address belongs to an account linked to another
    ///     login. <paramref name="userEmail" /> must come from a verified token, e.g.
    ///     <see cref="JwtHandler.VerifyGoogleToken" />.
    /// </summary>
    public async Task<ApplicationUser> Register(UserLoginInfo info, string userEmail)
    {
        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (user != null)
            return user;

        user = await _userManager.FindByEmailAsync(userEmail);
        if (user == null)
        {
            user = new ApplicationUser
            {
                Email = userEmail,
                UserName = userEmail
            };
            EnsureSucceeded(await _userManager.CreateAsync(user));

            //prepare and send an email for the email confirmation
        }
        else if (await HasLoginAsync(user))
        {
            throw new InvalidOperationException(
                "This e-mail address belongs to an account that signs in with a different login.");
        }

        EnsureSucceeded(await _userManager.AddLoginAsync(user, info));
        return user;
    }

    /// <param name="configuration">
    ///     No longer read: permissions come from the <see cref="PermissionCatalog" /> built at startup.
    /// </param>
    public async Task<AuthResponseDto> Login(UserLoginInfo info, IConfiguration configuration, string? userEmail = null,
        ClaimPayload[]? payloads = null)
    {
        var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        // Matching by e-mail is only for an account created ahead of its first sign-in. Once an account has a
        // login, a different one with the same address is someone else: a recycled address, another Google account
        // claiming it, or a provider that vouches for addresses less carefully.
        if (user == null && !string.IsNullOrWhiteSpace(userEmail))
        {
            user = await _userManager.FindByEmailAsync(userEmail);
            if (user != null && await HasLoginAsync(user))
                user = null;
        }

        // A signed-in Google account proves who the caller is, not that they may still use this application.
        if (!await CanSignInAsync(user))
            return Refused("This account is not registered, not active or locked out.");

        var appUser = await WithRolesAsync(user!);

        appUser.SetLastLoginDate();
        await context.SaveChangesAsync();

        var permissions = appUser.GetPermissions(_permissions);
        var token = await _jwtHandler.GenerateToken(appUser, null, payloads);

        return new AuthResponseDto
        {
            Token = token,
            IsAuthSuccessful = true,
            Permissions = permissions
        };
    }

    /// <summary>
    ///     Issues a token that acts as the account with <paramref name="userEmail" /> and names
    ///     <paramref name="impersonator" /> as the one behind it, in <see cref="AuthResponseDto.Impersonator" /> and the
    ///     token's <see cref="JwtHandler.ImpersonatorClaim" />. Both accounts must exist, be active and not be locked
    ///     out, and <paramref name="impersonator" /> must not be impersonating someone already. Whether the impersonator
    ///     may impersonate at all is up to the caller: guard the endpoint with a permission whose
    ///     <see cref="SystemAction.AllowImpersonation" /> is <c>false</c>. The token lives for
    ///     <paramref name="lifetime" />, at most <see cref="JwtHandler.MaxLifetime" />.
    /// </summary>
    /// <param name="configuration">
    ///     No longer read: permissions come from the <see cref="PermissionCatalog" /> built at startup.
    /// </param>
    public async Task<AuthResponseDto> Impersonate(ClaimsPrincipal impersonator, string userEmail,
        IConfiguration configuration, ClaimPayload[]? payloads = null, TimeSpan? lifetime = null)
    {
        var impersonatorEmail = impersonator.Identity is { IsAuthenticated: true } ? impersonator.Identity.Name : null;
        // The e-mail usually comes straight from a request, so a missing one is refused like an unknown account
        // rather than thrown back as a 500.
        var user = string.IsNullOrWhiteSpace(userEmail) ? null : await _userManager.FindByEmailAsync(userEmail);

        var refusal = await ImpersonationRefusalAsync(impersonator, impersonatorEmail, user);
        if (refusal != null)
        {
            _logger.LogWarning(ImpersonationRefused,
                "[UsersManager] {Impersonator} was refused impersonation of {User}: {Reason}",
                impersonatorEmail, userEmail, refusal);
            return Refused(refusal);
        }

        var appUser = await WithRolesAsync(user!);
        return new AuthResponseDto
        {
            Token = await _jwtHandler.GenerateToken(appUser, impersonatorEmail, payloads, lifetime),
            IsAuthSuccessful = true,
            Permissions = appUser.GetPermissions(_permissions),
            Impersonator = impersonatorEmail
        };
    }

    private async Task<string?> ImpersonationRefusalAsync(ClaimsPrincipal impersonator, string? impersonatorEmail,
        ApplicationUser? user)
    {
        if (impersonatorEmail == null)
            return "The impersonator is not signed in.";
        // An impersonator who starts another impersonation would be recorded as the user they were impersonating,
        // which hides who is really behind the second token.
        if (impersonator.IsImpersonated())
            return "An impersonation token cannot start another impersonation.";
        if (!await CanSignInAsync(await _userManager.FindByEmailAsync(impersonatorEmail)))
            return "The impersonator's account is not registered, not active or locked out.";
        if (!await CanSignInAsync(user))
            return "This account is not registered, not active or locked out.";
        if (string.Equals(user!.Email, impersonatorEmail, StringComparison.OrdinalIgnoreCase))
            return "An account cannot impersonate itself.";
        return null;
    }

    private async Task<bool> CanSignInAsync(ApplicationUser? user) =>
        user is { Active: true } && !await _userManager.IsLockedOutAsync(user);

    private Task<ApplicationUser> WithRolesAsync(ApplicationUser user) =>
        context.Users
            .Include(a => a.Roles)
            .ThenInclude(a => a.Role)
            .SingleAsync(a => a.Id == user.Id);

    private static AuthResponseDto Refused(string errorMessage) => new()
    {
        IsAuthSuccessful = false,
        ErrorMessage = errorMessage,
        Permissions = new ExpandoObject()
    };

    private async Task<bool> HasLoginAsync(ApplicationUser user) =>
        (await _userManager.GetLoginsAsync(user)).Count > 0;

    private static void EnsureSucceeded(IdentityResult result)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join(" ", result.Errors.Select(e => e.Description)));
    }

    public async Task AssignRoles(ApplicationUser user, params string[] roles)
    {
        var existingRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, existingRoles);
        await _userManager.AddToRolesAsync(user, roles);
    }
}