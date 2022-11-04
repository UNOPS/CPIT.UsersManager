using Microsoft.AspNetCore.Identity;
using UsersManager.Helpers;

namespace UsersManager.Domain;

public class ApplicationUser : IdentityUser<int>
{
    public bool Active => DateActivated.HasValue;

    /// <summary>
    ///     Navigation property for the claims this user possesses.
    /// </summary>
    public virtual ICollection<ApplicationUserClaim> Claims { get; } = new List<ApplicationUserClaim>();

    public DateTime? DateActivated { get; private set; }
    public DateTime? LastLoginDate { get; private set; }

    public bool HasLoggedIn => EmailConfirmed || PasswordHash != null;

    /// <summary>
    ///     Navigation property for this users login accounts.
    /// </summary>
    public virtual ICollection<ApplicationUserLogin> Logins { get; } = new List<ApplicationUserLogin>();

    /// <summary>
    ///     Navigation property for the roles this user belongs to.
    /// </summary>
    public virtual ICollection<ApplicationUserRole> Roles { get; } = new List<ApplicationUserRole>();

    public void Activate(DateTime? date = null)
    {
        DateActivated = date?.ToUserUTCDate() ?? DateTime.UtcNow.ToUserUTCDate();
    }

    public void Deactivate()
    {
        DateActivated = null;
    }

    public void SetLastLoginDate(DateTime? date = null)
    {
        this.LastLoginDate = date?.ToUserUTCDate() ?? DateTime.UtcNow.ToUserUTCDate();
    }
}