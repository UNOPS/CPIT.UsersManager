using Microsoft.AspNetCore.Identity;
using UsersManager.Helpers;

namespace UsersManager.Domain;

public class ApplicationUser : IdentityUser<int>
{
    public bool Active => DateActivated.HasValue;

    public virtual ICollection<ApplicationUserClaim> Claims { get; } = new List<ApplicationUserClaim>();

    public DateTime? DateActivated { get; private set; }
    public DateTime? LastLoginDate { get; private set; }

    public bool HasLoggedIn => EmailConfirmed || PasswordHash != null;

    public virtual ICollection<ApplicationUserLogin> Logins { get; } = new List<ApplicationUserLogin>();

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