using Microsoft.AspNetCore.Identity;

namespace UsersManager.Domain;

public class ApplicationUserRole : IdentityUserRole<int>
{
    // ReSharper disable once UnusedAutoPropertyAccessor.Local
    public virtual ApplicationRole Role { get; private set; }
    public virtual ApplicationUser User { get; private set; }
}