namespace UsersManager.Security;

public class SystemAction
{
    public SystemAction(string name, params string[] roles)
    {
        Name = name;
        Roles = roles;
    }

    public string Name { get; set; }
    public string[] Roles { get; set; }

    /// <summary>
    ///     Whether an impersonation token may perform the action. Set it to <c>false</c> for actions an impersonator
    ///     must not take in someone else's name, such as changing roles or starting another impersonation.
    /// </summary>
    public bool AllowImpersonation { get; set; } = true;
}