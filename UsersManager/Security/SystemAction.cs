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
}