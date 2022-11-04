namespace UsersManager.Security;

public class SystemPermissions
{
    public List<SystemAction?> GetActions(Type type)
    {
        return type
            .GetFields()
            .Where(a => a.FieldType == typeof(SystemAction))
            .Select(f => f.GetValue(null) as SystemAction)
            .ToList();
    }
}