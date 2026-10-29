namespace UsersManager.Security;

/// <summary>
///     Inherit it and declare each role as a public <c>const string</c> field, so that
///     <see cref="Helpers.RoleConfig.AddSystemRoleSynchronization{TRole}" /> can create the roles.
/// </summary>
public class SystemRole
{
}
