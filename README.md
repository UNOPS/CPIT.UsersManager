# User Manager

User manager is a .Net library which provides a backend framework for users management. 
The library uses EntityFrameworkCore and Google authentication.

## Before You Begin
Make sure to create a GCP project and have an active OAuth Client ID, the ID should authorize the Javascript origins which will initiate the authentication process.

## How To Use
#### Step 1: Adding the required appsettings
You should have a "JwtSettings" section in appsettings.json file, which contains three main configurations:
- securityKey
- validIssuer
- validAudience
- expiryInMinutes
Those settings can be also stored in application environment or Google secret manager, the library will be able to read them.
You need also to add "GoogleAuthSettings" section in appsettings.json file, which contains three main configurations:
- clientId

#### Step 2: Configure dependency injection
Add the following code in your Startup file
```
    services.AddUserAuthentication(Configuration);
```

#### Step 3: Inject the UserServices and use the supported functions
UserServices provides three main functions:
- Login
- Register
- Assign roles

#### Step 4: Security framework
Inherit SystemPermissions and SystemRole classes in your project, and use them as an authentication policies.
Example:
```
public class BaseRole: SystemRole {
    public const string SystemAdmin = "SystemAdmin";
}

public class BasePermissions: SystemPermissions
{
    public static readonly SystemAction CanManageUsers = new(nameof(CanManageUsers), BaseRole.SystemAdmin);
}


[Authorize(Policy = nameof(BasePermissions.CanManageUsers))]
public class UsersController : ControllerBase {

}
```



