# Users Manager

User manager is a .Net library which provides a backend framework for users management. 
The library uses EntityFrameworkCore and Google authentication. 
It supports both **PostgreSQL** and **MySQL** databases.

## Before You Begin
Make sure to create a GCP project and have an active OAuth Client ID, the ID should authorize the Javascript origins which will initiate the authentication process.

## How To Use
#### Step 1: Configure Database Provider
The library supports both PostgreSQL and MySQL. You need to configure your database provider and connection string in `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=YourDatabase;User Id=your_user;Password=your_password;"
  },
  "DatabaseProvider": "PostgreSQL"
}
```

**Database Provider Options:**
- `"PostgreSQL"` - For PostgreSQL databases (default if not specified)
- `"MySQL"` - For MySQL/MariaDB databases

**Connection String Examples:**

For PostgreSQL:
```
Server=localhost;Port=5432;Database=YourDatabase;User Id=your_user;Password=your_password;
```

For MySQL:
```
Server=localhost;Port=3306;Database=YourDatabase;User=your_user;Password=your_password;
```

#### Step 2: Adding the required appsettings
You should have a "JwtSettings" section in appsettings.json file, which contains three main configurations:
- securityKey
- validIssuer
- validAudience
- expiryInMinutes
Those settings can be also stored in application environment or Google secret manager, the library will be able to read them.
You need also to add "GoogleAuthSettings" section in appsettings.json file, which contains three main configurations:
- clientId

#### Step 3: Create Database Migrations
**Important:** The library does not include pre-built migrations. You must create your own migrations based on your chosen database provider.

After configuring your database provider and connection string, create an initial migration in your project:

**For PostgreSQL:**
```bash
dotnet ef migrations add InitialCreate --project YourProject
```

**For MySQL:**
```bash
dotnet ef migrations add InitialCreate --project YourProject
```

Then apply the migration to create the database schema:
```bash
dotnet ef database update --project YourProject
```

#### Step 4: Configure dependency injection
Add the following code in your Startup file
```
    services.AddUserAuthentication(Configuration);
```

#### Step 5: Inject the UserServices and use the supported functions
UserServices provides three main functions:
- Login
- Register
- Assign roles

#### Step 6: Security framework
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



