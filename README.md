# Users Manager

User manager is a .Net library which provides a backend framework for users management. 
The library uses EntityFrameworkCore and Google authentication. 
It supports both **PostgreSQL** and **MySQL** databases.

Before 5.0.0 the package also brought in `Google.Apis.Drive.v3`, which it never used. If your code uses the Drive API,
add a reference to that package yourself.

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

Only put a real password in appsettings.json for a local database. Elsewhere set the connection string outside
source control, e.g. as the `ConnectionStrings__DefaultConnection` environment variable from your secret store.

#### Step 2: Adding the required appsettings
You should have a "JwtSettings" section in appsettings.json file, which contains:
- validIssuer
- validAudience
- expiryInMinutes: a positive number of minutes.
- maxLifetimeInMinutes (optional, default `expiryInMinutes`, at least `expiryInMinutes`): the longest `lifetime` that
  `JwtHandler.GenerateToken` and `UsersServices.Impersonate` accept. A longer, zero or negative one throws
  `ArgumentOutOfRangeException`.
- clockSkewInMinutes (optional, default 5, zero or more): how long after its expiry a token is still accepted.
  Versions before 4.4.0 hard-coded eight hours, which kept every token usable for twice its `expiryInMinutes`.
- SecretName and ProjectId (optional): see the signing key below.
- PreviousSecretVersions and previousSecurityKeys (optional): see rotating the key below.

These are checked when the app starts, and it does not start if `validIssuer`, `validAudience` or `expiryInMinutes`
is missing, or a value is out of range or not a number. Write fractions with a `.`, e.g. `"0.5"`, whatever the
server's culture. The values are bound to `JwtSettingsOptions`, which you can inject as
`IOptions<JwtSettingsOptions>`. Before 5.0.0 a missing `expiryInMinutes` was read as 0, so tokens were issued already
expired and only worked during the clock skew, and the numbers were parsed in the server's culture, where `0,5` could
mean 5.

Tokens are signed with HS256, so anyone who has the signing key can mint a token for any user with any role. Keep it
out of source control. The library reads it once at startup, from the first of these that is set:
1. The Google Secret Manager secret `JwtSettings:SecretName` (latest version). On Google Cloud the project is the one
   the app runs in; elsewhere set `JwtSettings:ProjectId`.
2. The `JWT_SECRET` environment variable.
3. `JwtSettings:securityKey`. Outside Development it is refused when it comes from a file such as appsettings.json;
   setting it another way, e.g. as the `JwtSettings__securityKey` environment variable, is accepted.

The key must be at least 32 bytes. Generate one with `openssl rand -base64 48`. The app does not start when no key
is found, the key is too short, or `SecretName` is set but the secret can't be read; in Development a secret that
can't be read is logged as a warning and the other two sources are tried instead. "Development" is read from the
`IHostEnvironment` in the container; a plain `ServiceCollection` with none, as test projects and seeding tools often
build, is treated as production, so give those the key through the `JWT_SECRET` environment variable (CI included) or
register an `IHostEnvironment` whose name is `Development`. The log says which source the key
came from and its key id. Only HS256 tokens are accepted.

Every token names the key it was signed with in its `kid` header: a short id derived from the key, the same on every
instance. To rotate the key without signing everyone out, keep accepting the old one until the last token signed with
it has expired (`maxLifetimeInMinutes` plus `clockSkewInMinutes`):
- With Secret Manager, add a new version to the secret and list the version it replaces, e.g.
  `"PreviousSecretVersions": ["3"]` (or `JwtSettings__PreviousSecretVersions__0=3`), then restart or redeploy. New
  tokens are signed with the latest version; tokens signed with version 3 are still accepted.
- Otherwise, set the new key and put the old one in `JwtSettings:previousSecurityKeys`, e.g. as the
  `JwtSettings__previousSecurityKeys__0` environment variable.

Previous keys are only used to validate tokens, never to sign them, and follow the signing key's rules: at least 32
bytes, a version that can't be read stops the app outside Development, and `previousSecurityKeys` is refused from a
file such as appsettings.json outside Development. Remove the old key once its tokens have expired. If it was leaked,
don't list it at all: every token signed with it should stop working now.

Before 5.0.0 a secret that couldn't be read was ignored without a word and the key in appsettings.json used instead,
any key length was accepted, and the key was read again for every token issued. If your key was ever in
appsettings.json, rotate it: it is in your git history. `SecretManagerConfigurationProvider.GetSecret` now throws
instead of returning `null`, and `JwtHandler` takes the `JwtSigningKey` and `IOptions<JwtSettingsOptions>` the library registers.
You need also to add "GoogleAuthSettings" section in appsettings.json file, which contains:
- clientId: `VerifyGoogleToken` throws `InvalidOperationException` when it is missing. Before 5.0.0 it rejected every
  token for its audience, as if the token were at fault.
- hostedDomain (optional, recommended): the Google Workspace domain accounts must belong to, e.g. `unops.org`.
  `VerifyGoogleToken` refuses accounts outside it. Without it any Google account in the world can sign in and create
  an account.

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

The permission policies (see step 6) come, by default, from the assembly that makes this call and from every assembly
that references `CPIT.UsersManager` (`Extensions.DefaultPermissionAssemblies`). Those are found in the app's dependency
graph (its deps.json), which lists every project and package the app was built with whether or not the compiler kept a
reference to it, e.g. a project used only for `nameof(...)` in `[Authorize]` attributes; then by following the
references of the calling and entry assemblies; then among the assemblies already loaded. A package that does not
reference UsersManager cannot add or redefine a policy. To read exactly the assemblies you name instead, list them:
```
    services.AddUserAuthentication(Configuration, typeof(Permissions).Assembly, typeof(Program).Assembly);
```
When the host starts, event `PermissionsLoaded` (1004) says how many permissions were read from which assemblies, and
`NoPermissionsFound` (1005) warns when there were none: every `[Authorize(Policy = ...)]` would then fail with
"No policy found".

Clients authenticate with the JWT in the `Authorization: Bearer` header, and that is the only authentication scheme
the library registers. It registers ASP.NET Identity's core (`UserManager` and `RoleManager`) but not Identity's
cookies or `SignInManager`, so `HttpContext.SignInAsync` throws rather than issuing a cookie. Before 5.0.0 the library
called `AddIdentity`, which also registered Identity's cookie schemes with their defaults (14-day sliding expiry,
`SameSite=Lax`, `Secure` only over HTTPS) and made one of them the default for `HttpContext.SignInAsync`; if you
injected `SignInManager<ApplicationUser>`, the app now fails to resolve it. Do not put the JWT in a cookie: the browser
would then send it on cross-site requests too, and every state-changing endpoint would need antiforgery protection.
If you add cookie authentication of your own, set `HttpOnly`, `SecurePolicy = CookieSecurePolicy.Always`,
`SameSite = SameSiteMode.Strict` and a short expiry, and use ASP.NET Core antiforgery.

The bearer handler always maps the token's short claim names back to `ClaimTypes`, so `User.Identity.Name` is the
account's e-mail and `User.IsInRole` works, even if your app sets `JwtSecurityTokenHandler.DefaultMapInboundClaims = false`.
`ExternalAuthDto.Provider` and `IdToken`, and `ClaimPayload.ClaimName`, are `[Required]`, so an `[ApiController]`
answers 400 when they are missing. `AuthResponseDto.Token` and `ErrorMessage` are nullable: only one is set.

#### Step 5: Inject the UserServices and use the supported functions
UserServices provides three main functions:
- Login
- Register
- Assign roles

`Login` only issues a token to an account that is registered, active (`DateActivated` is set) and not locked out.
Otherwise it returns `IsAuthSuccessful = false`, no token and an `ErrorMessage`, so check `IsAuthSuccessful` before
handing the response to the client. `Register` creates accounts inactive; call `user.Activate()` when the account may
sign in. Before 5.0.0 `Login` issued a token to any account it could find and threw for an unknown one.

Pass `Login` and `Register` the login and e-mail from a token you verified with `JwtHandler.VerifyGoogleToken`.
It refuses a missing token, or one whose `Provider` is not `Google` (in any case), whose e-mail address Google has not
verified, or that is outside `hostedDomain`, by throwing `InvalidJwtException`. An account is found by its login. If none has that
login, an account with the same e-mail is used only when it has no login yet, i.e. it was created ahead of the
owner's first sign-in. `Register` then links the login to it. Once an account has a login, a different login with the
same e-mail address gets no token from `Login`, and `Register` throws `InvalidOperationException`. That includes
the same person signing in with a new Google account, e.g. one recreated in Workspace: remove the old login
(`UserManager.RemoveLoginAsync`) to let the new one claim the account. E-mail addresses must be unique
(`RequireUniqueEmail`), so `Register` and `UserManager` refuse a second account with an existing address. Before 5.0.0
any login carrying an account's e-mail address, verified or not, was linked to it and signed in as its owner.

The `ClaimPayload[]` you pass to `Login` or `JwtHandler.GenerateToken` is signed into the token as-is, so build it on
the server from data you trust, never from request input. Claim types the library sets or the token relies on are
refused with an `ArgumentException`: name, name identifier, role, `Impersonator` and the registered JWT claims (`iss`,
`sub`, `aud`, `exp`, `nbf`, `iat`, `jti`), including their short JWT forms such as `role` and `unique_name`, in any
case. Give your own claims a prefix (e.g. `myapp:tenant`) so they can't collide with these. Before 5.0.0 a payload
could add a role or a second name to the token.

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

To create the roles your `SystemRole` subclass declares, register its synchronization:
```
    services.AddSystemRoleSynchronization<BaseRole>();
```
When the app starts, every public static string field of `BaseRole` and its base classes (usually `const`) that has
no role in the database yet becomes one. Roles are never removed or renamed, so a role you delete from the class stays
in the database until you remove it. The app does not start if a role cannot be created, e.g. because the database is
unreachable or its migrations have not been applied, or if the class declares no roles. Each role created is logged
with event `RoleCreated` (1003). If you apply migrations at startup, synchronize after them instead:
```
    await app.Services.SynchronizeSystemRoles<BaseRole>();
```
Before 5.0.0 `services.SynchronizeSystemRoles()` read the empty `SystemRole` base class instead of yours, so it never
created a role and any permission whose roles you had not created by hand refused everyone. It also built a second
service provider and ran unawaited, so a failure could crash the app after startup. It no longer compiles.

Every public static `SystemAction` field of a public, non-abstract `SystemPermissions` subclass in the assemblies
`AddUserAuthentication` reads (see step 4) becomes a policy named after the action. Two actions with the same name stop the app
at startup. To switch a permission off without a release, list it in `InactivePermissions`; its policy then refuses
everyone (403) and `Login` does not report it:
```
"InactivePermissions": [ "CanManageUsers" ]
```
The permissions `Login` returns come from the same `PermissionCatalog` as the policies, which you can inject. Before
5.0.0 every assembly loaded at startup was read, so a package you depend on could add or redefine a policy, and of two
actions with the same name the last one read won. An inactive permission had no policy, so `[Authorize(Policy = ...)]`
threw on every request. The
`AddAuthorizationPolicies(IConfiguration)` and `GetPermissions(IConfiguration)` extensions still read every loaded
assembly and are obsolete; the `configuration` argument of `Login` and `Impersonate` is no longer read.

A token stays valid until it expires, so every request re-checks the account in the database: the account in the token,
and the impersonator's if the token has one, must still exist, be active and not be locked out. This applies to the
permission policies and to a bare `[Authorize]`, which the library makes its default policy. Deactivating or locking
out an account therefore takes effect on its next request. If you replace `AuthorizationOptions.DefaultPolicy`, add
`new ActiveUserRequirement()` to yours or a bare `[Authorize]` will accept any validly signed token. Before 5.0.0 a
bare `[Authorize]` did not check the database at all; an app-level middleware written to cover that can be removed.

`[Authorize(Roles = "...")]` is different: ASP.NET Core builds its policy from the roles alone, without the default
policy, so `ActiveUserRequirement` is not part of it. Its only database check is `RolesInDbAuthorizationHandler`,
which requires the account to hold one of the roles, be active and not be locked out. Prefer a permission policy,
which also gets `ActiveUserRequirement` and can refuse impersonation tokens. Before 5.0.0 the roles handler did not
check lockout.

The roles in a token are the ones the account had when the token was minted. Use them in the client for display
only. On the server, every authenticated request replaces them with the account's current roles from the database, so
`User.IsInRole(...)` and `User.HasRoles(...)` reflect a role removal on the next request. An account that is not
active or is locked out has no roles. This costs one database query per authenticated request. Only one
`IClaimsTransformation` is used, so if you register your own after `AddUserAuthentication`, have it call
`DbRolesClaimsTransformation` first or roles will again come from the token. Before 5.0.0 `HasRoles(ClaimsPrincipal)`
read the token's roles, so a removed role kept working until the token expired.

#### Impersonation
`UsersServices.Impersonate(User, userEmail, configuration)` returns a token that acts as `userEmail`, with that account's
roles, and names the caller in `AuthResponseDto.Impersonator` and in the token's `Impersonator` claim. It returns
`IsAuthSuccessful = false` and no token when either account is not registered, not active or locked out, when the
caller is already impersonating someone, or when an account tries to impersonate itself. The library does not decide
who may impersonate: guard the endpoint with a permission of your own.

```csharp
public class Permissions : SystemPermissions {
  public static readonly SystemAction Impersonate = new(nameof(Impersonate), Roles.SystemAdmin) { AllowImpersonation = false };
}

[Authorize(Policy = nameof(Permissions.Impersonate))]
[HttpPost("impersonate")]
public Task<AuthResponseDto> Impersonate(string email) => usersServices.Impersonate(User, email, configuration);
```

Every impersonation token issued is logged at Warning with event `ImpersonationTokenIssued` (1001), naming the
impersonator, the user, the token's `jti` and its expiry; every refusal is logged at Warning with event
`ImpersonationRefused` (1002). Each request made with the token re-checks both accounts, so deactivating or locking
out the impersonator ends the impersonation. Set `AllowImpersonation = false` on actions an impersonator must not take
in someone else's name; their policies then refuse impersonation tokens. Elsewhere, `User.IsImpersonated()` and
`User.GetImpersonator()` tell you whether a request is impersonated and by whom, and `NotImpersonatedRequirement`
can be added to policies of your own.

`JwtHandler.GenerateToken(string userEmail, string[] roles, ...)` signs whatever it is given without looking the
account up, so never pass it values from a request. Use `GenerateToken(ApplicationUser, ...)` or `Impersonate`.

Before 5.0.0 any `lifetime` was accepted, impersonation tokens were not logged, `AuthResponseDto.Impersonator` was never
set, and nothing checked the impersonator. If you passed a `lifetime` longer than `expiryInMinutes`, set
`maxLifetimeInMinutes`. `UsersServices` now also takes an `ILogger<UsersServices>` and the `PermissionCatalog`, which DI supplies.

Each token carries a unique `jti`, an `iat` and an `nbf`. Tokens cannot yet be revoked, so a stolen token works until it
expires. Keep `expiryInMinutes` short (15 minutes or less).

## Upgrading from 4.x to 5.0.0

5.0.0 is the security hardening release. Its breaking changes, and what a consuming app has to do:

1. **Constructors.** `JwtHandler` now takes `JwtSigningKey` and `IOptions<JwtSettingsOptions>`, and `UsersServices`
   takes `ILogger<UsersServices>` and `PermissionCatalog`. Resolve them from dependency injection; code that did
   `new JwtHandler(configuration, logger)`, typically in tests, must build a `JwtSigningKey` (configuration, logger,
   an `IHostEnvironment`) and `Options.Create(new JwtSettingsOptions { ... })`, or resolve `JwtHandler` from a container
   built with `AddUserAuthentication`.
2. **Permission assemblies.** If your `SystemPermissions` subclasses live in several projects, check the
   `PermissionsLoaded` log line on first start, or pass the assemblies explicitly (step 4). The
   `GetPermissions(IConfiguration)` and `AddAuthorizationPolicies(IConfiguration)` extensions are obsolete; use the
   injected `PermissionCatalog`.
3. **Signing key.** Must be at least 32 bytes; `JwtSettings:securityKey` in an appsettings file is refused outside
   Development, and a container with no `IHostEnvironment` counts as outside Development. Give test containers and
   seeding tools the key through `JWT_SECRET`. If your key was ever committed, rotate it.
4. **Settings validated at startup.** `validIssuer`, `validAudience` and a positive `expiryInMinutes` are required.
   Any `lifetime` you pass to `GenerateToken` must not exceed `maxLifetimeInMinutes` (default `expiryInMinutes`).
5. **Login and Register.** `Login` returns `IsAuthSuccessful = false` and no token for an account that is unknown,
   inactive or locked out, or whose e-mail belongs to an account with a different login: check `IsAuthSuccessful`
   before returning the response. `Register` throws `InvalidOperationException` in that last case: catch it and show a
   message. Before upgrading, look at `AspNetUserLogins` for accounts with more than one login provider, or provider
   names in a different spelling than the one you pass now; those users would be refused.
6. **Identity.** `AddIdentityCore` replaces `AddIdentity`: `SignInManager` and Identity's cookie schemes are gone, and
   `RequireUniqueEmail` is on. Check `AspNetUsers` for duplicate `NormalizedEmail` values first; `UserManager`
   refuses to update such accounts.
7. **Roles.** `services.SynchronizeSystemRoles()` no longer compiles; use `AddSystemRoleSynchronization<YourRoles>()`
   or your own seeding.
8. **Per-request checks.** A bare `[Authorize]` and every permission policy now re-check the account in the database,
   so an app-level middleware doing that can be removed. `SecretManagerConfigurationProvider.GetSecret` throws instead
   of returning `null`.
