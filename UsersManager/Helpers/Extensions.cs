using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using System.Reflection;
using Microsoft.Extensions.DependencyModel;
using System.Security.Claims;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public static class Extensions
{
    /// <param name="permissionAssemblies">
    ///     The assemblies whose <see cref="SystemPermissions" /> subclasses become authorization policies. When none are
    ///     given, <see cref="DefaultPermissionAssemblies" /> is used: the calling assembly, the entry assembly and every
    ///     assembly they reference, directly or indirectly, that itself references this library. A package that does not
    ///     reference UsersManager can therefore not add or redefine a policy.
    /// </param>
    public static void AddUserAuthentication(this IServiceCollection services, IConfiguration configuration,
        params Assembly[] permissionAssemblies)
    {
        var databaseProvider = configuration.GetSection("DatabaseProvider")?.Value ?? "PostgreSQL";
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException(
                "[UsersManager] Connection string 'DefaultConnection' is required. " +
                "Please add it to your ConnectionStrings section in appsettings.json.");
        }

        var callingAssembly = Assembly.GetCallingAssembly();
        var migrationsAssembly = callingAssembly.GetName().Name;

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (string.Equals(databaseProvider, "MySQL", StringComparison.OrdinalIgnoreCase))
            {
                // Compatible with MySQL 8.0+ and MariaDB 10.5+
                var serverVersion = new MySqlServerVersion(new Version(8, 0, 21));
                options.UseMySql(connectionString, serverVersion, mysqlOptions =>
                {
                    mysqlOptions.MigrationsAssembly(migrationsAssembly);
                    mysqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorNumbersToAdd: null);
                });
            }
            else if (string.Equals(databaseProvider, "PostgreSQL", StringComparison.OrdinalIgnoreCase))
            {
                options.UseNpgsql(connectionString, npgsqlOptions =>
                {
                    npgsqlOptions.MigrationsAssembly(migrationsAssembly);
                    npgsqlOptions.EnableRetryOnFailure(
                        maxRetryCount: 5,
                        maxRetryDelay: TimeSpan.FromSeconds(30),
                        errorCodesToAdd: null);
                });
            }
            else
            {
                throw new InvalidOperationException(
                    $"[UsersManager] Unsupported database provider: {databaseProvider}. " +
                    "Supported providers are: PostgreSQL, MySQL");
            }
        });

        // Accounts are found by e-mail, so two accounts sharing one would make it ambiguous which a sign-in is for.
        // Identity's core only: AddIdentity would also register its cookie schemes and SignInManager, a second way to
        // sign in that nothing here configures, and make a cookie the default for HttpContext.SignInAsync.
        services.AddIdentityCore<ApplicationUser>(options => options.User.RequireUniqueEmail = true)
            .AddRoles<ApplicationRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        // Checked at startup, so that a missing expiryInMinutes stops the app instead of issuing tokens that are
        // already expired.
        services.AddOptions<JwtSettingsOptions>()
            .Bind(configuration.GetSection(JwtSettingsOptions.Section))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<JwtSettingsOptions>, JwtSettingsOptionsValidator>();

        // One key for issuing and validating, plus any previous ones still accepted during a rotation, read at
        // startup (see the ValidateOnStart below) so that a missing or weak key stops the app instead of the first
        // login.
        services.AddSingleton<JwtSigningKey>();

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            // Tokens are written with the short JWT names ("unique_name", "role"), and the reserved-claim check in
            // JwtHandler.GetClaims assumes they are read back as ClaimTypes. Set here so that an application setting
            // JwtSecurityTokenHandler.DefaultMapInboundClaims = false does not leave every user nameless and roleless.
            options.MapInboundClaims = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                // The only algorithm the library signs with, so that no other is accepted for this key.
                ValidAlgorithms = [JwtSigningKey.Algorithm],
                // User.Identity.Name is the e-mail every database check looks the account up by.
                NameClaimType = ClaimTypes.Name,
                RoleClaimType = ClaimTypes.Role
            };
        });
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<JwtSigningKey, IOptions<JwtSettingsOptions>>((options, signingKey, jwtSettings) =>
            {
                var parameters = options.TokenValidationParameters;
                parameters.IssuerSigningKeys = signingKey.ValidationKeys;
                parameters.ValidIssuer = jwtSettings.Value.ValidIssuer;
                parameters.ValidAudience = jwtSettings.Value.ValidAudience;
                parameters.ClockSkew = jwtSettings.Value.ClockSkew;
            })
            .ValidateOnStart();
        // Registered after AddAuthentication's no-op default so that this is the one resolved.
        services.AddScoped<IClaimsTransformation, DbRolesClaimsTransformation>();
        services.AddScoped<JwtHandler>();
        services.AddScoped<UsersServices>();

        // Built now, so that two permissions with the same name stop the app at startup.
        var permissions = new PermissionCatalog(
            permissionAssemblies.Length > 0 ? permissionAssemblies : DefaultPermissionAssemblies(callingAssembly),
            configuration);
        services.AddSingleton(permissions);
        // Says at startup which assemblies were read, and warns when they declared no permission at all.
        services.AddHostedService<PermissionCatalogStartupLog>();

        services.AddAuthorization(options =>
        {
            // A bare [Authorize] never reaches the roles handler, so without this it would accept any validly signed
            // token, including one for an account deactivated or locked out since the token was minted.
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .AddRequirements(new ActiveUserRequirement())
                .Build();
            options.AddAuthorizationPolicies(permissions);
        });
        // Scoped like the DbContext they query.
        services.AddScoped<IAuthorizationHandler, RolesInDbAuthorizationHandler>();
        services.AddScoped<IAuthorizationHandler, ActiveUserAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, NotImpersonatedAuthorizationHandler>();
    }

    /// <summary>The NuGet package id, as it appears in a consuming app's dependency graph (deps.json).</summary>
    public const string PackageId = "CPIT.UsersManager";

    /// <summary>
    ///     The assemblies read for permissions when <see cref="AddUserAuthentication" /> is given none: the calling
    ///     assembly, and every assembly that references this library, found three ways. First in the app's dependency
    ///     graph (its deps.json), which lists every project and package the app was built with whether or not the
    ///     compiler kept a reference to it; then by walking the static references of the calling and entry assemblies;
    ///     then among the assemblies already loaded. A package that does not reference UsersManager can therefore not
    ///     add or redefine a policy. Framework assemblies (System.*, Microsoft.*) are not followed, as they cannot
    ///     reference this library.
    /// </summary>
    public static IReadOnlyList<Assembly> DefaultPermissionAssemblies(Assembly callingAssembly)
    {
        var library = typeof(SystemPermissions).Assembly.GetName().Name!;
        var found = new List<Assembly> { callingAssembly };

        void Add(Assembly assembly)
        {
            if (!assembly.IsDynamic && !found.Contains(assembly)) found.Add(assembly);
        }

        bool ReferencesLibrary(Assembly assembly) => assembly.GetReferencedAssemblies().Any(r => r.Name == library);

        // 1. The dependency graph: every library that depends on this package (or on the project, when referenced as
        //    one). A compiler only records a reference to an assembly whose types the code uses in metadata, so a
        //    project referenced only for its permission names (e.g. in nameof) is invisible to step 2 but listed here.
        var context = DependencyContext.Default;
        if (context != null)
            foreach (var runtimeLibrary in context.RuntimeLibraries)
            {
                if (!runtimeLibrary.Dependencies.Any(d => d.Name == PackageId || d.Name == library)) continue;
                foreach (var name in runtimeLibrary.GetDefaultAssemblyNames(context))
                    if (TryLoad(name) is { } assembly)
                        Add(assembly);
            }

        // 2. Static references of the calling and entry assemblies, followed transitively.
        var seen = new HashSet<string>();
        var pending = new Stack<Assembly>();
        foreach (var root in new[] { callingAssembly, Assembly.GetEntryAssembly() }.OfType<Assembly>())
            if (seen.Add(root.GetName().Name ?? root.FullName!))
                pending.Push(root);

        while (pending.Count > 0)
        {
            var assembly = pending.Pop();
            if (ReferencesLibrary(assembly)) Add(assembly);

            foreach (var reference in assembly.GetReferencedAssemblies())
            {
                var name = reference.Name ?? reference.FullName;
                if (IsFramework(name) || !seen.Add(name)) continue;
                if (TryLoad(reference) is { } referenced) pending.Push(referenced);
            }
        }

        // 3. Whatever is loaded already and references the library.
        foreach (var loaded in AppDomain.CurrentDomain.GetAssemblies())
            if (!loaded.IsDynamic && ReferencesLibrary(loaded))
                Add(loaded);

        return found;

        static Assembly? TryLoad(AssemblyName name)
        {
            try
            {
                return Assembly.Load(name);
            }
            catch (Exception e) when (e is FileNotFoundException or FileLoadException or BadImageFormatException)
            {
                // A reference that cannot be loaded cannot declare permissions the app could use either.
                return null;
            }
        }

        static bool IsFramework(string name) =>
            name is "mscorlib" or "netstandard" ||
            name.StartsWith("System", StringComparison.Ordinal) ||
            name.StartsWith("Microsoft.", StringComparison.Ordinal);
    }

    /// <summary>
    ///     Whether the user has any of the roles. For <c>HttpContext.User</c> these are the account's roles in the
    ///     database at the start of the request (see <see cref="DbRolesClaimsTransformation" />). For a principal you
    ///     built from a token yourself they are the roles the token was minted with, which may since have been removed.
    /// </summary>
    public static bool HasRoles(this ClaimsPrincipal user, params string[] roles)
    {
        return roles.Any(user.IsInRole);
    }

    public static string? GetImpersonator(this ClaimsPrincipal user)
    {
        return user.FindFirst(JwtHandler.ImpersonatorClaim)?.Value;
    }

    public static bool IsImpersonated(this ClaimsPrincipal user)
    {
        return user.GetImpersonator() != null;
    }

    public static IQueryable<ApplicationUser> Active(this IQueryable<ApplicationUser> users)
    {
        return users
            .Where(a => a.DateActivated.HasValue);
    }

    /// <summary>Mirrors <c>UserManager.IsLockedOutAsync</c> in SQL.</summary>
    public static IQueryable<ApplicationUser> NotLockedOut(this IQueryable<ApplicationUser> users)
    {
        var now = DateTimeOffset.UtcNow;
        return users
            .Where(a => !a.LockoutEnabled || a.LockoutEnd == null || a.LockoutEnd <= now);
    }

    public static IQueryable<ApplicationUser> HasRoles(this IQueryable<ApplicationUser> users, params string[] roles)
    {
        return users
            .Where(a => a.Roles.Any(r => roles.Contains(r.Role.Name)));
    }

    public static DateTime ToUserUTCDate(this DateTime date)
    {
        return DateTime.SpecifyKind(date, DateTimeKind.Utc);
    }
}