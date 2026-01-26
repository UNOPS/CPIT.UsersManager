using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using System.Security.Claims;
using System.Text;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public static class Extensions
{
    public static void AddUserAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        // Configure database provider
        var databaseProvider = configuration.GetSection("DatabaseProvider")?.Value ?? "PostgreSQL";
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrEmpty(connectionString))
        {
            throw new InvalidOperationException(
                "[UsersManager] Connection string 'DefaultConnection' is required. " +
                "Please add it to your ConnectionStrings section in appsettings.json.");
        }

        // Get the calling assembly name for migrations (the consuming application)
        var migrationsAssembly = System.Reflection.Assembly.GetCallingAssembly().GetName().Name;

        // Configure DbContext based on database provider
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (string.Equals(databaseProvider, "MySQL", StringComparison.OrdinalIgnoreCase))
            {
                // Use MySQL 8.0.21 as default server version
                // This is compatible with MySQL 8.0+ and MariaDB 10.5+
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

        services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        var jwtSettings = configuration.GetSection("JwtSettings");
        var projectId = jwtSettings.GetSection("ProjectId")?.Value;
        var jwtSecretName = jwtSettings.GetSection("SecretName").Value;

        string? jwtSecurityKey = null;

        if (!string.IsNullOrEmpty(jwtSecretName))
        {
            var secretManager = new SecretManagerConfigurationProvider(projectId);
            jwtSecurityKey = secretManager.GetSecret(jwtSecretName);
        }

        jwtSecurityKey ??= Environment.GetEnvironmentVariable("JWT_SECRET") ??
                           jwtSettings.GetSection("securityKey").Value;

        if (string.IsNullOrEmpty(jwtSecurityKey))
        {
            var errorMessage = $"[UsersManager] Failed to retrieve JWT security key. " +
                             $"Attempted: Google Secret Manager ({jwtSecretName}), Environment Variable (JWT_SECRET), appsettings (securityKey). " +
                             $"Please configure at least one source.";

            Console.Error.WriteLine(errorMessage);
            throw new InvalidOperationException(errorMessage);
        }

        services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings.GetSection("validIssuer").Value,
                ValidAudience = jwtSettings.GetSection("validAudience").Value,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecurityKey)),
                ClockSkew = TimeSpan.FromHours(8)
            };
        });
        services.AddScoped<JwtHandler>();
        services.AddScoped<UsersServices>();

        services.AddAuthorization(options => { options.AddAuthorizationPolicies(configuration); });
        services.AddTransient<IAuthorizationHandler, RolesInDbAuthorizationHandler>();
    }

    public static bool HasRoles(this ClaimsPrincipal user, params string[] roles)
    {
        return user.Claims
            .Where(a => a.Type == ClaimTypes.Role)
            .Any(a => roles.Contains(a.Value));
    }

    public static IQueryable<ApplicationUser> Active(this IQueryable<ApplicationUser> users)
    {
        return users
            .Where(a => a.DateActivated.HasValue);
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