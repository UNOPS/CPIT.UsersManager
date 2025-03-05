using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Security;

namespace UsersManager.Helpers;

public static class Extensions
{
    public static void AddUserAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddIdentity<ApplicationUser, ApplicationRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();
        
        var jwtSettings = configuration.GetSection("JwtSettings");
        var projectId = jwtSettings.GetSection("ProjectId")?.Value;
        var secretManager = new SecretManagerConfigurationProvider(projectId);
        var jwtSecretName = jwtSettings.GetSection("SecretName").Value;
        
        var jwtSecurityKey = Environment.GetEnvironmentVariable("JWT_SECRET") ??
                             secretManager.GetSecret(jwtSecretName ?? "JWT_SECRET") ??
                             jwtSettings.GetSection("securityKey").Value;

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

    public static bool HasRoles(this ClaimsPrincipal user, params string [] roles)
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

    public static IQueryable<ApplicationUser> HasRoles(this IQueryable<ApplicationUser> users, params string [] roles)
    {
        return users
            .Where(a => a.Roles.Any(r => roles.Contains(r.Role.Name)));
    }
    
    public static DateTime ToUserUTCDate(this DateTime date)
    {
        return DateTime.SpecifyKind(date, DateTimeKind.Utc);
    }
}