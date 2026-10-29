using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using UsersManager.DataAccess;
using UsersManager.Domain;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

public class TestRole : SystemRole
{
    public const string Admin = "TestAdmin";
}

public class TestPermissions : SystemPermissions
{
    public static readonly SystemAction CanDoAdminThings = new(nameof(CanDoAdminThings), TestRole.Admin);

    public static readonly SystemAction CanDoAdminThingsInOwnName =
        new(nameof(CanDoAdminThingsInOwnName), TestRole.Admin) { AllowImpersonation = false };
}

/// <summary>
///     The library's own <see cref="Extensions.AddUserAuthentication" /> registrations, with the database swapped for
///     an in-memory one so the policies and handlers under test are exactly the ones consumers get.
/// </summary>
public sealed class TestHost : IDisposable
{
    private readonly ServiceProvider _root;

    public TestHost(IDictionary<string, string?>? settings = null, params Assembly[] permissionAssemblies)
        : this(settings, _ => { }, permissionAssemblies)
    {
    }

    /// <param name="configureServices">Further registrations, made after the library's own.</param>
    public TestHost(Action<IServiceCollection> configureServices) : this(null, configureServices)
    {
    }

    private TestHost(IDictionary<string, string?>? settings, Action<IServiceCollection> configureServices,
        params Assembly[] permissionAssemblies)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = "Host=unused",
                ["JwtSettings:securityKey"] = "test-signing-key-that-is-at-least-32-bytes-long",
                ["JwtSettings:validIssuer"] = "issuer",
                ["JwtSettings:validAudience"] = "audience",
                ["JwtSettings:expiryInMinutes"] = "15"
            })
            .AddInMemoryCollection(settings ?? new Dictionary<string, string?>())
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(logging => logging.AddProvider(new CapturingLoggerProvider(Logs)));
        services.AddSingleton<IConfiguration>(configuration);
        services.AddUserAuthentication(configuration, permissionAssemblies);
        configureServices(services);

        foreach (var descriptor in services.Where(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>))
                     .ToList())
            services.Remove(descriptor);
        var databaseName = Guid.NewGuid().ToString();
        services.AddDbContext<ApplicationDbContext>(options => options.UseInMemoryDatabase(databaseName));

        _root = services.BuildServiceProvider();
        Services = _root.CreateScope().ServiceProvider;
    }

    public IServiceProvider Services { get; }

    public List<LogEntry> Logs { get; } = [];

    public T Get<T>() where T : notnull => Services.GetRequiredService<T>();

    public async Task<ApplicationUser> CreateUserAsync(bool active = true, params string[] roles)
    {
        var email = $"user.{Guid.NewGuid():N}@example.org";
        var info = new UserLoginInfo("Google", Guid.NewGuid().ToString("N"), "Google");
        var user = await Get<UsersServices>().Register(info, email);

        foreach (var role in roles)
            if (!await Get<RoleManager<ApplicationRole>>().RoleExistsAsync(role))
                await Get<RoleManager<ApplicationRole>>().CreateAsync(new ApplicationRole { Name = role });
        if (roles.Length > 0)
            await Get<UsersServices>().AssignRoles(user, roles);

        if (active)
        {
            user.Activate();
            await Get<UserManager<ApplicationUser>>().UpdateAsync(user);
        }

        return user;
    }

    public async Task<UserLoginInfo> LoginOfAsync(ApplicationUser user) =>
        (await Get<UserManager<ApplicationUser>>().GetLoginsAsync(user)).Single();

    public async Task LockOutAsync(ApplicationUser user, DateTimeOffset until)
    {
        await Get<UserManager<ApplicationUser>>().SetLockoutEndDateAsync(user, until);
    }

    public async Task DeactivateAsync(ApplicationUser user)
    {
        user.Deactivate();
        await Get<UserManager<ApplicationUser>>().UpdateAsync(user);
    }

    public static ClaimsPrincipal TokenFor(string email, string? impersonator = null, params string[] roles)
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, email) };
        if (impersonator != null)
            claims.Add(new Claim(JwtHandler.ImpersonatorClaim, impersonator));
        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));
    }

    public void Dispose() => _root.Dispose();
}

public record LogEntry(LogLevel Level, EventId EventId, string Message);

internal sealed class CapturingLoggerProvider(List<LogEntry> entries) : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName) => new CapturingLogger(entries);

    public void Dispose()
    {
    }

    private sealed class CapturingLogger(List<LogEntry> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (entries) entries.Add(new LogEntry(logLevel, eventId, formatter(state, exception)));
        }
    }
}
