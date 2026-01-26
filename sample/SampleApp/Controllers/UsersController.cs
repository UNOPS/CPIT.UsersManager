using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UsersManager.Helpers;

namespace SampleApp.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly UsersServices _usersServices;

    public UsersController(UsersServices usersServices)
    {
        _usersServices = usersServices;
    }

    [HttpGet("test")]
    public IActionResult Test()
    {
        return Ok(new { message = "UsersManager library is configured and working!" });
    }

    [HttpGet("database-info")]
    public IActionResult GetDatabaseInfo([FromServices] IConfiguration configuration)
    {
        var databaseProvider = configuration.GetSection("DatabaseProvider")?.Value ?? "PostgreSQL";
        var connectionString = configuration.GetConnectionString("DefaultConnection");
        
        // Mask password in connection string for display
        var maskedConnectionString = connectionString;
        if (!string.IsNullOrEmpty(connectionString))
        {
            var parts = connectionString.Split(';');
            maskedConnectionString = string.Join(";", parts.Select(p => 
                p.StartsWith("Password", StringComparison.OrdinalIgnoreCase) ? "Password=***" : p));
        }

        return Ok(new
        {
            databaseProvider,
            connectionString = maskedConnectionString,
            message = $"Currently using {databaseProvider} database"
        });
    }
}
