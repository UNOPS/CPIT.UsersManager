using System.ComponentModel.DataAnnotations;

namespace UsersManager.Security;

/// <summary>
///     Usually bound from a request body, so either value may be missing; <see cref="JwtHandler.VerifyGoogleToken" />
///     rejects that as well as model validation does.
/// </summary>
public class ExternalAuthDto
{
    [Required] public string? Provider { get; set; }
    [Required] public string? IdToken { get; set; }
}
