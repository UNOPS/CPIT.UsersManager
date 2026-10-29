using Microsoft.Extensions.Options;

namespace UsersManager.Security;

/// <summary>
///     The signing key is not here; see <see cref="JwtSigningKey" />. Numbers are read the same way whatever the
///     server's culture, with a <c>.</c> as the decimal separator.
/// </summary>
public sealed class JwtSettingsOptions
{
    public const string Section = "JwtSettings";

    public string? ValidIssuer { get; set; }
    public string? ValidAudience { get; set; }

    public double? ExpiryInMinutes { get; set; }

    public double? MaxLifetimeInMinutes { get; set; }

    public double? ClockSkewInMinutes { get; set; }

    public TimeSpan Expiry => TimeSpan.FromMinutes(ExpiryInMinutes ?? 0);
    public TimeSpan MaxLifetime => MaxLifetimeInMinutes is { } minutes ? TimeSpan.FromMinutes(minutes) : Expiry;
    public TimeSpan ClockSkew => TimeSpan.FromMinutes(ClockSkewInMinutes ?? 5);
}

/// <summary>
///     Without these checks a missing <c>expiryInMinutes</c> read as 0, so every token was born expired and lived only
///     for the clock skew, and a missing issuer or audience made every token fail validation with no hint why.
/// </summary>
public sealed class JwtSettingsOptionsValidator : IValidateOptions<JwtSettingsOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtSettingsOptions options)
    {
        var failures = new List<string>();
        const string section = JwtSettingsOptions.Section;

        if (string.IsNullOrWhiteSpace(options.ValidIssuer))
            failures.Add($"{section}:validIssuer is required.");
        if (string.IsNullOrWhiteSpace(options.ValidAudience))
            failures.Add($"{section}:validAudience is required.");

        if (!IsPositive(options.ExpiryInMinutes))
            failures.Add($"{section}:expiryInMinutes is required and must be a positive number of minutes.");
        else if (options.MaxLifetimeInMinutes is { } max && (!IsPositive(max) || max < options.ExpiryInMinutes))
            failures.Add($"{section}:maxLifetimeInMinutes must be at least {section}:expiryInMinutes " +
                         $"({options.ExpiryInMinutes}), or tokens of the default lifetime could not be issued.");

        if (options.ClockSkewInMinutes is { } skew && !(double.IsFinite(skew) && skew >= 0))
            failures.Add($"{section}:clockSkewInMinutes must be zero or a positive number of minutes.");

        return failures.Count > 0
            ? ValidateOptionsResult.Fail(failures.Select(failure => $"[UsersManager] {failure}"))
            : ValidateOptionsResult.Success;
    }

    private static bool IsPositive(double? minutes) => minutes is { } value && double.IsFinite(value) && value > 0;
}
