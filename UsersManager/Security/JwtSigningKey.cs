using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace UsersManager.Security;

/// <summary>
///     The key tokens are signed and validated with, resolved once so that both always use the same one. It is read
///     from, in order: the Google Secret Manager secret <c>JwtSettings:SecretName</c>, the <c>JWT_SECRET</c>
///     environment variable, and <c>JwtSettings:securityKey</c>. Outside Development a source that is configured but
///     fails is an error rather than a reason to try the next one, and <c>securityKey</c> is refused when it comes from
///     a file such as appsettings.json, since that file is usually in source control.
///     <para>
///         To rotate the key without invalidating the tokens already issued, keep the old one in
///         <c>JwtSettings:PreviousSecretVersions</c> (versions of <c>SecretName</c>) or
///         <c>JwtSettings:previousSecurityKeys</c> until the last token signed with it has expired. Those are only
///         used to validate tokens, never to sign them, and follow the same rules as the signing key.
///     </para>
/// </summary>
public sealed class JwtSigningKey
{
    /// <summary>HS256 needs a key at least as long as its 256-bit output to be as strong as the algorithm.</summary>
    public const int MinimumKeyBytes = 32;

    public const string Algorithm = SecurityAlgorithms.HmacSha256;

    private const string SecurityKeyPath = "JwtSettings:securityKey";
    private const string PreviousSecurityKeysPath = "JwtSettings:previousSecurityKeys";
    private const string PreviousSecretVersionsPath = "JwtSettings:PreviousSecretVersions";

    public JwtSigningKey(IConfiguration configuration, ILogger<JwtSigningKey> logger,
        IHostEnvironment? environment = null)
        : this(configuration, logger, environment, SecretManager())
    {
    }

    internal JwtSigningKey(IConfiguration configuration, ILogger<JwtSigningKey> logger,
        IHostEnvironment? environment, Func<string?, string, string, string> readSecret)
    {
        // Without a host there is no way to tell Development apart, so assume the strictest case.
        var isDevelopment = environment?.IsDevelopment() ?? false;

        var (value, source) = Resolve(configuration, logger, isDevelopment, readSecret);
        Key = ToKey(value, source, logger);

        var previousKeys = ResolvePrevious(configuration, logger, isDevelopment, readSecret)
            .Select(previous => ToKey(previous.Value, previous.Source, logger))
            // Listing the current key as a previous one too is harmless; it only needs to be tried once.
            .Where(key => key.KeyId != Key.KeyId)
            .DistinctBy(key => key.KeyId);
        ValidationKeys = [Key, ..previousKeys];

        var previousKeyIds = ValidationKeys.Skip(1).Select(k => k.KeyId).ToList();
        logger.LogInformation(
            "[UsersManager] JWT signing key {KeyId} loaded from {KeySource}; previous keys still accepted: " +
            "{PreviousKeyIds}", Key.KeyId, source, previousKeyIds.Count > 0 ? string.Join(", ", previousKeyIds) : "none");
    }

    public SymmetricSecurityKey Key { get; }

    /// <summary>
    ///     The keys a token may be signed with to be accepted: <see cref="Key" /> first, then the previous keys. A token
    ///     is checked against the key its <c>kid</c> names, or against all of them when it has none, as tokens issued
    ///     before 5.0.0 don't.
    /// </summary>
    public IReadOnlyList<SymmetricSecurityKey> ValidationKeys { get; }

    public SigningCredentials SigningCredentials => new(Key, Algorithm);

    private static Func<string?, string, string, string> SecretManager()
    {
        SecretManagerConfigurationProvider? client = null;
        return (projectId, secretName, version) =>
            (client ??= new SecretManagerConfigurationProvider(projectId)).GetSecret(secretName, version);
    }

    private static SymmetricSecurityKey ToKey(string value, string source, ILogger logger)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length < MinimumKeyBytes)
            throw Fail(logger,
                $"The JWT signing key from {source} is {bytes.Length} bytes; it must be at least {MinimumKeyBytes} " +
                "random bytes. Generate one with `openssl rand -base64 48`.");

        var key = new SymmetricSecurityKey(bytes);
        // The key's RFC 7638 thumbprint, so that every instance derives the same id for the same key without it being
        // configured. A hash of 32 random bytes says nothing about them.
        key.KeyId = Base64UrlEncoder.Encode(key.ComputeJwkThumbprint())[..16];
        return key;
    }

    private static (string Value, string Source) Resolve(IConfiguration configuration, ILogger logger,
        bool isDevelopment, Func<string?, string, string, string> readSecret)
    {
        var jwtSettings = configuration.GetSection("JwtSettings");
        var secretName = jwtSettings["SecretName"];

        if (!string.IsNullOrEmpty(secretName))
        {
            var source = $"Google Secret Manager secret '{secretName}'";
            if (TryReadSecret(jwtSettings["ProjectId"], secretName, "latest", source, logger, isDevelopment,
                    readSecret) is { } secret)
                return (secret, source);
        }

        var environmentVariable = Environment.GetEnvironmentVariable("JWT_SECRET");
        if (!string.IsNullOrEmpty(environmentVariable))
            return (environmentVariable, "the JWT_SECRET environment variable");

        var securityKey = configuration[SecurityKeyPath];
        if (!string.IsNullOrEmpty(securityKey))
        {
            EnsureNotInAFile(configuration, SecurityKeyPath, logger, isDevelopment);
            return (securityKey, SecurityKeyPath);
        }

        throw Fail(logger,
            "No JWT signing key is configured. Set JwtSettings:SecretName (Google Secret Manager), the JWT_SECRET " +
            $"environment variable or, in Development, {SecurityKeyPath}.");
    }

    private static IEnumerable<(string Value, string Source)> ResolvePrevious(IConfiguration configuration,
        ILogger logger, bool isDevelopment, Func<string?, string, string, string> readSecret)
    {
        var jwtSettings = configuration.GetSection("JwtSettings");

        var versions = Values(configuration.GetSection(PreviousSecretVersionsPath)).ToList();
        if (versions.Count > 0)
        {
            var secretName = jwtSettings["SecretName"];
            if (string.IsNullOrEmpty(secretName))
                throw Fail(logger, $"{PreviousSecretVersionsPath} is set but JwtSettings:SecretName is not.");

            foreach (var (_, version) in versions)
            {
                var source = $"version {version} of Google Secret Manager secret '{secretName}'";
                if (TryReadSecret(jwtSettings["ProjectId"], secretName, version, source, logger, isDevelopment,
                        readSecret) is { } secret)
                    yield return (secret, source);
            }
        }

        foreach (var (path, value) in Values(configuration.GetSection(PreviousSecurityKeysPath)))
        {
            // A previous key that is committed to the repository lets anyone mint tokens as surely as a current one.
            EnsureNotInAFile(configuration, path, logger, isDevelopment);
            yield return (value, path);
        }
    }

    private static IEnumerable<(string Path, string Value)> Values(IConfigurationSection section) =>
        section.GetChildren()
            .Where(child => !string.IsNullOrEmpty(child.Value))
            .Select(child => (child.Path, child.Value!));

    /// <summary>
    ///     The secret, or <c>null</c> when it can't be read in Development. Outside Development that is an error, since
    ///     carrying on would sign with whatever key is configured locally, typically one committed to the repository,
    ///     without anyone noticing the secret was never read.
    /// </summary>
    private static string? TryReadSecret(string? projectId, string secretName, string version, string source,
        ILogger logger, bool isDevelopment, Func<string?, string, string, string> readSecret)
    {
        try
        {
            var secret = readSecret(projectId, secretName, version);
            if (!string.IsNullOrEmpty(secret)) return secret;
            throw new InvalidOperationException("The secret is empty.");
        }
        catch (Exception e)
        {
            if (!isDevelopment)
                throw Fail(logger, $"Could not read the JWT signing key from {source}.", e);
            logger.LogWarning(e,
                "[UsersManager] Could not read the JWT signing key from {KeySource}; skipping it because this is " +
                "Development", source);
            return null;
        }
    }

    private static void EnsureNotInAFile(IConfiguration configuration, string path, ILogger logger,
        bool isDevelopment)
    {
        if (!isDevelopment && ComesFromAFile(configuration, path))
            throw Fail(logger,
                $"{path} is set in a configuration file, which is only allowed in Development. " +
                "Outside Development use JwtSettings:SecretName (Google Secret Manager) or an environment variable, " +
                "and remove the key from the file and rotate it, as it is in source control.");
    }

    /// <summary>
    ///     Whether the value that wins for <paramref name="key" /> is read from a file. When that can't be told, it is
    ///     assumed to be.
    /// </summary>
    private static bool ComesFromAFile(IConfiguration configuration, string key)
    {
        if (configuration is not IConfigurationRoot root) return true;

        // Later providers override earlier ones.
        var provider = root.Providers.LastOrDefault(p => p.TryGet(key, out _));
        return provider switch
        {
            FileConfigurationProvider => true,
            ChainedConfigurationProvider chained => ComesFromAFile(chained.Configuration, key),
            _ => false
        };
    }

    private static InvalidOperationException Fail(ILogger logger, string message, Exception? inner = null)
    {
        message = $"[UsersManager] {message}";
        logger.LogCritical(inner, "{Message}", message);
        return new InvalidOperationException(message, inner);
    }
}
