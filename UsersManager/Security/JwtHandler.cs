using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Google.Apis.Auth;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UsersManager.Domain;
using UsersManager.Models;
using JsonWebTokenHandler = Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler;

namespace UsersManager.Security;

public class JwtHandler
{
    public const string ImpersonatorClaim = "Impersonator";

    public const string GoogleProvider = "Google";

    private readonly IConfiguration _configuration;
    private readonly IConfigurationSection _goolgeSettings;
    private readonly JwtSettingsOptions _jwtSettings;
    private readonly ILogger<JwtHandler> _logger;
    private readonly JwtSigningKey _signingKey;

    public JwtHandler(IConfiguration configuration, ILogger<JwtHandler> logger, JwtSigningKey signingKey,
        IOptions<JwtSettingsOptions> jwtSettings)
    {
        _configuration = configuration;
        _logger = logger;
        _signingKey = signingKey;
        _jwtSettings = jwtSettings.Value;
        _goolgeSettings = _configuration.GetSection("GoogleAuthSettings");
    }

    public SigningCredentials GetSigningCredentials() => _signingKey.SigningCredentials;

    public List<Claim> GetClaims(string userEmail, string[] roles, string? impersonator = null, 
        ClaimPayload[]? claimsPayload = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userEmail)
        };

        if (impersonator != null)
        {
            if (string.IsNullOrWhiteSpace(impersonator))
                throw new ArgumentException("An impersonator must be named.", nameof(impersonator));
            claims.Add(new Claim(ImpersonatorClaim, impersonator));
        }
        
        if (claimsPayload != null)
        {
            foreach (var payload in claimsPayload)
            {
                if (string.IsNullOrWhiteSpace(payload.ClaimName))
                    throw new ArgumentException("A claim payload has no ClaimName.", nameof(claimsPayload));
                if (IsReservedClaimType(payload.ClaimName))
                    throw new ArgumentException(
                        $"'{payload.ClaimName}' is set by the library and cannot be supplied as a custom claim.",
                        nameof(claimsPayload));

                foreach (var claimValue in payload.ClaimValues ?? [])
                {
                    claims.Add(new Claim(payload.ClaimName, claimValue));
                }
            }
        }
        
        foreach (var role in roles) claims.Add(new Claim(ClaimTypes.Role, role));

        return claims;
    }

    /// <summary>
    ///     Claim types that carry the identity, the roles or the token's own registered fields. A custom claim of one
    ///     of these types would let whoever controls the payload choose who the token is for or what it may do.
    /// </summary>
    private static readonly HashSet<string> ReservedClaimTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ClaimTypes.Name,
        ClaimTypes.NameIdentifier,
        ClaimTypes.Role,
        ImpersonatorClaim,
        JwtRegisteredClaimNames.Iss,
        JwtRegisteredClaimNames.Sub,
        JwtRegisteredClaimNames.Aud,
        JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf,
        JwtRegisteredClaimNames.Iat,
        JwtRegisteredClaimNames.Jti
    };

    /// <summary>
    ///     Also catches names that only become reserved on the way through the token: the short JWT names (e.g. "role",
    ///     "unique_name") that the bearer handler maps back to a reserved type, and anything the outbound map would
    ///     write as one. Claim types are matched ignoring case, as <see cref="ClaimsIdentity" /> does.
    /// </summary>
    private static bool IsReservedClaimType(string claimType)
    {
        var written = new[] { claimType, Lookup(JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap, claimType) };
        return written.OfType<string>().Any(type =>
            ReservedClaimTypes.Contains(type) ||
            ReservedClaimTypes.Contains(Lookup(JwtSecurityTokenHandler.DefaultInboundClaimTypeMap, type) ?? "") ||
            ReservedClaimTypes.Contains(Lookup(JsonWebTokenHandler.DefaultInboundClaimTypeMap, type) ?? ""));

        static string? Lookup(IDictionary<string, string> map, string key) =>
            map.FirstOrDefault(entry => string.Equals(entry.Key, key, StringComparison.OrdinalIgnoreCase)).Value;
    }

    /// <summary>
    ///     Builds the token. <paramref name="lifetime" /> defaults to <c>JwtSettings:expiryInMinutes</c> and must be
    ///     positive and no longer than <see cref="MaxLifetime" />, or <see cref="ArgumentOutOfRangeException" /> is
    ///     thrown.
    /// </summary>
    public JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims,
        TimeSpan? lifetime = null)
    {
        lifetime ??= DefaultLifetime;
        // Whoever can reach a lifetime argument could otherwise mint a token that outlives every role removal and
        // key rotation the application will ever make.
        if (lifetime <= TimeSpan.Zero || lifetime > MaxLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime,
                $"A token's lifetime must be positive and at most {MaxLifetime.TotalMinutes} minutes " +
                "(JwtSettings:maxLifetimeInMinutes).");

        // jti and iat identify each token and when it was issued, so logs can tell tokens apart and a token can be
        // singled out for revocation. nbf keeps a token from being accepted before it was issued, beyond clock skew.
        var now = DateTime.UtcNow;
        if (!claims.Any(c => c.Type == JwtRegisteredClaimNames.Jti))
            claims = [..claims, new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())];

        var tokenOptions = new JwtSecurityToken(
            new JwtHeader(signingCredentials),
            new JwtPayload(
                _jwtSettings.ValidIssuer,
                _jwtSettings.ValidAudience,
                claims,
                notBefore: now,
                expires: now.Add(lifetime.Value),
                issuedAt: now));
        return tokenOptions;
    }

    /// <summary><c>JwtSettings:expiryInMinutes</c>.</summary>
    public TimeSpan DefaultLifetime => _jwtSettings.Expiry;

    /// <summary>
    ///     The longest lifetime a token can be given: <c>JwtSettings:maxLifetimeInMinutes</c>, or
    ///     <see cref="DefaultLifetime" /> when that is not set.
    /// </summary>
    public TimeSpan MaxLifetime => _jwtSettings.MaxLifetime;

    /// <summary>
    ///     Validates a Google ID token and returns its payload. Throws <see cref="InvalidJwtException" /> when the
    ///     token is missing or invalid, <see cref="ExternalAuthDto.Provider" /> is not <see cref="GoogleProvider" />, the
    ///     account's e-mail address is not verified, or <c>GoogleAuthSettings:hostedDomain</c> is set and the account
    ///     is not in that Workspace domain. Throws <see cref="InvalidOperationException" /> when
    ///     <c>GoogleAuthSettings:clientId</c> is not configured.
    /// </summary>
    public async Task<GoogleJsonWebSignature.Payload> VerifyGoogleToken(ExternalAuthDto externalAuth)
    {
        // Only Google tokens are verified here, so any other provider name would file a Google identity under a
        // name the client picked.
        if (!string.Equals(externalAuth.Provider, GoogleProvider, StringComparison.OrdinalIgnoreCase))
            throw new InvalidJwtException($"Unsupported login provider '{externalAuth.Provider}'.");
        // Google throws an ArgumentException for a missing token, which a caller catching InvalidJwtException would
        // let through as a 500.
        if (string.IsNullOrWhiteSpace(externalAuth.IdToken))
            throw new InvalidJwtException("No ID token was supplied.");

        // Without it every token is rejected for its audience, which reads as the caller's fault rather than a
        // missing setting.
        var clientId = _goolgeSettings.GetSection("clientId").Value;
        if (string.IsNullOrWhiteSpace(clientId))
            throw new InvalidOperationException("[UsersManager] GoogleAuthSettings:clientId is not configured.");

        var hostedDomain = _goolgeSettings.GetSection("hostedDomain").Value;
        var settings = new GoogleJsonWebSignature.ValidationSettings
        {
            Audience = new List<string> { clientId },
            // Without it any Google account in the world can sign in, not only the organisation's.
            HostedDomain = string.IsNullOrWhiteSpace(hostedDomain) ? null : hostedDomain
        };

        var payload = await GoogleJsonWebSignature.ValidateAsync(externalAuth.IdToken, settings);
        EnsureEmailVerified(payload);
        return payload;
    }

    /// <summary>
    ///     A Google account can carry an e-mail address Google has not verified, so an unverified address says
    ///     nothing about who owns it. Accounts are found by e-mail, so it would let anyone claim someone else's.
    /// </summary>
    internal static void EnsureEmailVerified(GoogleJsonWebSignature.Payload payload)
    {
        if (!payload.EmailVerified || string.IsNullOrWhiteSpace(payload.Email))
            throw new InvalidJwtException("The Google account's e-mail address is not verified.");
    }

    /// <summary>
    ///     Mints a token for <paramref name="userEmail" /> with <paramref name="roles" /> without looking the account
    ///     up, so never pass it values taken from a request. Prefer <see cref="GenerateToken(ApplicationUser, string?,
    ///     ClaimPayload[]?, TimeSpan?)" />, or <see cref="Helpers.UsersServices.Impersonate" /> to impersonate.
    /// </summary>
    public Task<string> GenerateToken(string userEmail, string[] roles, string? impersonator = null,
        ClaimPayload[]? payloads = null, TimeSpan? lifetime = null)
    {
        return Task.FromResult(WriteToken(GetClaims(userEmail, roles, impersonator, payloads), lifetime));
    }

    /// <summary>Mints a token for <paramref name="user" /> with the roles loaded on it. Throws when it has no e-mail.</summary>
    public Task<string> GenerateToken(ApplicationUser user, string? impersonator = null,
        ClaimPayload[]? payloads = null, TimeSpan? lifetime = null)
    {
        if (string.IsNullOrWhiteSpace(user.Email))
            throw new ArgumentException("The user has no e-mail address to name the token after.", nameof(user));
        var roles = user.Roles.Select(a => a.Role.Name).OfType<string>().ToArray();
        return Task.FromResult(WriteToken(GetClaims(user.Email, roles, impersonator, payloads), lifetime));
    }

    private string WriteToken(List<Claim> claims, TimeSpan? lifetime)
    {
        var tokenOptions = GenerateTokenOptions(GetSigningCredentials(), claims, lifetime);
        var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

        // An impersonation token acts as someone else, so it must leave a trace that names who is behind it.
        var impersonator = claims.FirstOrDefault(c => c.Type == ImpersonatorClaim)?.Value;
        if (impersonator != null)
            _logger.LogWarning(ImpersonationTokenIssued,
                "[UsersManager] {Impersonator} was issued token {TokenId} to impersonate {User} until {Expires:o}",
                impersonator, tokenOptions.Id, claims.First(c => c.Type == ClaimTypes.Name).Value,
                tokenOptions.ValidTo);

        return token;
    }

    public static readonly EventId ImpersonationTokenIssued = new(1001, nameof(ImpersonationTokenIssued));
}
