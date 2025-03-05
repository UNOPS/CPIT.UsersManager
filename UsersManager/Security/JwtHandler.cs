using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Google.Apis.Auth;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using UsersManager.Domain;
using UsersManager.Models;

namespace UsersManager.Security;

public class JwtHandler
{
    private readonly IConfiguration _configuration;
    private readonly IConfigurationSection _goolgeSettings;
    private readonly IConfigurationSection _jwtSettings;

    public JwtHandler(IConfiguration configuration)
    {
        _configuration = configuration;
        _jwtSettings = _configuration.GetSection("JwtSettings");
        _goolgeSettings = _configuration.GetSection("GoogleAuthSettings");
    }

    public SigningCredentials GetSigningCredentials()
    {
        var projectId = _jwtSettings.GetSection("ProjectId")?.Value;
        var secretManager = new SecretManagerConfigurationProvider(projectId);
        var jwtSecretName = _jwtSettings.GetSection("SecretName").Value;
        
        var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET") ??
                                          secretManager.GetSecret(jwtSecretName ?? "JWT_SECRET") ??
                                         _jwtSettings.GetSection("securityKey").Value);
        var secret = new SymmetricSecurityKey(key);
        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    public List<Claim> GetClaims(string userEmail, string[] roles, string? impersonator = null, 
        ClaimPayload[]? claimsPayload = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userEmail)
        };

        if (impersonator != null)
        {
            claims.Add(new Claim("Impersonator",  impersonator));
        }
        
        if (claimsPayload != null)
        {
            foreach (var payload in claimsPayload)
            {
                foreach (var claimValue in payload.ClaimValues)
                {
                    claims.Add(new Claim(payload.ClaimName, claimValue));
                }
            }
        }
        
        // Add roles as multiple claims
        foreach (var role in roles) claims.Add(new Claim(ClaimTypes.Role, role));

        return claims;
    }

    public JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
    {
        var tokenOptions = new JwtSecurityToken(
            _jwtSettings.GetSection("validIssuer").Value,
            _jwtSettings.GetSection("validAudience").Value,
            claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble(_jwtSettings.GetSection("expiryInMinutes").Value)),
            signingCredentials: signingCredentials);
        return tokenOptions;
    }

    public async Task<GoogleJsonWebSignature.Payload> VerifyGoogleToken(ExternalAuthDto externalAuth)
    {
        var settings = new GoogleJsonWebSignature.ValidationSettings
        {
            Audience = new List<string>
            {
                _goolgeSettings.GetSection("clientId").Value
            }
        };

        var payload = await GoogleJsonWebSignature.ValidateAsync(externalAuth.IdToken, settings);
        return payload;
    }

    public async Task<string> GenerateToken(string userEmail, string[] roles, string? impersonator = null, 
        ClaimPayload[]? payloads = null)
    {
        var signingCredentials = GetSigningCredentials();
        var claims = GetClaims(userEmail, roles, impersonator, payloads);
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        return token;
    }
    
    public async Task<string> GenerateToken(ApplicationUser user, string? impersonator = null, 
        ClaimPayload[]? payloads = null)
    {
        var signingCredentials = GetSigningCredentials();
        var claims = GetClaims(user.Email, user.Roles.Select(a => a.Role.Name).ToArray(), impersonator, payloads);
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        return token;
    }
}