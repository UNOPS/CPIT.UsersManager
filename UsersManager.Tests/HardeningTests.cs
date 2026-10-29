using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using UsersManager.Models;
using UsersManager.Security;

namespace UsersManager.Tests;

public class HardeningTests : IDisposable
{
    private readonly TestHost _host = new();

    public void Dispose() => _host.Dispose();

    private JwtBearerOptions BearerOptions =>
        _host.Get<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

    [Fact]
    public async Task ATokenIsNotValidBeforeItWasIssued()
    {
        var token = new JwtSecurityToken(await _host.Get<JwtHandler>().GenerateToken("a@example.org", []));

        Assert.True(token.Payload.NotBefore.HasValue);
        Assert.Equal(token.IssuedAt, token.ValidFrom);
    }

    /// <summary>
    ///     An application that turns claim mapping off globally would otherwise read the e-mail as "unique_name", leave
    ///     <c>User.Identity.Name</c> empty and fail every database check.
    /// </summary>
    [Fact]
    public async Task TheNameAndRolesAreReadAsTheLibraryWritesThem()
    {
        var options = BearerOptions;
        Assert.True(options.MapInboundClaims);
        Assert.Equal(ClaimTypes.Name, options.TokenValidationParameters.NameClaimType);
        Assert.Equal(ClaimTypes.Role, options.TokenValidationParameters.RoleClaimType);

        var token = await _host.Get<JwtHandler>().GenerateToken("a@example.org", [TestRole.Admin]);
        var handler = new JsonWebTokenHandler { MapInboundClaims = options.MapInboundClaims };
        var result = await handler.ValidateTokenAsync(token, options.TokenValidationParameters);

        var principal = new ClaimsPrincipal(result.ClaimsIdentity);
        Assert.Equal("a@example.org", principal.Identity!.Name);
        Assert.True(principal.IsInRole(TestRole.Admin));
    }

    [Fact]
    public async Task AMissingGoogleClientIdIsAConfigurationError()
    {
        var auth = new ExternalAuthDto { Provider = JwtHandler.GoogleProvider, IdToken = "token" };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _host.Get<JwtHandler>().VerifyGoogleToken(auth));
        Assert.Contains("GoogleAuthSettings:clientId", error.Message);
    }

    [Fact]
    public void TheDatabaseHandlersLiveForTheRequest()
    {
        static IEnumerable<IAuthorizationHandler> Handlers(IServiceProvider services) =>
            services.GetServices<IAuthorizationHandler>()
                .Where(h => h is RolesInDbAuthorizationHandler or ActiveUserAuthorizationHandler);

        Assert.Equal(Handlers(_host.Services), Handlers(_host.Services));
    }

    [Fact]
    public void ASignInRequestNeedsAProviderAndAToken()
    {
        var errors = Validate(new ExternalAuthDto());

        Assert.Equal(
            [nameof(ExternalAuthDto.Provider), nameof(ExternalAuthDto.IdToken)],
            errors.SelectMany(e => e.MemberNames));
    }

    [Fact]
    public void AClaimPayloadNeedsAName()
    {
        Assert.Single(Validate(new ClaimPayload()));
        Assert.Empty(Validate(new ClaimPayload { ClaimName = "tenant" }));
    }

    private static List<ValidationResult> Validate(object instance)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(instance, new ValidationContext(instance), results, validateAllProperties: true);
        return results;
    }
}
