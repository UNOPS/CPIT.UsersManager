using System.Globalization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

/// <summary>
///     A missing <c>expiryInMinutes</c> used to read as 0, so every token was born expired and accepted only through
///     the clock skew, and the numbers were parsed in the server's culture.
/// </summary>
public class JwtSettingsTests
{
    private static TestHost HostWith(string key, string? value) =>
        new(new Dictionary<string, string?> { [$"JwtSettings:{key}"] = value });

    private static OptionsValidationException InvalidSettings(string key, string? value)
    {
        using var host = HostWith(key, value);
        return Assert.Throws<OptionsValidationException>(() => host.Get<JwtHandler>());
    }

    [Fact]
    public void AMissingExpiryIsAnError()
    {
        var error = InvalidSettings("expiryInMinutes", null);

        Assert.Contains("JwtSettings:expiryInMinutes is required", error.Message);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-15")]
    [InlineData("NaN")]
    [InlineData("Infinity")]
    public void AnExpiryThatIsNotAPositiveNumberIsAnError(string minutes)
    {
        Assert.Contains("expiryInMinutes", InvalidSettings("expiryInMinutes", minutes).Message);
    }

    [Theory]
    [InlineData("validIssuer")]
    [InlineData("validAudience")]
    public void AMissingIssuerOrAudienceIsAnError(string key)
    {
        Assert.Contains($"JwtSettings:{key} is required", InvalidSettings(key, null).Message);
    }

    [Fact]
    public void AMaximumLifetimeShorterThanTheExpiryIsAnError()
    {
        Assert.Contains("maxLifetimeInMinutes", InvalidSettings("maxLifetimeInMinutes", "10").Message);
    }

    [Fact]
    public void ANegativeClockSkewIsAnError()
    {
        Assert.Contains("clockSkewInMinutes", InvalidSettings("clockSkewInMinutes", "-1").Message);
    }

    [Fact]
    public void EveryProblemIsReportedAtOnce()
    {
        using var host = new TestHost(new Dictionary<string, string?>
        {
            ["JwtSettings:validIssuer"] = null,
            ["JwtSettings:expiryInMinutes"] = null
        });

        var error = Assert.Throws<OptionsValidationException>(() => host.Get<JwtHandler>());
        Assert.Equal(2, error.Failures.Count());
    }

    /// <summary>"0,5" is half a minute in many cultures, and was read as 5 there.</summary>
    [Fact]
    public void ACommaIsNotADecimalSeparator()
    {
        using var host = HostWith("expiryInMinutes", "0,5");

        var error = Assert.Throws<InvalidOperationException>(() => host.Get<JwtHandler>());
        Assert.Contains("JwtSettings:expiryInMinutes", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NumbersAreReadTheSameWayInEveryCulture()
    {
        var culture = CultureInfo.CurrentCulture;
        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("de-DE");
        try
        {
            using var host = HostWith("expiryInMinutes", "0.5");

            Assert.Equal(TimeSpan.FromSeconds(30), host.Get<JwtHandler>().DefaultLifetime);
        }
        finally
        {
            CultureInfo.CurrentCulture = culture;
        }
    }

    [Fact]
    public void TokensAreValidatedWithTheConfiguredValues()
    {
        using var host = new TestHost(new Dictionary<string, string?> { ["JwtSettings:clockSkewInMinutes"] = "2" });

        var parameters = host.Get<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters;

        Assert.Equal("issuer", parameters.ValidIssuer);
        Assert.Equal("audience", parameters.ValidAudience);
        Assert.Equal(TimeSpan.FromMinutes(2), parameters.ClockSkew);
    }

    [Fact]
    public void TheClockSkewDefaultsToFiveMinutes()
    {
        using var host = new TestHost();

        var parameters = host.Get<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters;

        Assert.Equal(TimeSpan.FromMinutes(5), parameters.ClockSkew);
    }

    [Fact]
    public async Task AnAppWithoutAnExpiryDoesNotStart()
    {
        using var host = new HostBuilder()
            .ConfigureAppConfiguration(builder => builder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = "Host=unused",
                ["JwtSettings:securityKey"] = "test-signing-key-that-is-at-least-32-bytes-long",
                ["JwtSettings:validIssuer"] = "issuer",
                ["JwtSettings:validAudience"] = "audience"
            }))
            .ConfigureServices((context, services) => services.AddUserAuthentication(context.Configuration))
            .Build();

        // Several options are validated at startup and more than one depends on these settings.
        var error = await Assert.ThrowsAnyAsync<Exception>(() => host.StartAsync());
        Assert.Contains("JwtSettings:expiryInMinutes is required", error.Message);
    }
}
