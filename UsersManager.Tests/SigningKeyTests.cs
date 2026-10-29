using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using UsersManager.Helpers;
using UsersManager.Security;

namespace UsersManager.Tests;

public class SigningKeyTests : IDisposable
{
    private const string GoodKey = "a-signing-key-that-is-at-least-32-bytes-long";
    private const string SecretKey = "the-key-stored-in-google-secret-manager-0123";
    private const string OldKey = "the-key-tokens-were-signed-with-before-rotation";

    private readonly string _appsettingsDirectory = Directory.CreateTempSubdirectory().FullName;

    private static Dictionary<string, string?> Settings(string? securityKey = GoodKey, string? secretName = null) =>
        new()
        {
            ["ConnectionStrings:DefaultConnection"] = "Host=unused",
            ["JwtSettings:securityKey"] = securityKey,
            ["JwtSettings:SecretName"] = secretName,
            ["JwtSettings:validIssuer"] = "issuer",
            ["JwtSettings:validAudience"] = "audience",
            ["JwtSettings:expiryInMinutes"] = "15"
        };

    private static IConfiguration InMemory(Dictionary<string, string?> settings) =>
        new ConfigurationBuilder().AddInMemoryCollection(settings).Build();

    private IConfigurationBuilder AppsettingsFile(string securityKey, string? previousSecurityKey = null)
    {
        var path = Path.Combine(_appsettingsDirectory, "appsettings.json");
        var previous = previousSecurityKey == null ? "" : $$""", "previousSecurityKeys": ["{{previousSecurityKey}}"]""";
        File.WriteAllText(path, $$"""{ "JwtSettings": { "securityKey": "{{securityKey}}"{{previous}} } }""");
        return new ConfigurationBuilder().AddJsonFile(path);
    }

    private static IHostEnvironment Environment(string name) => new HostingEnvironment { EnvironmentName = name };

    private static JwtSigningKey Resolve(IConfiguration configuration, string environment = "Production",
        Func<string?, string, string, string>? readSecret = null) =>
        new(configuration, NullLogger<JwtSigningKey>.Instance, Environment(environment),
            readSecret ?? ((_, _, _) => throw new InvalidOperationException("Secret Manager should not be called.")));

    private static string KeyText(JwtSigningKey key) => Encoding.UTF8.GetString(key.Key.Key);

    private static string[] ValidationKeyTexts(JwtSigningKey key) =>
        key.ValidationKeys.Select(k => Encoding.UTF8.GetString(k.Key)).ToArray();

    private static TokenValidationParameters ValidationParameters(TestHost host) =>
        host.Get<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters;

    /// <summary>Validates as the bearer handler does, which uses <see cref="JsonWebTokenHandler" /> since .NET 8.</summary>
    private static async Task<bool> IsAccepted(string token, TestHost host) =>
        (await new JsonWebTokenHandler().ValidateTokenAsync(token, ValidationParameters(host))).IsValid;

    private static Task<string> TokenFrom(TestHost host) =>
        host.Get<JwtHandler>().GenerateToken("user@example.org", []);

    private static TestHost HostWithPreviousKey(string previousKey) =>
        new(new Dictionary<string, string?> { ["JwtSettings:previousSecurityKeys:0"] = previousKey });

    private static Dictionary<string, string?> WithPreviousSecretVersion(string version)
    {
        var settings = Settings(secretName: "jwt");
        settings["JwtSettings:PreviousSecretVersions:0"] = version;
        return settings;
    }

    private static string Unreachable(string? projectId, string secretName, string version) =>
        throw new InvalidOperationException("PermissionDenied");

    [Fact]
    public void TheSecretWinsOverTheOtherSources()
    {
        var key = Resolve(InMemory(Settings(secretName: "jwt")), readSecret: (_, _, _) => SecretKey);

        Assert.Equal(SecretKey, KeyText(key));
    }

    [Fact]
    public void AnUnreadableSecretStopsStartupInsteadOfFallingBackToTheConfiguredKey()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            Resolve(InMemory(Settings(secretName: "jwt")), readSecret: Unreachable));

        Assert.Contains("jwt", error.Message);
        Assert.Equal("PermissionDenied", error.InnerException!.Message);
    }

    [Fact]
    public void AnEmptySecretStopsStartup()
    {
        Assert.Throws<InvalidOperationException>(() =>
            Resolve(InMemory(Settings(secretName: "jwt")), readSecret: (_, _, _) => ""));
    }

    [Fact]
    public void InDevelopmentAnUnreadableSecretFallsBackToTheConfiguredKey()
    {
        var key = Resolve(InMemory(Settings(secretName: "jwt")), Environments.Development, Unreachable);

        Assert.Equal(GoodKey, KeyText(key));
    }

    [Fact]
    public void AKeyInAnAppsettingsFileIsRefusedOutsideDevelopment()
    {
        var configuration = AppsettingsFile(GoodKey).Build();

        var error = Assert.Throws<InvalidOperationException>(() => Resolve(configuration));
        Assert.Contains("JwtSettings:securityKey", error.Message);
    }

    [Fact]
    public void AKeyInAnAppsettingsFileIsRefusedWhenTheFileIsInAChainedConfiguration()
    {
        var configuration = new ConfigurationBuilder()
            .AddConfiguration(AppsettingsFile(GoodKey).Build())
            .Build();

        Assert.Throws<InvalidOperationException>(() => Resolve(configuration));
    }

    [Fact]
    public void AKeyInAnAppsettingsFileIsUsedInDevelopment()
    {
        var key = Resolve(AppsettingsFile(GoodKey).Build(), Environments.Development);

        Assert.Equal(GoodKey, KeyText(key));
    }

    /// <summary>E.g. <c>JwtSettings__securityKey</c> set as an environment variable by the deployment.</summary>
    [Fact]
    public void AKeyFromASourceThatIsNotAFileIsUsedOutsideDevelopment()
    {
        var configuration = AppsettingsFile("the-committed-key-that-is-at-least-32-bytes")
            .AddInMemoryCollection(Settings())
            .Build();

        Assert.Equal(GoodKey, KeyText(Resolve(configuration)));
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Development")]
    public void AKeyShorterThan32BytesIsRefused(string environment)
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            Resolve(InMemory(Settings("secret")), environment));

        Assert.Contains("6 bytes", error.Message);
    }

    [Fact]
    public void NoKeyAtAllIsAnError()
    {
        Assert.Throws<InvalidOperationException>(() => Resolve(InMemory(Settings(securityKey: null))));
    }

    [Fact]
    public void WithoutAHostTheStrictRulesApply()
    {
        var configuration = AppsettingsFile(GoodKey).Build();

        Assert.Throws<InvalidOperationException>(() =>
            new JwtSigningKey(configuration, NullLogger<JwtSigningKey>.Instance));
    }

    [Fact]
    public async Task AnAppWithAWeakKeyDoesNotStart()
    {
        using var host = Host(Settings("secret"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync());
    }

    [Fact]
    public async Task AnAppWithAGoodKeyStarts()
    {
        using var host = Host(Settings());

        await host.StartAsync();
        await host.StopAsync();
    }

    [Fact]
    public void IssuingAndValidationUseTheSameKey()
    {
        using var host = new TestHost();

        var parameters = host.Get<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

        Assert.Equal([host.Get<JwtSigningKey>().Key], parameters.IssuerSigningKeys);
        Assert.Same(host.Get<JwtSigningKey>().Key, host.Get<JwtHandler>().GetSigningCredentials().Key);
    }

    /// <summary>With a key long enough for HS512, so that it is the pinned algorithm that refuses it.</summary>
    [Fact]
    public void ATokenSignedWithAnotherAlgorithmIsRejected()
    {
        using var host = Host(Settings(new string('k', 64)));
        var key = host.Services.GetRequiredService<JwtSigningKey>().Key;
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken("issuer", "audience",
            [new Claim(ClaimTypes.Name, "user@example.org")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha512)));
        var parameters = host.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;

        Assert.ThrowsAny<SecurityTokenException>(() =>
            new JwtSecurityTokenHandler().ValidateToken(token, parameters, out _));

        var unpinned = parameters.Clone();
        unpinned.ValidAlgorithms = null;
        new JwtSecurityTokenHandler().ValidateToken(token, unpinned, out _);
    }

    [Fact]
    public async Task TokensNameTheKeyTheyAreSignedWith()
    {
        using var host = new TestHost();

        var token = new JsonWebToken(await TokenFrom(host));

        Assert.Equal(host.Get<JwtSigningKey>().Key.KeyId, token.Kid);
    }

    /// <summary>So that every instance of the app names the same key the same way without it being configured.</summary>
    [Fact]
    public void TheKeyIdDependsOnlyOnTheKey()
    {
        var key = Resolve(InMemory(Settings()));

        Assert.Equal(key.Key.KeyId, Resolve(InMemory(Settings())).Key.KeyId);
        Assert.NotEqual(key.Key.KeyId, Resolve(InMemory(Settings(SecretKey))).Key.KeyId);
    }

    [Fact]
    public async Task AfterARotationTokensSignedWithThePreviousKeyAreStillAccepted()
    {
        using var beforeRotation = new TestHost(new Dictionary<string, string?> { ["JwtSettings:securityKey"] = OldKey });
        using var afterRotation = HostWithPreviousKey(OldKey);
        using var previousKeyDropped = new TestHost();
        var token = await TokenFrom(beforeRotation);

        Assert.True(await IsAccepted(token, afterRotation));
        Assert.False(await IsAccepted(token, previousKeyDropped));
    }

    [Fact]
    public async Task APreviousKeyIsNeverSignedWith()
    {
        using var host = HostWithPreviousKey(OldKey);

        var token = new JsonWebToken(await TokenFrom(host));

        Assert.Equal(host.Get<JwtSigningKey>().Key.KeyId, token.Kid);
        Assert.NotEqual(OldKey, KeyText(host.Get<JwtSigningKey>()));
    }

    /// <summary>Tokens issued before 5.0.0 have no <c>kid</c>.</summary>
    [Fact]
    public async Task ATokenWithoutAKeyIdIsCheckedAgainstEveryKey()
    {
        using var host = HostWithPreviousKey(OldKey);
        var token = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken("issuer", "audience",
            [new Claim(ClaimTypes.Name, "user@example.org")], expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(OldKey)),
                JwtSigningKey.Algorithm)));

        Assert.Empty(new JsonWebToken(token).Kid);
        Assert.True(await IsAccepted(token, host));
    }

    [Fact]
    public void PreviousSecretVersionsAreAcceptedButNotSignedWith()
    {
        var versionsRead = new List<string>();

        var key = Resolve(InMemory(WithPreviousSecretVersion("3")), readSecret: (_, secretName, version) =>
        {
            Assert.Equal("jwt", secretName);
            versionsRead.Add(version);
            return version == "latest" ? SecretKey : OldKey;
        });

        Assert.Equal(["latest", "3"], versionsRead);
        Assert.Equal(SecretKey, KeyText(key));
        Assert.Equal([SecretKey, OldKey], ValidationKeyTexts(key));
    }

    [Fact]
    public void AnUnreadablePreviousSecretVersionStopsStartup()
    {
        var error = Assert.Throws<InvalidOperationException>(() => Resolve(InMemory(WithPreviousSecretVersion("3")),
            readSecret: (_, _, version) => version == "latest" ? SecretKey : Unreachable(null, "jwt", version)));

        Assert.Contains("version 3", error.Message);
    }

    [Fact]
    public void InDevelopmentAnUnreadablePreviousSecretVersionIsSkipped()
    {
        var key = Resolve(InMemory(WithPreviousSecretVersion("3")), Environments.Development,
            (_, _, version) => version == "latest" ? SecretKey : Unreachable(null, "jwt", version));

        Assert.Equal([SecretKey], ValidationKeyTexts(key));
    }

    [Fact]
    public void PreviousSecretVersionsWithoutASecretAreAnError()
    {
        var settings = Settings();
        settings["JwtSettings:PreviousSecretVersions:0"] = "3";

        var error = Assert.Throws<InvalidOperationException>(() => Resolve(InMemory(settings)));
        Assert.Contains("SecretName", error.Message);
    }

    [Fact]
    public void APreviousKeyInAnAppsettingsFileIsRefusedOutsideDevelopment()
    {
        var configuration = AppsettingsFile("the-committed-key-that-is-at-least-32-bytes", OldKey)
            .AddInMemoryCollection(Settings())
            .Build();

        var error = Assert.Throws<InvalidOperationException>(() => Resolve(configuration));
        Assert.Contains("JwtSettings:previousSecurityKeys:0", error.Message);
        Assert.Equal([GoodKey, OldKey],
            ValidationKeyTexts(Resolve(configuration, Environments.Development)));
    }

    [Fact]
    public void APreviousKeyShorterThan32BytesIsRefused()
    {
        var settings = Settings();
        settings["JwtSettings:previousSecurityKeys:0"] = "secret";

        Assert.Throws<InvalidOperationException>(() => Resolve(InMemory(settings)));
    }

    [Fact]
    public void TheCurrentKeyListedAsAPreviousOneIsKeptOnce()
    {
        var settings = Settings();
        settings["JwtSettings:previousSecurityKeys:0"] = GoodKey;
        settings["JwtSettings:previousSecurityKeys:1"] = OldKey;
        settings["JwtSettings:previousSecurityKeys:2"] = OldKey;

        Assert.Equal([GoodKey, OldKey], ValidationKeyTexts(Resolve(InMemory(settings))));
    }

    private static IHost Host(Dictionary<string, string?> settings) =>
        new HostBuilder()
            .ConfigureAppConfiguration(builder => builder.AddInMemoryCollection(settings))
            .ConfigureServices((context, services) => services.AddUserAuthentication(context.Configuration))
            .Build();

    public void Dispose() => Directory.Delete(_appsettingsDirectory, true);
}
