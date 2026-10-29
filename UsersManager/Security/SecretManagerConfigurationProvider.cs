using Google.Api.Gax;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.SecretManager.V1;
using Microsoft.Extensions.Configuration;

namespace UsersManager.Security;

/// <summary>
///     Reads secrets from Google Secret Manager. Errors are thrown, not hidden: a caller that got <c>null</c> for a
///     secret it could not read would carry on with whatever it uses instead.
/// </summary>
public class SecretManagerConfigurationProvider : ConfigurationProvider
{
    /// <summary>Throws when no Secret Manager client can be created, e.g. without Google credentials.</summary>
    public SecretManagerConfigurationProvider(string? projectId = null)
    {
        Client = SecretManagerServiceClient.Create();
        var platform = Platform.Instance();
        if (platform != null && platform.ProjectId != null)
        {
            ProjectId = platform.ProjectId;
        }
        else if (projectId != null)
        {
            ProjectName project = new ProjectName(projectId);
            ProjectId = project.ProjectId;
        }
    }

    private string? ProjectId { get; }

    private SecretManagerServiceClient Client { get; }

    /// <summary>
    ///     A version of the secret, by default the latest. Throws when there is no project to read it from (not running
    ///     on Google Cloud and no project id given) or the secret can't be read.
    /// </summary>
    public string GetSecret(string secretId, string version = "latest")
    {
        if (ProjectId == null)
            throw new InvalidOperationException(
                $"No Google Cloud project to read secret '{secretId}' from: not running on Google Cloud and no " +
                "project id given (JwtSettings:ProjectId).");

        var secretVersionName = new SecretVersionName(ProjectId, secretId, version);

        var result = Client.AccessSecretVersion(secretVersionName);

        return result.Payload.Data.ToStringUtf8();
    }
}
