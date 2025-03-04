using Google.Api.Gax;
using Google.Api.Gax.ResourceNames;
using Google.Cloud.SecretManager.V1;
using Microsoft.Extensions.Configuration;

namespace UsersManager.Security;

public class SecretManagerConfigurationProvider : ConfigurationProvider
{
    public SecretManagerConfigurationProvider(string? projectId = null)
    {
        try
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
        catch (Exception e)
        {
        }
    }

    private string? ProjectId { get; }

    private SecretManagerServiceClient Client { get; }

    public string? GetSecret(string secretId)
    {
        if (ProjectId == null) return null;
        // Build the resource name.
        var secretVersionName = new SecretVersionName(ProjectId, secretId, "1");

        try
        {
            // Call the API.
            var result = Client.AccessSecretVersion(secretVersionName);

            // Convert the payload to a string. Payloads are bytes by default.
            var payload = result.Payload.Data.ToStringUtf8();
            return payload;
        }
        catch (Exception e)
        {
            return null;
            //throw e;
        }
    }
}