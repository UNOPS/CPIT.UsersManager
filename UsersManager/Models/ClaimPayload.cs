using System.ComponentModel.DataAnnotations;

namespace UsersManager.Models;

public class ClaimPayload
{
    [Required] public string ClaimName { get; set; } = "";
    public string[] ClaimValues { get; set; } = [];
}
