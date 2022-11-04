using System.Dynamic;

namespace UsersManager.Models
{
    public class AuthResponseDto
    {
        public bool IsAuthSuccessful { get; set; }
        public string ErrorMessage { get; set; }
        public string Token { get; set; }
        public ExpandoObject Permissions { get; set; }
        public string? Impersonator { get; set; }
    }
}