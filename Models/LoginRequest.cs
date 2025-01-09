namespace Authenticator2.Models
{
    public class LoginRequest
    {
        public int Id { get; set; } // Primary Key
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string SecretKey { get; set; } = string.Empty; // Base32-encoded secret key
    }
}
