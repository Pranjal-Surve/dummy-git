namespace Authenticator2.Models
{
    public class VerifyTOTPRequest
    {
        public string Username { get; set; }
        public string TOTP { get; set; }
    }
}