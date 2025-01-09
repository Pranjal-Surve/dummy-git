using Microsoft.AspNetCore.Mvc;   //for ControllerBase
using Authenticator2.Models;
using Authenticator2.DTO;
using Authenticator2.Database;
using OtpNet;
using QRCoder;
//This is AuthController
namespace Authenticator2.Controllers
{
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        public AuthController(AppDbContext context)
        {
            _context = context;   
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] LoginRequestDTO request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            {
                return BadRequest("Username or password cannot be null or empty.");
            }

            // if user already exist in db
            if (_context.Users.Any(u => u.Username == request.Username))
            {
                return Conflict("Username already exists. Please choose a different one.");
            }

            // if not present, add user and Hash the password before saving
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // Create a new LoginRequest entity for the database
            var newUser = new LoginRequest
            {
                Username = request.Username,
                Password = hashedPassword,
                SecretKey = string.Empty // Initialize with an empty secret; will be generated during login
            };

            _context.Users.Add(newUser);
            _context.SaveChanges();
            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequestDTO request)
        {            
            // var user = _context.Users.SingleOrDefault(u => u.Username == request.Username && u.Password == request.Password);
            var user = _context.Users.SingleOrDefault(u => u.Username == request.Username);

            if (user == null)
            {
                return Unauthorized("Invalid credentials.");
            }

            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(request.Password, user.Password);

            if (!isPasswordValid)
            {
                return Unauthorized("Invalid username or password.");
            }
 
            // Step 2:  HMAC and Secret Key Generation => uses Otp.net package
            if (string.IsNullOrEmpty(user.SecretKey))
            {
                //this secretKey will be shared using QRCode with client and server
                var secretKey = KeyGeneration.GenerateRandomKey(16); // Generate 16-byte key => OTp.net

                user.SecretKey = Base32Encoding.ToString(secretKey); // Store as Base32 string
                _context.SaveChanges(); 
            }

            string secret = user.SecretKey;

            // Step 3: Generate QR Code content
            string qrCodeContent = $"otpauth://totp/PranjalApp:{request.Username}?secret={secret}&issuer=PranjalApp";

            // Step 4: Generate QR Code => uses QRCoder
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(qrCodeContent, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            var qrCodeImage = qrCode.GetGraphic(5); // Generate as PNG byte array

            return File(qrCodeImage, "image/png");
        }

        [HttpPost("verify-totp")]
        public IActionResult VerifyTOTP([FromBody] VerifyTOTPRequest request)
        {
            // Step 1: Check if the user exists in the database
            var user = _context.Users.SingleOrDefault(u => u.Username == request.Username);
            if (user == null)
            {
                return Unauthorized("User not found or not logged in.");
            }
            // Step 2: Retrieve the user's secret key
            if (string.IsNullOrEmpty(user.SecretKey))
            {
                return Unauthorized("No secret key found for the user.");
            }
            // Step 3: Decode the secret key from Base32
            // HMAC and Truncation During Verification => (abstracted by the OtpNet library)
            //HMAC: The HMAC (Hash-based Message Authentication Code) algorithm combines the secret key with the current time to generate a hash.
            //Truncation: A process to extract the desired number of digits (e.g., 6 digits) from the hash.
            byte[] secretKey = Base32Encoding.ToBytes(user.SecretKey);

            // Step 4: Initialize the TOTP provider
            var totp = new Totp(secretKey);

            // Step 5: Validate the provided TOTP code
            bool isValid = totp.VerifyTotp(request.TOTP, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (isValid)
            {
                return Ok(new { Message = "Authentication successful!" });                
            }
            return Unauthorized("Invalid TOTP code.");
        } 
    }
}
//This is Two Factor Auths
