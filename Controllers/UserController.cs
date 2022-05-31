using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using VeriftEmailForgetPassword.Data;

namespace VeriftEmailForgetPassword.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _dataContext;
        public UserController(DataContext context)
        {
            _dataContext = context;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserRegisterRequest request)
        {
            if (_dataContext.Users.Any(u => u.Email == request.Email))
                return BadRequest("User Already Exist");

            CreatePasswordHash(
                request.Password,
                out byte[] passwordHash,
                out byte[] passwordSalt);

            var User = new User
            {
                Email = request.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };

            _dataContext.Users.Add(User);
            await _dataContext.SaveChangesAsync();

            return Ok("OK User Successfully Created");
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login(UserLoginRequest request)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if(user == null) { return BadRequest("User not found."); } //just example but in prod dont use this
            if(user.VerifiedAt == null) { return BadRequest("User not verified"); }
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password is incorrect");
            }

            return Ok($"Welcome Back {user.Email} !");
        }
        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.VerificationToken == token);
            if (user == null) { return BadRequest("Invalid Token."); } //just example but in prod dont use this
            user.VerifiedAt = DateTime.Now;
            await _dataContext.SaveChangesAsync();

            return Ok("User Verified !");
        }
        private bool VerifyPasswordHash(string Password,byte[] passwordHash,byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));
                return computeHash.SequenceEqual(passwordHash);
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null) { return BadRequest("User Not Found"); } //just example but in prod dont use this
            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            await _dataContext.SaveChangesAsync();

            return Ok("You may now reset your password");
        }
        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest request)
        {
            var user = await _dataContext.Users.FirstOrDefaultAsync(u => u.PasswordResetToken == request.Token);
            if (user == null || user.ResetTokenExpires < DateTime.Now) { return BadRequest("Invalid Token"); } //just example but in prod dont use this

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;

            await _dataContext.SaveChangesAsync();

            return Ok("Password reset successfully !!!");
        }

        private void CreatePasswordHash(string Password,out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Password));

            }
        }
        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }
    }
}
